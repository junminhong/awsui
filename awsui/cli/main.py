"""Command-line entry point and command dispatch for awsui."""

from argparse import Namespace
from collections.abc import Sequence
import os
from pathlib import Path
import shlex
import sys

from ..command_runner import (
    CommandLaunchError,
    run_command,
    select_interactive_shell,
)
from ..context.dashboard import load_dashboard
from ..context.resolution import (
    BindingNotFoundError,
    ContextResolutionError,
    ContextSourceError,
    EnvironmentNotFoundError,
    resolve_context,
)
from ..context.runtime import VerifiedRuntime, prepare_resolved_runtime
from ..context.verification import (
    AccountMismatchError,
    ContextVerificationError,
)
from ..doctor import diagnose
from ..i18n import text, use_language
from ..profiles.catalog import ProfileCatalogError
from ..project.bindings import LocalBindingsError
from ..project.config import ProjectConfigError, ProjectConfigNotFoundError
from ..settings import (
    SUPPORTED_LANGUAGES,
    UserSettingsError,
    get_default_settings_path,
    load_settings,
    save_settings,
    settings_with_language,
)
from .bind import BindCommandCancelled, BindCommandError, bind_environment
from .console import CliConsole, safe_text
from .initialization import (
    InitCommandCancelled,
    InitCommandError,
    initialize_project,
)
from .parser import _requested_language, build_parser, parse_args
from .presenter import (
    render_account_mismatch,
    render_account_mismatch_rich,
    render_bind_result,
    render_bind_result_rich,
    render_cancelled_rich,
    render_context_list,
    render_context_list_json,
    render_context_list_rich,
    render_doctor_report,
    render_doctor_report_rich,
    render_failure_rich,
    render_init_result,
    render_init_result_rich,
    render_launch_context,
    render_launch_context_rich,
    render_status_rich,
    render_verified_context,
    render_verified_context_json,
    render_verified_context_rich,
)


_BIND_LIST_ALIASES = frozenset({"ls", "list"})
_CONTEXT_LIST_ALIASES = frozenset({"ls", "list"})


def main(
    argv: Sequence[str] | None = None,
    *,
    settings_path: Path | None = None,
) -> int:
    """Load user preferences, then dispatch one localized CLI invocation."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    explicit_language = _requested_language(raw_argv)
    selected_path = (
        get_default_settings_path() if settings_path is None else settings_path
    )

    try:
        settings = load_settings(selected_path)
    except UserSettingsError as exc:
        if explicit_language not in SUPPORTED_LANGUAGES:
            return _settings_failure(
                text("cli_settings_unavailable", lang="en"),
                exc,
                lang="en",
            )
        settings = settings_with_language(explicit_language, selected_path)

    if explicit_language in SUPPORTED_LANGUAGES:
        settings = settings_with_language(explicit_language, selected_path)
        try:
            save_settings(settings)
        except UserSettingsError as exc:
            return _settings_failure(
                text("cli_settings_write_failed", lang=explicit_language),
                exc,
                lang=explicit_language,
            )

    effective_language = (
        explicit_language
        if explicit_language in SUPPORTED_LANGUAGES
        else settings.language
    )
    args = parse_args(raw_argv, default_lang=effective_language)
    with use_language(args.lang):
        if args.command is None and explicit_language in SUPPORTED_LANGUAGES:
            key = (
                "cli_language_switched_zh_tw"
                if explicit_language == "zh-TW"
                else "cli_language_switched_en"
            )
            print(text(key))
            return 0
        return _dispatch(args)


def _settings_failure(title: str, error: UserSettingsError, *, lang: str) -> int:
    """Render a settings failure without depending on the damaged preference."""
    with use_language(lang):
        detail = str(error)
        next_step = text("cli_settings_recover")
        CliConsole(sys.stderr).print(
            render_failure_rich(title, detail, next_step=next_step),
            plain=f"{title}: {detail}\n{text('cli_next_step')}: {next_step}",
        )
    return 1


def _dispatch(args: Namespace) -> int:
    """Dispatch parsed arguments within the active language scope."""
    if args.command == "bind":
        if args.environment in _BIND_LIST_ALIASES:
            return _run_context_list(json_output=args.json, command_name="bind")
        if args.json:
            message = text("cli_bind_json_error")
            CliConsole(sys.stderr).print(
                render_failure_rich(
                    text("cli_invalid_bind_options"),
                    message,
                    next_step=text("cli_bind_json_next"),
                ),
                plain=message,
            )
            return 2
        return _run_bind(args.environment)

    if args.command == "init":
        return _run_init()

    if args.command == "context":
        if args.environment in _CONTEXT_LIST_ALIASES:
            return _run_context_list(json_output=args.json)
        return _run_context(args.environment, json_output=args.json)

    if args.command == "run":
        if not args.child_command:
            message = text("cli_command_required_detail")
            CliConsole(sys.stderr).print(
                render_failure_rich(
                    text("cli_command_required"),
                    message,
                    next_step=text("cli_run_help_usage", environment=args.environment),
                ),
                plain=message,
            )
            return 2
        return _run_in_context(args.environment, args.child_command)

    if args.command == "shell":
        return _run_context_shell(args.environment)

    if args.command == "doctor":
        return _run_doctor()

    build_parser(args.lang).print_help()
    return 0


def _run_bind(environment: str) -> int:
    output = CliConsole(sys.stdout)
    errors = CliConsole(sys.stderr)
    try:
        result = bind_environment(environment)
    except BindCommandCancelled as exc:
        message = text("cli_bind_cancelled_detail", detail=exc)
        errors.print(render_cancelled_rich(message), plain=message)
        return 130
    except KeyboardInterrupt:
        message = text("cli_bind_cancelled")
        errors.print(render_cancelled_rich(message), plain=message)
        return 130
    except BindCommandError as exc:
        message = text("cli_command_error", command="bind", detail=exc)
        errors.print(
            render_failure_rich(
                text("cli_bind_failed"),
                str(exc),
                next_step=text("cli_bind_doctor"),
            ),
            plain=message,
        )
        return 1

    output.print(render_bind_result_rich(result), plain=render_bind_result(result))
    return 0


def _run_init() -> int:
    output = CliConsole(sys.stdout)
    errors = CliConsole(sys.stderr)
    try:
        result = initialize_project()
    except InitCommandCancelled as exc:
        message = text("cli_init_cancelled_detail", detail=exc)
        errors.print(render_cancelled_rich(message), plain=message)
        return 130
    except KeyboardInterrupt:
        message = text("cli_init_cancelled")
        errors.print(render_cancelled_rich(message), plain=message)
        return 130
    except InitCommandError as exc:
        message = text("cli_command_error", command="init", detail=exc)
        errors.print(
            render_failure_rich(
                text("cli_init_failed"),
                str(exc),
                next_step=text("cli_fix_init"),
            ),
            plain=message,
        )
        return 1

    output.print(render_init_result_rich(result), plain=render_init_result(result))
    return 0


def _run_doctor() -> int:
    report = diagnose()
    CliConsole(sys.stdout).print(
        render_doctor_report_rich(report),
        plain=render_doctor_report(report),
    )
    return 0 if report.healthy else 1


def _run_context_list(
    *,
    json_output: bool = False,
    command_name: str = "context",
) -> int:
    try:
        snapshot = load_dashboard()
    except (ProjectConfigError, LocalBindingsError, ProfileCatalogError) as exc:
        next_step = (
            text("cli_run_init")
            if isinstance(exc, ProjectConfigNotFoundError)
            else text("cli_run_doctor")
        )
        message = text("cli_command_error", command=command_name, detail=exc)
        CliConsole(sys.stderr).print(
            render_failure_rich(
                text("cli_list_failed"),
                str(exc),
                next_step=next_step,
            ),
            plain=f"{message}\nNext step: {next_step}",
        )
        return 1

    if json_output:
        print(render_context_list_json(snapshot))
    else:
        CliConsole(sys.stdout).print(
            render_context_list_rich(snapshot),
            plain=render_context_list(snapshot),
        )
    return 0


def _run_context(environment: str, *, json_output: bool = False) -> int:
    runtime, exit_code = _prepare_cli_runtime("context", environment)
    if runtime is None:
        return exit_code

    if json_output:
        print(render_verified_context_json(runtime.verified))
    else:
        CliConsole(sys.stdout).print(
            render_verified_context_rich(runtime.verified),
            plain=render_verified_context(runtime.verified),
        )
    return 0


def _prepare_cli_runtime(
    command_name: str,
    environment: str,
) -> tuple[VerifiedRuntime | None, int]:
    errors = CliConsole(sys.stderr)
    try:
        resolved = resolve_context(environment)
    except ContextResolutionError as exc:
        message = text("cli_command_error", command=command_name, detail=exc)
        errors.print(
            render_failure_rich(
                text("cli_context_unavailable"),
                str(exc),
                next_step=_resolution_next_step(exc, environment),
                not_started=_not_started_message(command_name),
            ),
            plain=message,
        )
        return None, 1

    status = text("cli_authenticating")
    errors.print(render_status_rich(status), plain=status, flush=True)
    try:
        runtime = prepare_resolved_runtime(
            resolved,
            base_environment=os.environ,
            login_output=sys.stderr,
        )
    except AccountMismatchError as exc:
        not_started = _not_started_message(command_name)
        errors.print(
            render_account_mismatch_rich(
                exc,
                not_started=not_started,
                next_step=text("cli_rebind", environment=environment),
            ),
            plain=render_account_mismatch(exc, not_started=not_started),
        )
        return None, 1
    except KeyboardInterrupt:
        message = text("cli_verification_cancelled", command=command_name)
        errors.print(render_cancelled_rich(message), plain=message)
        return None, 130
    except ContextVerificationError as exc:
        message = text("cli_command_error", command=command_name, detail=exc)
        not_started = _not_started_message(command_name)
        rich_failure = render_failure_rich(
            text("cli_verification_failed"),
            str(exc),
            next_step=text("cli_verify_profile"),
            not_started=not_started,
        )
        errors.print(rich_failure, plain=message)
        if not_started is not None and not errors.enhanced:
            errors.print(safe_text(not_started), plain=not_started)
        return None, 1

    return runtime, 0


def _run_in_context(environment: str, command: Sequence[str]) -> int:
    runtime, exit_code = _prepare_cli_runtime("run", environment)
    if runtime is None:
        return exit_code

    command_text = shlex.join(command)
    CliConsole(sys.stderr).print(
        render_launch_context_rich(runtime.verified, command_text),
        plain=render_launch_context(
            runtime.verified,
            text("cli_launching_plain", command=command_text),
        ),
        flush=True,
    )
    try:
        return run_command(command, environment=runtime.environment)
    except CommandLaunchError as exc:
        message = text("cli_command_error", command="run", detail=exc)
        CliConsole(sys.stderr).print(
            render_failure_rich(
                text("cli_command_start_failed"),
                str(exc),
                next_step=text("cli_install_command"),
            ),
            plain=message,
        )
        return exc.exit_code


def _run_context_shell(environment: str) -> int:
    runtime, exit_code = _prepare_cli_runtime("shell", environment)
    if runtime is None:
        return exit_code

    shell = select_interactive_shell(runtime.environment)
    CliConsole(sys.stderr).print(
        render_launch_context_rich(runtime.verified, f"shell: {shell}"),
        plain=render_launch_context(
            runtime.verified,
            text("cli_launching_shell", shell=shell),
        ),
        flush=True,
    )
    try:
        return run_command([shell], environment=runtime.environment)
    except CommandLaunchError as exc:
        message = text("cli_command_error", command="shell", detail=exc)
        CliConsole(sys.stderr).print(
            render_failure_rich(
                text("cli_shell_start_failed"),
                str(exc),
                next_step=text("cli_set_shell"),
            ),
            plain=message,
        )
        return exc.exit_code


def _not_started_message(command_name: str) -> str | None:
    if command_name == "run":
        return text("cli_command_not_started")
    if command_name == "shell":
        return text("cli_shell_not_started")
    return None


def _resolution_next_step(
    error: ContextResolutionError,
    environment: str,
) -> str:
    if isinstance(error, BindingNotFoundError):
        return text("cli_rebind", environment=environment)
    if isinstance(error, EnvironmentNotFoundError):
        available = ", ".join(error.available_environments)
        return text("cli_choose_environment", environments=available)
    if isinstance(error, ContextSourceError):
        if (
            error.source == "project configuration"
            and ".awsui.yaml was not found" in str(error)
        ):
            return text("cli_run_init")
        return text("cli_run_doctor")
    return text("cli_local_diagnostics")
