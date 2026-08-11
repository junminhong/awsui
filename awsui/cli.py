"""Command-line entry point for awsui."""

from argparse import ArgumentParser, Namespace, REMAINDER
from collections.abc import Sequence
import os
import shlex
import sys

from rich_argparse import RawDescriptionRichHelpFormatter

from . import __version__
from .bind_command import (
    BindCommandCancelled,
    BindCommandError,
    bind_environment,
)
from .bindings import LocalBindingsError
from .cli_console import CliConsole, safe_text
from .cli_presenter import (
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
    render_verified_context_rich,
    render_verified_context_json,
)
from .command_runner import (
    CommandLaunchError,
    run_command,
    select_interactive_shell,
)
from .context_engine import (
    BindingNotFoundError,
    ContextResolutionError,
    ContextSourceError,
    EnvironmentNotFoundError,
    resolve_context,
)
from .context_runtime import VerifiedRuntime, prepare_resolved_runtime
from .context_verification import (
    AccountMismatchError,
    ContextVerificationError,
)
from .doctor_command import diagnose
from .init_command import (
    InitCommandCancelled,
    InitCommandError,
    initialize_project,
)
from .profile_catalog import ProfileCatalogError
from .project_config import ProjectConfigError, ProjectConfigNotFoundError
from .tui_context import load_dashboard


_COMMANDS = frozenset({"init", "bind", "context", "run", "shell", "doctor"})
_BIND_LIST_ALIASES = frozenset({"ls", "list"})
_CONTEXT_LIST_ALIASES = frozenset({"ls", "list"})
_HELP_EPILOG = """\
Quick start:
  awsui init
  awsui prod -- codex
  awsui prod
  awsui context prod

Compatibility:
  awsui run prod -- codex
  awsui shell prod
"""


class AwsuiHelpFormatter(RawDescriptionRichHelpFormatter):
    """awsui-colored argparse help output."""

    styles = {
        **RawDescriptionRichHelpFormatter.styles,
        "argparse.args": "bold cyan",
        "argparse.groups": "bold cyan",
        "argparse.metavar": "cyan",
        "argparse.prog": "bright_blue",
        "argparse.syntax": "bold green",
    }
    text_markup = False
    help_markup = False


class AwsuiArgumentParser(ArgumentParser):
    """Argument parser with TTY-aware actionable errors."""

    def error(self, message: str) -> None:
        output = CliConsole(sys.stderr)
        if not output.enhanced:
            super().error(message)
        output.print(
            render_failure_rich(
                "Invalid command",
                message,
                next_step=f"Run `{self.prog} --help` for usage.",
            )
        )
        self.exit(2)


def build_parser() -> ArgumentParser:
    """Build the awsui command-line parser."""
    parser = AwsuiArgumentParser(
        prog="awsui",
        description="Verified AWS contexts for AI agents and CLI tools",
        epilog=_HELP_EPILOG,
        formatter_class=AwsuiHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    parser.add_argument(
        "--lang",
        choices=["zh-TW", "en"],
        default="en",
        help="UI language (default: en)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        parser_class=AwsuiArgumentParser,
    )
    subparsers.add_parser(
        "init",
        help="Initialize verified AWS contexts for this project",
        description="Initialize verified AWS contexts for this project",
        formatter_class=AwsuiHelpFormatter,
    )
    bind_parser = subparsers.add_parser(
        "bind",
        help="Bind or list project environment AWS profiles",
        description="Bind or list project environment AWS profiles",
        formatter_class=AwsuiHelpFormatter,
    )
    bind_parser.add_argument(
        "environment",
        help="Environment to bind, or `ls`/`list` to list bindings",
    )
    bind_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the binding list as JSON (only with `ls`/`list`)",
    )

    context_parser = subparsers.add_parser(
        "context",
        help="Show, verify, or list project AWS contexts",
        description="Show, verify, or list project AWS contexts",
        formatter_class=AwsuiHelpFormatter,
    )
    context_parser.add_argument(
        "environment",
        help="Project environment to show, or `ls`/`list` to list contexts",
    )
    context_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the context or context list as JSON",
    )

    run_parser = subparsers.add_parser(
        "run",
        help="Run a command in a verified project AWS context",
        description="Run a command in a verified project AWS context",
        formatter_class=AwsuiHelpFormatter,
    )
    run_parser.add_argument("environment", help="Project environment to use")
    run_parser.add_argument(
        "child_command",
        nargs=REMAINDER,
        help="Command and arguments to launch",
    )

    shell_parser = subparsers.add_parser(
        "shell",
        help="Open a shell in a verified project AWS context",
        description="Open a shell in a verified project AWS context",
        formatter_class=AwsuiHelpFormatter,
    )
    shell_parser.add_argument("environment", help="Project environment to use")

    subparsers.add_parser(
        "doctor",
        help="Diagnose local project context configuration",
        description="Diagnose local project context configuration without authenticating",
        formatter_class=AwsuiHelpFormatter,
    )

    return parser


def parse_args(argv: Sequence[str] | None = None) -> Namespace:
    """Parse command-line arguments from argv or the current process."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    normalized, error = _normalize_shorthand(raw_argv)
    if error is not None:
        parser.error(error)
    return parser.parse_args(normalized)


def _normalize_shorthand(argv: list[str]) -> tuple[list[str], str | None]:
    """Translate `awsui <environment> [-- command]` to legacy subcommands."""
    if not argv or argv[0].startswith("-") or argv[0] in _COMMANDS:
        return argv, None

    environment, *remainder = argv
    if not remainder:
        return ["shell", environment], None
    if remainder[0] != "--":
        example = f"awsui {environment} -- {shlex.join(remainder)}"
        return argv, f"commands after an environment require `--`; use `{example}`"
    if len(remainder) == 1:
        return argv, "a command is required after `--`"
    return ["run", environment, *remainder], None


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch an awsui command or show CLI help when none is selected."""
    args = parse_args(argv)

    if args.command is not None:
        invalid_options = _tui_only_options(args)
        if invalid_options:
            rendered = ", ".join(invalid_options)
            message = (
                f"awsui {args.command}: error: TUI-only options are not valid "
                f"with {args.command}: {rendered}"
            )
            CliConsole(sys.stderr).print(
                render_failure_rich(
                    "Invalid options",
                    message,
                    next_step=f"Run `awsui {args.command} --help` for usage.",
                ),
                plain=message,
            )
            return 2

    if args.command == "bind":
        if args.environment in _BIND_LIST_ALIASES:
            return _run_context_list(json_output=args.json, command_name="bind")
        if args.json:
            message = (
                "awsui bind: error: `--json` is only valid with "
                "`awsui bind ls` or `awsui bind list`"
            )
            CliConsole(sys.stderr).print(
                render_failure_rich(
                    "Invalid bind options",
                    message,
                    next_step="Run `awsui bind ls --json` to list local bindings.",
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
            message = "awsui run: error: a command is required after the environment"
            CliConsole(sys.stderr).print(
                render_failure_rich(
                    "Command required",
                    message,
                    next_step=f"Run `awsui {args.environment} -- <command>`.",
                ),
                plain=message,
            )
            return 2
        return _run_in_context(args.environment, args.child_command)

    if args.command == "shell":
        return _run_context_shell(args.environment)

    if args.command == "doctor":
        return _run_doctor()

    build_parser().print_help()
    return 0


def _tui_only_options(args: Namespace) -> list[str]:
    invalid_options: list[str] = []
    if args.lang != "en":
        invalid_options.append("--lang")
    if args.log_level != "INFO":
        invalid_options.append("--log-level")
    return invalid_options


def _run_bind(environment: str) -> int:
    output = CliConsole(sys.stdout)
    errors = CliConsole(sys.stderr)
    try:
        result = bind_environment(environment)
    except BindCommandCancelled as exc:
        message = f"awsui bind: {exc}"
        errors.print(render_cancelled_rich(message), plain=message)
        return 130
    except KeyboardInterrupt:
        message = "awsui bind: binding cancelled"
        errors.print(render_cancelled_rich(message), plain=message)
        return 130
    except BindCommandError as exc:
        message = f"awsui bind: error: {exc}"
        errors.print(
            render_failure_rich(
                "Unable to bind environment",
                str(exc),
                next_step="Run `awsui doctor` to inspect the project contexts.",
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
        message = f"awsui init: {exc}"
        errors.print(render_cancelled_rich(message), plain=message)
        return 130
    except KeyboardInterrupt:
        message = "awsui init: initialization cancelled"
        errors.print(render_cancelled_rich(message), plain=message)
        return 130
    except InitCommandError as exc:
        message = f"awsui init: error: {exc}"
        errors.print(
            render_failure_rich(
                "Initialization failed",
                str(exc),
                next_step="Fix the reported project configuration issue and retry.",
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
            "Run `awsui init` from the project root."
            if isinstance(exc, ProjectConfigNotFoundError)
            else "Run `awsui doctor` and fix the reported configuration issue."
        )
        message = f"awsui {command_name}: error: {exc}"
        CliConsole(sys.stderr).print(
            render_failure_rich(
                "Unable to list project contexts",
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
        message = f"awsui {command_name}: error: {exc}"
        errors.print(
            render_failure_rich(
                "AWS context unavailable",
                str(exc),
                next_step=_resolution_next_step(exc, environment),
                not_started=_not_started_message(command_name),
            ),
            plain=message,
        )
        return None, 1

    status = "Authenticating and verifying AWS identity..."
    errors.print(
        render_status_rich(status),
        plain=status,
        flush=True,
    )
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
                next_step=f"Run `awsui bind {environment}` to select the intended "
                "local profile, then retry.",
            ),
            plain=render_account_mismatch(exc, not_started=not_started),
        )
        return None, 1
    except KeyboardInterrupt:
        message = f"awsui {command_name}: verification cancelled"
        errors.print(render_cancelled_rich(message), plain=message)
        return None, 130
    except ContextVerificationError as exc:
        message = f"awsui {command_name}: error: {exc}"
        not_started = _not_started_message(command_name)
        rich_failure = render_failure_rich(
            "AWS identity verification failed",
            str(exc),
            next_step="Run `awsui doctor`; if local checks pass, verify the bound "
            "profile with AWS CLI.",
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
            f"Launching: {command_text}",
        ),
        flush=True,
    )
    try:
        return run_command(command, environment=runtime.environment)
    except CommandLaunchError as exc:
        message = f"awsui run: error: {exc}"
        CliConsole(sys.stderr).print(
            render_failure_rich(
                "Command could not start",
                str(exc),
                next_step="Install the command or ensure it is available on PATH.",
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
            f"Launching shell: {shell}",
        ),
        flush=True,
    )
    try:
        return run_command([shell], environment=runtime.environment)
    except CommandLaunchError as exc:
        message = f"awsui shell: error: {exc}"
        CliConsole(sys.stderr).print(
            render_failure_rich(
                "Shell could not start",
                str(exc),
                next_step="Set SHELL to an installed executable and retry.",
            ),
            plain=message,
        )
        return exc.exit_code


def _not_started_message(command_name: str) -> str | None:
    if command_name == "run":
        return "Command was not started."
    if command_name == "shell":
        return "Shell was not started."
    return None


def _resolution_next_step(
    error: ContextResolutionError,
    environment: str,
) -> str:
    if isinstance(error, BindingNotFoundError):
        return f"Run `awsui bind {environment}`."
    if isinstance(error, EnvironmentNotFoundError):
        available = ", ".join(error.available_environments)
        return f"Choose a configured environment: {available}."
    if isinstance(error, ContextSourceError):
        if (
            error.source == "project configuration"
            and ".awsui.yaml was not found" in str(error)
        ):
            return "Run `awsui init` from the project root."
        return "Run `awsui doctor` and fix the reported configuration issue."
    return "Run `awsui doctor` for local configuration diagnostics."
