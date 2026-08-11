"""Interactive initialization of shared project contexts and local bindings."""

from collections.abc import Callable, Mapping
import os
from pathlib import Path
import sys
from typing import TextIO

from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

from .aws_cli import AwsCliInfo
from .cli_console import CliConsole, safe_text
from .context_verification import (
    ContextVerificationError,
    IdentityProvider,
)
from .models import Profile
from .interactive import InputClosedError, prompt_value, prompt_yes_no, read_line
from .i18n import text
from .profile_creation import ProfileCommandRunner
from .profile_selection import (
    ProfileSelectionCancelled,
    ProfileWorkflowError,
    select_or_create_profile,
)
from .project_initialization import (
    InitResult,
    InitializedEnvironment,
    ProjectInitializationError,
    commit_project_initialization,
    resolve_initialization_target,
    verify_initialization_environment,
)


class InitCommandError(Exception):
    """Raised when project initialization cannot be completed."""


class InitCommandCancelled(Exception):
    """Raised when project initialization is cancelled."""


def initialize_project(
    *,
    start_dir: Path | None = None,
    bindings_path: Path | None = None,
    base_environment: Mapping[str, str] | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    identity_provider: IdentityProvider | None = None,
    profiles_loader: Callable[[], list[Profile]] | None = None,
    command_runner: ProfileCommandRunner | None = None,
    cli_info_provider: Callable[[], AwsCliInfo | None] | None = None,
) -> InitResult:
    """Interactively create a verified multi-environment project."""
    input_stream = sys.stdin if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    error_stream = sys.stderr if stderr is None else stderr
    output = CliConsole(output_stream)
    errors = CliConsole(error_stream)
    base = os.environ if base_environment is None else base_environment
    try:
        target = resolve_initialization_target(start_dir)
    except ProjectInitializationError as exc:
        raise InitCommandError(str(exc)) from exc

    output.print(
        Panel(
            Text(text("cli_init_intro"), style="awsui.muted"),
            title=Text("awsui init", style="awsui.title"),
            border_style="cyan",
            expand=False,
        )
    )

    default_project = target.default_project
    try:
        project = prompt_value(
            text("cli_project_prompt", default=default_project),
            default=default_project,
            stdin=input_stream,
            stdout=output_stream,
        )
    except InputClosedError as exc:
        raise InitCommandCancelled("initialization cancelled: input closed") from exc

    initialized: list[InitializedEnvironment] = []
    names: set[str] = set()
    while True:
        prompt = (
            text("cli_environment_prompt")
            if not initialized
            else text("cli_environment_finish_prompt")
        )
        try:
            environment_name = read_line(
                prompt,
                stdin=input_stream,
                stdout=output_stream,
            ).strip()
        except InputClosedError as exc:
            raise InitCommandCancelled(
                "initialization cancelled: input closed"
            ) from exc
        if not environment_name:
            if initialized:
                break
            output.print(
                Text(text("cli_environment_required"), style="awsui.warning"),
                plain=text("cli_environment_required"),
            )
            continue
        if environment_name in names:
            message = text(
                "cli_environment_duplicate", environment=environment_name
            )
            output.print(
                safe_text(message, "awsui.warning"),
                plain=message,
            )
            continue

        output.print(
            Rule(
                Text.assemble(
                    (f"{text('cli_environment')} ", "awsui.label"),
                    safe_text(environment_name.upper(), "awsui.title"),
                ),
                align="left",
                style="cyan",
            )
        )

        try:
            profile = select_or_create_profile(
                project=project,
                environment=environment_name,
                current_profile=None,
                base_environment=base,
                stdin=input_stream,
                stdout=output_stream,
                profiles_loader=profiles_loader,
                command_runner=command_runner,
                cli_info_provider=cli_info_provider,
            )
        except ProfileSelectionCancelled as exc:
            raise InitCommandCancelled(str(exc)) from exc
        except ProfileWorkflowError as exc:
            raise InitCommandError(str(exc)) from exc

        profile_name = profile["name"]
        default_region = (
            profile.get("region")
            or base.get("AWS_REGION")
            or base.get("AWS_DEFAULT_REGION")
        )
        region_prompt = (
            text("cli_region_prompt")
            if default_region is None
            else text("cli_region_default_prompt", default=default_region)
        )
        try:
            region = prompt_value(
                region_prompt,
                default=default_region,
                stdin=input_stream,
                stdout=output_stream,
            )
            protected = prompt_yes_no(
                text("cli_protected_prompt"),
                stdin=input_stream,
                stdout=output_stream,
            )
        except InputClosedError as exc:
            raise InitCommandCancelled(
                "initialization cancelled: input closed"
            ) from exc

        status = text("cli_authenticating")
        errors.print(
            Text.assemble(("● ", "awsui.title"), safe_text(status, "awsui.muted")),
            plain=status,
            flush=True,
        )
        try:
            verified_environment = verify_initialization_environment(
                name=environment_name,
                profile=profile_name,
                region=region,
                protected=protected,
                base_environment=base,
                identity_provider=identity_provider,
                login_output=error_stream,
            )
        except ContextVerificationError as exc:
            raise InitCommandError(str(exc)) from exc

        if output.enhanced:
            grid = Table.grid(padding=(0, 2))
            grid.add_column(style="awsui.label", no_wrap=True)
            grid.add_column(style="awsui.value")
            grid.add_row(text("cli_account"), safe_text(verified_environment.account))
            grid.add_row(text("cli_region"), safe_text(region))
            grid.add_row(text("cli_profile"), safe_text(profile_name))
            if protected:
                grid.add_row(
                    text("cli_protection"),
                    Text(text("cli_protected"), style="awsui.protected"),
                )
            output.print(
                Panel(
                    grid,
                    title=Text(
                        f"✓ {text('cli_identity_verified_short')}",
                        style="awsui.success",
                    ),
                    border_style="red" if protected else "green",
                    expand=False,
                )
            )
        else:
            print(
                f"{text('cli_account')}: {verified_environment.account}",
                file=output_stream,
            )
            print(f"{text('cli_region')}: {region}", file=output_stream)
            print("", file=output_stream)
        initialized.append(verified_environment)
        names.add(environment_name)

    try:
        return commit_project_initialization(
            project=project,
            environments=initialized,
            start_dir=target.directory,
            bindings_path=bindings_path,
        )
    except ProjectInitializationError as exc:
        raise InitCommandError(str(exc)) from exc
