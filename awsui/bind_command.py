"""Interactive local AWS profile binding use case."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import sys
from typing import TextIO

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .aws_cli import AwsCliInfo
from .bindings import (
    LocalBindingsError,
    load_bindings,
    save_bindings,
)
from .cli_console import CliConsole, safe_text
from .i18n import text
from .models import Profile
from .profile_selection import (
    ProfileSelectionCancelled,
    ProfileWorkflowError,
    select_or_create_profile,
)
from .profile_creation import ProfileCommandRunner
from .project_config import (
    ProjectConfigError,
    ProjectContext,
    find_project_config,
    load_project_config,
)


class BindCommandError(Exception):
    """Raised when a profile binding cannot be completed."""


class BindCommandCancelled(Exception):
    """Raised when the user cancels profile selection."""

    def __init__(self, *, input_closed: bool = False) -> None:
        detail = "binding cancelled"
        if input_closed:
            detail += ": input closed"
        super().__init__(detail)


@dataclass(frozen=True, slots=True)
class BindResult:
    """Result of binding one project environment to a local profile."""

    project: str
    environment: str
    profile: str
    previous_profile: str | None
    changed: bool


def bind_environment(
    environment: str,
    *,
    start_dir: Path | None = None,
    bindings_path: Path | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    base_environment: Mapping[str, str] | None = None,
    profiles_loader: Callable[[], list[Profile]] | None = None,
    command_runner: ProfileCommandRunner | None = None,
    cli_info_provider: Callable[[], AwsCliInfo | None] | None = None,
) -> BindResult:
    """Interactively bind a project environment to a local AWS profile."""
    input_stream = sys.stdin if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    base = os.environ if base_environment is None else base_environment

    try:
        project_path = find_project_config(start_dir)
        project_config = load_project_config(project_path)
    except ProjectConfigError as exc:
        raise BindCommandError(str(exc)) from exc

    context = project_config.contexts.get(environment)
    if context is None:
        available = ", ".join(sorted(project_config.contexts))
        raise BindCommandError(
            f"unknown environment {environment!r}; available environments: {available}"
        )

    try:
        bindings = load_bindings(bindings_path)
    except LocalBindingsError as exc:
        raise BindCommandError(str(exc)) from exc

    current_profile = bindings.get_profile(project_config.project, environment)
    _render_context(
        project=project_config.project,
        context=context,
        current_profile=current_profile,
        stdout=output_stream,
    )

    try:
        selected = select_or_create_profile(
            project=project_config.project,
            environment=environment,
            current_profile=current_profile,
            base_environment=base,
            stdin=input_stream,
            stdout=output_stream,
            profiles_loader=profiles_loader,
            command_runner=command_runner,
            cli_info_provider=cli_info_provider,
        )
    except ProfileSelectionCancelled as exc:
        raise BindCommandCancelled(input_closed=exc.input_closed) from exc
    except ProfileWorkflowError as exc:
        raise BindCommandError(str(exc)) from exc
    selected_profile = selected["name"]
    changed = selected_profile != current_profile

    if changed:
        try:
            updated = bindings.with_binding(
                project_config.project,
                environment,
                selected_profile,
            )
            save_bindings(updated)
        except LocalBindingsError as exc:
            raise BindCommandError(str(exc)) from exc

    return BindResult(
        project=project_config.project,
        environment=environment,
        profile=selected_profile,
        previous_profile=current_profile,
        changed=changed,
    )


def _render_context(
    *,
    project: str,
    context: ProjectContext,
    current_profile: str | None,
    stdout: TextIO,
) -> None:
    heading = f"{project} · {context.name.upper()}"
    if context.protected:
        heading = f"{heading} · {text('cli_protected')}"

    output = CliConsole(stdout)
    if output.enhanced:
        title = Text.assemble(
            ("awsui", "awsui.title"),
            (" · ", "awsui.muted"),
            safe_text(project, "awsui.value"),
            (" / ", "awsui.muted"),
            safe_text(context.name.upper(), "awsui.title"),
        )
        border_style = "cyan"
        if context.protected:
            title.append("  ")
            title.append(text("cli_protected"), style="awsui.protected")
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="awsui.label", no_wrap=True)
        grid.add_column(style="awsui.value")
        grid.add_row(text("cli_expected_account"), safe_text(context.account))
        grid.add_row(text("cli_region"), safe_text(context.region))
        if current_profile is not None:
            grid.add_row(text("cli_current_profile"), safe_text(current_profile))
        output.print(Panel(grid, title=title, border_style=border_style, expand=False))
        return

    print(heading, file=stdout)
    print(f"{text('cli_expected_account')}: {context.account}", file=stdout)
    print(f"{text('cli_region')}: {context.region}", file=stdout)
    print("", file=stdout)
    if current_profile is not None:
        print(f"{text('cli_current_profile')}: {current_profile}", file=stdout)
