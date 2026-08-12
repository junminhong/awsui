"""Static widget tree for the native project initialization wizard."""

from collections.abc import Callable
from pathlib import Path

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Checkbox,
    Input,
    LoadingIndicator,
    OptionList,
    RichLog,
    Static,
)


def compose_initialization_view(
    *,
    project: str,
    target_directory: Path,
    text: Callable[[str], str],
) -> ComposeResult:
    """Compose the wizard's fixed widget hierarchy."""
    with Horizontal(id="init-header"):
        yield Static("awsui", id="init-brand")
        yield Static(text("init_title"), id="init-heading")
        yield Static(str(target_directory), id="init-path")
    yield Static(id="init-progress")
    with VerticalScroll(id="init-scroll"):
        with Vertical(id="init-project-step", classes="init-step"):
            yield Static(text("init_project_title"), classes="init-title")
            yield Static(text("init_project_help"), classes="init-help")
            yield Static(text("init_project_label"), classes="init-label")
            yield Input(value=project, id="init-project-name")
            yield Static(id="init-project-error", classes="init-error")
            with Horizontal(classes="init-actions"):
                yield Button(
                    text("action_cancel"),
                    id="init-cancel",
                    compact=True,
                    flat=True,
                )
                yield Button(
                    text("action_continue"),
                    id="init-project-next",
                    classes="init-primary",
                    compact=True,
                    flat=True,
                )

        with Vertical(id="init-context-step", classes="init-step"):
            yield Static(text("init_context_title"), classes="init-title")
            yield Static(text("init_context_help"), classes="init-help")
            yield Static(text("init_environment_label"), classes="init-label")
            yield Input(
                placeholder=text("init_environment_placeholder"),
                id="init-environment-name",
            )
            yield Static(text("init_profile_label"), classes="init-label")
            yield OptionList(id="init-profile-list", markup=False)
            with Horizontal(classes="init-inline-actions"):
                yield Button(
                    text("action_refresh_profiles"),
                    id="init-profile-refresh",
                    compact=True,
                    flat=True,
                )
                yield Button(
                    text("action_create_profile"),
                    id="init-profile-create",
                    classes="init-primary",
                    compact=True,
                    flat=True,
                )
            yield Static(text("field_region"), classes="init-label")
            yield Input(id="init-region")
            yield Checkbox(
                text("init_protected_label"),
                id="init-protected",
                compact=True,
            )
            yield Static(id="init-context-error", classes="init-error")
            with Horizontal(classes="init-actions"):
                yield Button(
                    text("action_back"),
                    id="init-context-back",
                    compact=True,
                    flat=True,
                )
                yield Button(
                    text("action_verify_add"),
                    id="init-verify",
                    classes="init-primary",
                    compact=True,
                    flat=True,
                )

        with Vertical(id="init-create-step", classes="init-step"):
            yield Static(text("init_create_profile_title"), classes="init-title")
            yield Static(text("init_create_profile_help"), classes="init-help")
            yield OptionList(id="init-method-list", markup=False)
            yield Static(text("init_profile_name_label"), classes="init-label")
            yield Input(id="init-new-profile-name")
            yield Static(
                text("init_access_key_warning"),
                id="init-access-warning",
            )
            yield Static(id="init-create-error", classes="init-error")
            with Horizontal(classes="init-actions"):
                yield Button(
                    text("action_back"),
                    id="init-create-back",
                    compact=True,
                    flat=True,
                )
                yield Button(
                    text("action_open_aws_cli"),
                    id="init-create-start",
                    classes="init-primary",
                    compact=True,
                    flat=True,
                )

        with Vertical(id="init-verifying-step", classes="init-step"):
            yield Static(text("init_verify_title"), classes="init-title")
            yield LoadingIndicator(id="init-auth-spinner")
            yield Static(text("authenticating"), id="init-auth-status")
            yield RichLog(
                max_lines=40,
                wrap=True,
                markup=False,
                id="init-auth-log",
            )
            with Horizontal(classes="init-actions"):
                yield Button(
                    text("action_cancel_verification"),
                    id="init-verification-cancel",
                    compact=True,
                    flat=True,
                )

        with Vertical(id="init-review-step", classes="init-step"):
            yield Static(text("init_review_title"), classes="init-title")
            yield Static(text("init_review_help"), classes="init-help")
            yield OptionList(id="init-review-list", markup=False)
            yield Static(id="init-review-detail")
            yield Static(id="init-review-error", classes="init-error")
            with Horizontal(classes="init-actions"):
                yield Button(
                    text("action_cancel"),
                    id="init-review-cancel",
                    classes="init-danger",
                    compact=True,
                    flat=True,
                )
                yield Button(
                    text("action_remove"),
                    id="init-review-remove",
                    compact=True,
                    flat=True,
                )
                yield Button(
                    text("action_edit"),
                    id="init-review-edit",
                    compact=True,
                    flat=True,
                )
                yield Button(
                    text("action_add_environment"),
                    id="init-review-add",
                    compact=True,
                    flat=True,
                )
                yield Button(
                    text("action_create_project"),
                    id="init-finish",
                    classes="init-primary",
                    compact=True,
                    flat=True,
                )
