"""Native Textual project initialization wizard."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum
from io import TextIOBase
from pathlib import Path
import sys
from threading import Event
from typing import TextIO

from rich.text import Text
from textual import work
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.worker import Worker, WorkerState, get_current_worker
from textual.widgets import (
    Button,
    Checkbox,
    Input,
    LoadingIndicator,
    OptionList,
    RichLog,
    Static,
)
from textual.widgets.option_list import Option

from .aws_cli import AwsCliInfo, get_aws_cli_info
from .context_verification import IdentityProvider
from .models import Profile
from .profile_authentication import describe_authentication
from .profile_catalog import ProfileCatalog, ProfileCatalogError, load_profile_catalog
from .profile_creation import (
    ProfileCommandRunner,
    ProfileCreationCommandCancelled,
    ProfileCreationError,
    ProfileCreationMethod,
    create_profile,
)
from .project_initialization import (
    InitResult,
    InitializedEnvironment,
    ProjectBindingsWriteError,
    ProjectInitializationError,
    commit_project_initialization,
    resolve_initialization_target,
    verify_initialization_environment,
)
from .tui_theme import TUI_RICH_STYLES


class InitWizardStep(Enum):
    """Visible step in the initialization wizard."""

    PROJECT = "project"
    CONTEXT = "context"
    CREATE_PROFILE = "create-profile"
    VERIFYING = "verifying"
    REVIEW = "review"


@dataclass(frozen=True, slots=True)
class InitScreenOutcome:
    """Wizard result, optionally carrying a recoverable bindings warning."""

    result: InitResult
    warning: str | None = None


class _AuthenticationOutput(TextIOBase):
    """Forward transient AWS CLI output from a worker into the wizard."""

    def __init__(self, screen: "InitializationScreen") -> None:
        super().__init__()
        self.screen = screen

    def writable(self) -> bool:
        return True

    def write(self, value: str) -> int:
        if value and not self.closed:
            try:
                self.screen.app.call_from_thread(
                    self.screen.append_authentication_output,
                    value,
                )
            except RuntimeError:
                pass
        return len(value)

    def flush(self) -> None:
        return None


class InitializationScreen(Screen[InitScreenOutcome | None]):
    """Full-screen, keyboard-first project initialization workflow."""

    CSS = """
    InitializationScreen {
        layout: vertical;
        background: $background;
        color: $text;
    }
    #init-header {
        height: 3;
        padding: 0 2;
        align-vertical: middle;
        border-bottom: solid $border;
        background: $background;
    }
    #init-brand {
        width: auto;
        margin-right: 2;
        color: $text;
        text-style: bold;
    }
    #init-heading { width: 1fr; color: $text; text-style: bold; }
    #init-path { width: auto; color: $text-muted; }
    #init-progress {
        height: 2;
        padding: 0 2;
        color: $text-muted;
        background: $surface;
        border-bottom: solid $border;
    }
    #init-scroll { height: 1fr; }
    .init-step {
        width: 1fr;
        height: auto;
        margin: 2 4;
        padding: 1 2;
        background: $surface;
        border: solid $border;
    }
    .init-title { height: 2; color: $text; text-style: bold; }
    .init-help { height: auto; margin-bottom: 1; color: $text-muted; }
    .init-label { height: 1; margin-top: 1; color: $text-muted; }
    .init-error { height: auto; margin-top: 1; color: $text-error; }
    .init-actions {
        height: 3;
        margin-top: 1;
        align-horizontal: right;
        align-vertical: middle;
    }
    .init-actions Button, .init-inline-actions Button {
        width: auto;
        min-width: 9;
        height: 1;
        margin-left: 1;
        padding: 0 1;
        border: none;
        background: transparent;
        color: $text-muted;
    }
    .init-actions Button:hover, .init-actions Button:focus,
    .init-inline-actions Button:hover, .init-inline-actions Button:focus {
        background: $panel;
        color: $text;
    }
    .init-primary { color: $text-primary; }
    .init-primary:hover, .init-primary:focus { background: $primary-muted; }
    .init-danger { color: $text-error; }
    .init-inline-actions { height: 3; align-horizontal: right; }
    #init-profile-list, #init-method-list, #init-review-list {
        height: 9;
        margin-top: 1;
        border: solid $border;
        background: $background;
    }
    #init-profile-list:focus, #init-method-list:focus, #init-review-list:focus,
    InitializationScreen Input:focus {
        border: tall $primary;
    }
    InitializationScreen Input { margin-bottom: 1; }
    #init-protected { margin: 1 0; }
    #init-auth-spinner { height: 3; color: $text-primary; }
    #init-auth-status { height: auto; margin-bottom: 1; color: $text; }
    #init-auth-log {
        height: 10;
        padding: 0 1;
        border: solid $border;
        background: $background;
        color: $text-muted;
    }
    #init-review-detail {
        height: auto;
        min-height: 6;
        margin-top: 1;
        padding: 1;
        background: $background;
        color: $text;
    }
    #init-access-warning { height: auto; margin-top: 1; color: $text-warning; }
    """

    BINDINGS = [
        Binding("escape", "back", "Back"),
    ]

    def __init__(
        self,
        *,
        start_dir: Path,
        bindings_path: Path | None,
        base_environment: Mapping[str, str],
        translations: Mapping[str, str],
        identity_provider: IdentityProvider | None = None,
        profiles_loader: Callable[[], list[Profile]] | None = None,
        command_runner: ProfileCommandRunner | None = None,
        cli_info_provider: Callable[[], AwsCliInfo | None] = get_aws_cli_info,
    ) -> None:
        super().__init__()
        self.start_dir = start_dir
        self.bindings_path = bindings_path
        self.base_environment = dict(base_environment)
        self.translations = translations
        self.identity_provider = identity_provider
        self.profiles_loader = profiles_loader
        self.command_runner = command_runner
        self.cli_info_provider = cli_info_provider
        self.target = resolve_initialization_target(start_dir)
        self.step = InitWizardStep.PROJECT
        self.project = self.target.default_project
        self.environments: list[InitializedEnvironment] = []
        self.catalog = ProfileCatalog.from_profiles(())
        self.selected_profile: str | None = None
        self.selected_method = ProfileCreationMethod.SSO
        self.editing_index: int | None = None
        self.review_index = 0
        self.verification_worker: Worker[InitializedEnvironment] | None = None
        self.cancel_verification = Event()
        self.discard_armed = False
        self.access_key_confirmed = False

    def _text(self, key: str, **values: object) -> str:
        return self.translations[key].format(**values)

    def compose(self) -> ComposeResult:
        with Horizontal(id="init-header"):
            yield Static("awsui", id="init-brand")
            yield Static(self._text("init_title"), id="init-heading")
            yield Static(str(self.target.directory), id="init-path")
        yield Static(id="init-progress")
        with VerticalScroll(id="init-scroll"):
            with Vertical(id="init-project-step", classes="init-step"):
                yield Static(self._text("init_project_title"), classes="init-title")
                yield Static(self._text("init_project_help"), classes="init-help")
                yield Static(self._text("init_project_label"), classes="init-label")
                yield Input(value=self.project, id="init-project-name")
                yield Static(id="init-project-error", classes="init-error")
                with Horizontal(classes="init-actions"):
                    yield Button(
                        self._text("action_cancel"),
                        id="init-cancel",
                        compact=True,
                        flat=True,
                    )
                    yield Button(
                        self._text("action_continue"),
                        id="init-project-next",
                        classes="init-primary",
                        compact=True,
                        flat=True,
                    )

            with Vertical(id="init-context-step", classes="init-step"):
                yield Static(self._text("init_context_title"), classes="init-title")
                yield Static(self._text("init_context_help"), classes="init-help")
                yield Static(self._text("init_environment_label"), classes="init-label")
                yield Input(
                    placeholder=self._text("init_environment_placeholder"),
                    id="init-environment-name",
                )
                yield Static(self._text("init_profile_label"), classes="init-label")
                yield OptionList(id="init-profile-list", markup=False)
                with Horizontal(classes="init-inline-actions"):
                    yield Button(
                        self._text("action_refresh_profiles"),
                        id="init-profile-refresh",
                        compact=True,
                        flat=True,
                    )
                    yield Button(
                        self._text("action_create_profile"),
                        id="init-profile-create",
                        classes="init-primary",
                        compact=True,
                        flat=True,
                    )
                yield Static(self._text("field_region"), classes="init-label")
                yield Input(id="init-region")
                yield Checkbox(
                    self._text("init_protected_label"),
                    id="init-protected",
                    compact=True,
                )
                yield Static(id="init-context-error", classes="init-error")
                with Horizontal(classes="init-actions"):
                    yield Button(
                        self._text("action_back"),
                        id="init-context-back",
                        compact=True,
                        flat=True,
                    )
                    yield Button(
                        self._text("action_verify_add"),
                        id="init-verify",
                        classes="init-primary",
                        compact=True,
                        flat=True,
                    )

            with Vertical(id="init-create-step", classes="init-step"):
                yield Static(
                    self._text("init_create_profile_title"), classes="init-title"
                )
                yield Static(
                    self._text("init_create_profile_help"), classes="init-help"
                )
                yield OptionList(id="init-method-list", markup=False)
                yield Static(self._text("init_profile_name_label"), classes="init-label")
                yield Input(id="init-new-profile-name")
                yield Static(
                    self._text("init_access_key_warning"),
                    id="init-access-warning",
                )
                yield Static(id="init-create-error", classes="init-error")
                with Horizontal(classes="init-actions"):
                    yield Button(
                        self._text("action_back"),
                        id="init-create-back",
                        compact=True,
                        flat=True,
                    )
                    yield Button(
                        self._text("action_open_aws_cli"),
                        id="init-create-start",
                        classes="init-primary",
                        compact=True,
                        flat=True,
                    )

            with Vertical(id="init-verifying-step", classes="init-step"):
                yield Static(self._text("init_verify_title"), classes="init-title")
                yield LoadingIndicator(id="init-auth-spinner")
                yield Static(self._text("authenticating"), id="init-auth-status")
                yield RichLog(
                    max_lines=40,
                    wrap=True,
                    markup=False,
                    id="init-auth-log",
                )
                with Horizontal(classes="init-actions"):
                    yield Button(
                        self._text("action_cancel_verification"),
                        id="init-verification-cancel",
                        compact=True,
                        flat=True,
                    )

            with Vertical(id="init-review-step", classes="init-step"):
                yield Static(self._text("init_review_title"), classes="init-title")
                yield Static(self._text("init_review_help"), classes="init-help")
                yield OptionList(id="init-review-list", markup=False)
                yield Static(id="init-review-detail")
                yield Static(id="init-review-error", classes="init-error")
                with Horizontal(classes="init-actions"):
                    yield Button(
                        self._text("action_cancel"),
                        id="init-review-cancel",
                        classes="init-danger",
                        compact=True,
                        flat=True,
                    )
                    yield Button(
                        self._text("action_remove"),
                        id="init-review-remove",
                        compact=True,
                        flat=True,
                    )
                    yield Button(
                        self._text("action_edit"),
                        id="init-review-edit",
                        compact=True,
                        flat=True,
                    )
                    yield Button(
                        self._text("action_add_environment"),
                        id="init-review-add",
                        compact=True,
                        flat=True,
                    )
                    yield Button(
                        self._text("action_create_project"),
                        id="init-finish",
                        classes="init-primary",
                        compact=True,
                        flat=True,
                    )

    def on_mount(self) -> None:
        self._load_profiles()
        self._populate_creation_methods()
        self._show_step(InitWizardStep.PROJECT)

    def _show_step(self, step: InitWizardStep) -> None:
        self.step = step
        step_ids = {
            InitWizardStep.PROJECT: "#init-project-step",
            InitWizardStep.CONTEXT: "#init-context-step",
            InitWizardStep.CREATE_PROFILE: "#init-create-step",
            InitWizardStep.VERIFYING: "#init-verifying-step",
            InitWizardStep.REVIEW: "#init-review-step",
        }
        for candidate, selector in step_ids.items():
            self.query_one(selector).display = candidate is step
        progress = {
            InitWizardStep.PROJECT: self._text("init_progress_project"),
            InitWizardStep.CONTEXT: self._text("init_progress_context"),
            InitWizardStep.CREATE_PROFILE: self._text("init_progress_profile"),
            InitWizardStep.VERIFYING: self._text("init_progress_verify"),
            InitWizardStep.REVIEW: self._text("init_progress_review"),
        }[step]
        self.query_one("#init-progress", Static).update(progress)
        focus_selector = {
            InitWizardStep.PROJECT: "#init-project-name",
            InitWizardStep.CONTEXT: "#init-environment-name",
            InitWizardStep.CREATE_PROFILE: "#init-method-list",
            InitWizardStep.VERIFYING: "#init-verification-cancel",
            InitWizardStep.REVIEW: "#init-review-list",
        }[step]
        self.query_one(focus_selector).focus()

    def _set_error(self, selector: str, message: str | None) -> None:
        widget = self.query_one(selector, Static)
        widget.update(message or "")
        widget.display = bool(message)

    def _load_profiles(self, preferred: str | None = None) -> None:
        try:
            self.catalog = load_profile_catalog(self.profiles_loader)
        except ProfileCatalogError as exc:
            self.catalog = ProfileCatalog.from_profiles(())
            self.selected_profile = None
            self._set_error("#init-context-error", str(exc))
        profile_list = self.query_one("#init-profile-list", OptionList)
        profile_list.clear_options()
        options: list[Option] = []
        for index, profile in enumerate(self.catalog.profiles):
            detail = describe_authentication(profile)
            if profile.get("region"):
                detail += f" · {profile['region']}"
            options.append(
                Option(
                    Text.assemble(
                        (profile["name"], TUI_RICH_STYLES.value),
                        (f"  {detail}", TUI_RICH_STYLES.muted),
                    ),
                    id=f"profile-{index}",
                )
            )
        if not options:
            options.append(
                Option(
                    self._text("init_no_profiles"),
                    id="profile-empty",
                    disabled=True,
                )
            )
        profile_list.add_options(options)
        names = [profile["name"] for profile in self.catalog.profiles]
        selected = preferred if preferred in names else (names[0] if names else None)
        self._select_profile(selected, update_region=True)

    def _select_profile(self, profile_name: str | None, *, update_region: bool) -> None:
        self.selected_profile = profile_name
        if profile_name is None:
            return
        for index, profile in enumerate(self.catalog.profiles):
            if profile["name"] == profile_name:
                self.query_one("#init-profile-list", OptionList).highlighted = index
                if update_region:
                    region = (
                        profile.get("region")
                        or self.base_environment.get("AWS_REGION")
                        or self.base_environment.get("AWS_DEFAULT_REGION")
                        or ""
                    )
                    self.query_one("#init-region", Input).value = region
                break

    def _populate_creation_methods(self) -> None:
        cli_info = self.cli_info_provider()
        console_available = bool(cli_info and cli_info.supports_console_login)
        methods = self.query_one("#init-method-list", OptionList)
        methods.clear_options()
        methods.add_options(
            [
                Option(
                    self._text("init_method_sso"),
                    id=ProfileCreationMethod.SSO.value,
                ),
                Option(
                    self._text(
                        "init_method_console"
                        if console_available
                        else "init_method_console_unavailable"
                    ),
                    id=ProfileCreationMethod.CONSOLE.value,
                    disabled=not console_available,
                ),
                Option(
                    self._text("init_method_access_key"),
                    id=ProfileCreationMethod.ACCESS_KEY.value,
                ),
            ]
        )
        methods.highlighted = 0
        self.selected_method = ProfileCreationMethod.SSO
        self.query_one("#init-access-warning", Static).display = False

    def on_option_list_option_highlighted(
        self,
        event: OptionList.OptionHighlighted,
    ) -> None:
        option_id = event.option.id
        if event.option_list.id == "init-profile-list" and option_id:
            if option_id.startswith("profile-") and option_id != "profile-empty":
                index = int(option_id.removeprefix("profile-"))
                self._select_profile(
                    self.catalog.profiles[index]["name"],
                    update_region=True,
                )
        elif event.option_list.id == "init-method-list" and option_id:
            self.selected_method = ProfileCreationMethod(option_id)
            is_access_key = self.selected_method is ProfileCreationMethod.ACCESS_KEY
            self.access_key_confirmed = False
            self.query_one("#init-access-warning", Static).display = is_access_key
            self.query_one("#init-create-start", Button).label = self._text(
                "action_open_aws_cli"
            )
        elif event.option_list.id == "init-review-list" and option_id:
            if option_id.startswith("review-"):
                self.review_index = int(option_id.removeprefix("review-"))
                self._render_review_detail()

    def on_option_list_option_selected(
        self,
        event: OptionList.OptionSelected,
    ) -> None:
        if event.option_list.id == "init-review-list":
            self._edit_review_environment()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "init-project-name":
            self._continue_project()
        elif event.input.id in {"init-environment-name", "init-region"}:
            self._start_verification()
        elif event.input.id == "init-new-profile-name":
            self._start_profile_creation()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        actions = {
            "init-cancel": self.action_cancel,
            "init-project-next": self._continue_project,
            "init-context-back": self.action_back,
            "init-profile-refresh": self._refresh_profiles,
            "init-profile-create": self._open_profile_creation,
            "init-verify": self._start_verification,
            "init-create-back": self.action_back,
            "init-create-start": self._start_profile_creation,
            "init-verification-cancel": self._cancel_active_verification,
            "init-review-cancel": self.action_cancel,
            "init-review-remove": self._remove_review_environment,
            "init-review-edit": self._edit_review_environment,
            "init-review-add": self._add_environment,
            "init-finish": self._finish,
        }
        action = actions.get(event.button.id or "")
        if action is not None:
            action()

    def _continue_project(self) -> None:
        project = self.query_one("#init-project-name", Input).value.strip()
        if not project:
            self._set_error(
                "#init-project-error",
                self._text("init_error_project_required"),
            )
            return
        self.project = project
        self._set_error("#init-project-error", None)
        self._prepare_context_form()
        self._show_step(InitWizardStep.CONTEXT)

    def _prepare_context_form(
        self,
        environment: InitializedEnvironment | None = None,
    ) -> None:
        name = "" if environment is None else environment.name
        self.query_one("#init-environment-name", Input).value = name
        self.query_one("#init-protected", Checkbox).value = bool(
            environment and environment.protected
        )
        if environment is None:
            preferred = self.selected_profile
            self._select_profile(preferred, update_region=True)
        else:
            self._select_profile(environment.profile, update_region=False)
            self.query_one("#init-region", Input).value = environment.region
        self._set_error("#init-context-error", None)

    def _refresh_profiles(self) -> None:
        self._load_profiles(preferred=self.selected_profile)
        self.notify(self._text("notification_profiles_reloaded"))

    def _open_profile_creation(self) -> None:
        environment = self.query_one("#init-environment-name", Input).value.strip()
        suffix = environment or self._text("init_environment_default_suffix")
        self.query_one("#init-new-profile-name", Input).value = (
            f"{self.project}-{suffix}"
        )
        self._set_error("#init-create-error", None)
        self.access_key_confirmed = False
        self._show_step(InitWizardStep.CREATE_PROFILE)

    def _start_profile_creation(self) -> None:
        profile_name = self.query_one("#init-new-profile-name", Input).value.strip()
        if not profile_name:
            self._set_error(
                "#init-create-error",
                self._text("init_error_profile_name_required"),
            )
            return
        if self.catalog.get(profile_name) is not None:
            self._set_error(
                "#init-create-error",
                self._text("init_error_profile_exists", profile=profile_name),
            )
            return
        if (
            self.selected_method is ProfileCreationMethod.ACCESS_KEY
            and not self.access_key_confirmed
        ):
            self.access_key_confirmed = True
            self.query_one("#init-create-start", Button).label = self._text(
                "action_confirm_access_key"
            )
            self._set_error(
                "#init-create-error",
                self._text("init_confirm_access_key"),
            )
            return

        creation_kwargs: dict[str, object] = {}
        if self.command_runner is not None:
            creation_kwargs["command_runner"] = self.command_runner
        try:
            with self.app.suspend():
                created = create_profile(
                    method=self.selected_method,
                    profile_name=profile_name,
                    base_environment=self.base_environment,
                    output=sys.stdout,
                    profiles_loader=self.profiles_loader,
                    **creation_kwargs,
                )
        except (ProfileCreationCommandCancelled, KeyboardInterrupt):
            self.notify(
                self._text("notification_profile_creation_cancelled"),
                severity="warning",
            )
            return
        except ProfileCreationError as exc:
            self._set_error("#init-create-error", str(exc))
            return

        self._load_profiles(preferred=created["name"])
        self._set_error("#init-context-error", None)
        self._show_step(InitWizardStep.CONTEXT)
        self.notify(
            self._text("notification_profile_created", profile=created["name"]),
            severity="information",
        )

    def _validate_context_form(self) -> tuple[str, str, str, bool] | None:
        environment = self.query_one("#init-environment-name", Input).value.strip()
        region = self.query_one("#init-region", Input).value.strip()
        protected = self.query_one("#init-protected", Checkbox).value
        if not environment:
            self._set_error(
                "#init-context-error",
                self._text("init_error_environment_required"),
            )
            return None
        duplicate = next(
            (
                index
                for index, item in enumerate(self.environments)
                if item.name == environment and index != self.editing_index
            ),
            None,
        )
        if duplicate is not None:
            self._set_error(
                "#init-context-error",
                self._text("init_error_environment_duplicate", environment=environment),
            )
            return None
        if self.selected_profile is None:
            self._set_error(
                "#init-context-error",
                self._text("init_error_profile_required"),
            )
            return None
        if not region:
            self._set_error(
                "#init-context-error",
                self._text("init_error_region_required"),
            )
            return None
        self._set_error("#init-context-error", None)
        return environment, self.selected_profile, region, protected

    def _start_verification(self) -> None:
        values = self._validate_context_form()
        if values is None:
            return
        environment, profile, region, protected = values
        self.cancel_verification = Event()
        self.query_one("#init-auth-log", RichLog).clear()
        self.query_one("#init-auth-status", Static).update(
            self._text("init_verify_status", profile=profile)
        )
        self.query_one("#init-verification-cancel", Button).disabled = False
        self._show_step(InitWizardStep.VERIFYING)
        self.verification_worker = self._verify_in_background(
            environment,
            profile,
            region,
            protected,
        )

    @work(
        thread=True,
        group="init-verification",
        exclusive=True,
        exit_on_error=False,
    )
    def _verify_in_background(
        self,
        environment: str,
        profile: str,
        region: str,
        protected: bool,
    ) -> InitializedEnvironment:
        worker = get_current_worker()
        output: TextIO = _AuthenticationOutput(self)
        return verify_initialization_environment(
            name=environment,
            profile=profile,
            region=region,
            protected=protected,
            base_environment=self.base_environment,
            identity_provider=self.identity_provider,
            login_output=output,
            cancel_check=lambda: self.cancel_verification.is_set()
            or worker.is_cancelled,
        )

    def on_worker_state_changed(self, event: Worker.StateChanged) -> None:
        if event.worker is not self.verification_worker:
            return
        if event.state not in {
            WorkerState.SUCCESS,
            WorkerState.ERROR,
            WorkerState.CANCELLED,
        }:
            return
        self.verification_worker = None
        if self.cancel_verification.is_set() or event.state is WorkerState.CANCELLED:
            self._show_step(InitWizardStep.CONTEXT)
            self._set_error(
                "#init-context-error",
                self._text("notification_verification_cancelled"),
            )
            return
        if event.state is WorkerState.ERROR:
            error = event.worker.error
            detail = str(error) if error is not None else self._text("unknown_error")
            self._show_step(InitWizardStep.CONTEXT)
            self._set_error("#init-context-error", detail)
            return
        verified = event.worker.result
        if verified is None:
            self._show_step(InitWizardStep.CONTEXT)
            self._set_error(
                "#init-context-error",
                self._text("unknown_error"),
            )
            return
        if self.editing_index is None:
            self.environments.append(verified)
            self.review_index = len(self.environments) - 1
        else:
            self.environments[self.editing_index] = verified
            self.review_index = self.editing_index
            self.editing_index = None
        self._refresh_review()
        self._show_step(InitWizardStep.REVIEW)
        self.notify(
            self._text(
                "notification_environment_verified",
                environment=verified.name,
            ),
            severity="information",
        )

    def append_authentication_output(self, value: str) -> None:
        for line in value.splitlines():
            if line.strip():
                self.query_one("#init-auth-log", RichLog).write(line)

    def _cancel_active_verification(self) -> None:
        if self.verification_worker is None:
            return
        self.cancel_verification.set()
        self.query_one("#init-auth-status", Static).update(
            self._text("init_cancelling_verification")
        )
        self.query_one("#init-verification-cancel", Button).disabled = True

    def _refresh_review(self) -> None:
        review = self.query_one("#init-review-list", OptionList)
        review.clear_options()
        review.add_options(
            [
                Option(
                    Text.assemble(
                        (item.name.upper(), TUI_RICH_STYLES.title),
                        (f"  {item.account}", TUI_RICH_STYLES.value),
                        (
                            f"  {self._text('protected')}" if item.protected else "",
                            TUI_RICH_STYLES.protected,
                        ),
                    ),
                    id=f"review-{index}",
                )
                for index, item in enumerate(self.environments)
            ]
        )
        self.review_index = min(self.review_index, len(self.environments) - 1)
        review.highlighted = max(self.review_index, 0)
        self._render_review_detail()
        self._set_error("#init-review-error", None)
        self.discard_armed = False

    def _render_review_detail(self) -> None:
        if not self.environments:
            self.query_one("#init-review-detail", Static).update("")
            return
        item = self.environments[self.review_index]
        lines = Text()
        fields = (
            (self._text("field_environment"), item.name),
            (self._text("field_actual_account"), item.account),
            (self._text("field_region"), item.region),
            (self._text("field_local_profile"), item.profile),
        )
        for label, value in fields:
            lines.append(f"{label:<20}", style=TUI_RICH_STYLES.label)
            lines.append(f"{value}\n", style=TUI_RICH_STYLES.value)
        if item.principal_arn:
            lines.append(f"{self._text('field_principal'):<20}", style=TUI_RICH_STYLES.label)
            lines.append(item.principal_arn, style=TUI_RICH_STYLES.muted)
        self.query_one("#init-review-detail", Static).update(lines)

    def _add_environment(self) -> None:
        self.editing_index = None
        self._prepare_context_form()
        self._show_step(InitWizardStep.CONTEXT)

    def _edit_review_environment(self) -> None:
        if not self.environments:
            return
        self.editing_index = self.review_index
        self._prepare_context_form(self.environments[self.review_index])
        self._show_step(InitWizardStep.CONTEXT)

    def _remove_review_environment(self) -> None:
        if len(self.environments) <= 1:
            self._set_error(
                "#init-review-error",
                self._text("init_error_one_environment_required"),
            )
            return
        removed = self.environments.pop(self.review_index)
        self.review_index = min(self.review_index, len(self.environments) - 1)
        self._refresh_review()
        self.notify(
            self._text("notification_environment_removed", environment=removed.name),
            severity="information",
        )

    def _finish(self) -> None:
        self._set_error("#init-review-error", None)
        try:
            result = commit_project_initialization(
                project=self.project,
                environments=self.environments,
                start_dir=self.target.directory,
                bindings_path=self.bindings_path,
            )
        except ProjectBindingsWriteError as exc:
            partial = InitResult(
                project=self.project,
                config_path=exc.config_path.resolve(),
                environments=tuple(self.environments),
            )
            self.dismiss(InitScreenOutcome(partial, str(exc)))
            return
        except ProjectInitializationError as exc:
            self._set_error("#init-review-error", str(exc))
            return
        self.dismiss(InitScreenOutcome(result))

    def action_back(self) -> None:
        if self.step is InitWizardStep.PROJECT:
            self.action_cancel()
        elif self.step is InitWizardStep.CONTEXT:
            if self.environments:
                self.editing_index = None
                self._refresh_review()
                self._show_step(InitWizardStep.REVIEW)
            else:
                self._show_step(InitWizardStep.PROJECT)
        elif self.step is InitWizardStep.CREATE_PROFILE:
            self._show_step(InitWizardStep.CONTEXT)
        elif self.step is InitWizardStep.VERIFYING:
            self._cancel_active_verification()
        else:
            self.action_cancel()

    def action_cancel(self) -> None:
        if self.step is InitWizardStep.VERIFYING:
            self._cancel_active_verification()
            return
        if self.environments and not self.discard_armed:
            self.discard_armed = True
            self._set_error(
                "#init-review-error",
                self._text("init_confirm_discard"),
            )
            if self.step is not InitWizardStep.REVIEW:
                self._refresh_review()
                self.discard_armed = True
                self._set_error(
                    "#init-review-error",
                    self._text("init_confirm_discard"),
                )
                self._show_step(InitWizardStep.REVIEW)
            return
        self.dismiss(None)
