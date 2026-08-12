"""Project-aware Textual dashboard for verified AWS contexts."""

from collections.abc import Mapping
from datetime import datetime
import os
from pathlib import Path
import shlex
import sys

from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, HorizontalScroll, Vertical
from textual.widgets import Button, ListView, Static

from ..cli.bind import BindCommandCancelled, BindCommandError, bind_environment
from ..cli.console import CliConsole, safe_text
from ..cli.presenter import (
    DoctorRenderStyles,
    render_doctor_report_rich,
    render_launch_context,
    render_launch_context_rich,
    render_status_rich,
)
from ..command_runner import CommandLaunchError, run_command, select_interactive_shell
from ..context.dashboard import (
    ContextItem,
    ContextStatus,
    DashboardSnapshot,
    load_dashboard,
)
from ..context.resolution import ContextResolutionError
from ..context.runtime import VerifiedRuntime, prepare_context_runtime
from ..context.verification import (
    AccountMismatchError,
    ContextVerificationError,
    VerifiedContext,
    describe_principal,
)
from ..doctor import diagnose
from ..i18n import LANG_EN, LANG_ZH_TW
from ..logging import get_logger
from ..profiles.catalog import ProfileCatalogError
from ..project.bindings import LocalBindingsError
from ..project.config import (
    ProjectConfigError,
    ProjectConfigNotFoundError,
)
from ..project.initialization import ProjectInitializationError
from .initialization import InitializationScreen, InitScreenOutcome
from .launch import (
    LaunchCommandError,
    detect_tools,
    parse_launch_command,
)
from .screens import InformationScreen, LaunchScreen
from .styles import DASHBOARD_CSS
from .theme import AWSUI_GRAPHITE_THEME, TUI_RICH_STYLES
from .widgets import ContextList, STATUS_PRESENTATION

_TUI_DOCTOR_STYLES = DoctorRenderStyles(
    value=TUI_RICH_STYLES.value,
    muted=TUI_RICH_STYLES.muted,
    success=TUI_RICH_STYLES.success,
    error=TUI_RICH_STYLES.error,
    option=TUI_RICH_STYLES.primary,
    title=TUI_RICH_STYLES.title,
    healthy_border=TUI_RICH_STYLES.success,
    unhealthy_border=TUI_RICH_STYLES.error,
)


class AWSUIApp(App[None]):
    """Keyboard-first dashboard for project AWS environments."""

    TITLE = "awsui"
    CSS = DASHBOARD_CSS

    BINDINGS = [
        Binding("v", "verify_context", "Verify", show=True),
        Binding("b", "bind_context", "Bind", show=True),
        Binding("l", "launch", "Launch", show=True),
        Binding("s", "open_shell", "Shell", show=True),
        Binding("d", "doctor", "Doctor", show=True),
        Binding("r", "reload", "Reload", show=True),
        Binding("i", "initialize", "Init", show=False),
        Binding("?", "show_help", "Help", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    def __init__(
        self,
        lang: str = "en",
        log_level: str = "INFO",
        *,
        start_dir: Path | None = None,
        bindings_path: Path | None = None,
        base_environment: Mapping[str, str] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.register_theme(AWSUI_GRAPHITE_THEME)
        self.theme = AWSUI_GRAPHITE_THEME.name
        self.lang = LANG_ZH_TW if lang == "zh-TW" else LANG_EN
        self.logger = get_logger(log_level)
        self.start_dir = Path.cwd() if start_dir is None else Path(start_dir)
        self.bindings_path = bindings_path
        self.base_environment = dict(
            os.environ if base_environment is None else base_environment
        )
        self.snapshot: DashboardSnapshot | None = None
        self.selected_environment: str | None = None
        self.statuses: dict[str, ContextStatus] = {}
        self.verified: dict[str, VerifiedContext] = {}
        self.verified_at: dict[str, datetime] = {}
        self.actual_accounts: dict[str, str] = {}
        self.errors: dict[str, str] = {}
        self.load_error: str | None = None
        self.tools = detect_tools(self.base_environment)

    def compose(self) -> ComposeResult:
        with Horizontal(id="top-bar"):
            yield Static("awsui", id="brand")
            yield Static(id="breadcrumb")
            yield Static(self._text("topbar_product"), id="product-label")
        with Horizontal(id="dashboard"):
            with Vertical(id="context-pane"):
                yield Static(
                    self._text("environment_heading"), id="environment-heading"
                )
                yield ContextList(id="context-list")
            with Vertical(id="detail-pane"):
                yield Static(id="detail-content")
        with HorizontalScroll(id="action-bar"):
            yield self._action_button("i", "action_initialize", "initialize")
            yield self._action_button("b", "action_bind", "bind")
            yield self._action_button("v", "action_verify", "verify")
            yield self._action_button("l", "action_launch", "launch")
            yield self._action_button("s", "action_shell", "shell")
            yield self._action_button("d", "action_doctor", "doctor")
            yield self._action_button("r", "action_reload", "reload")
            yield self._action_button("?", "action_help", "help")
            yield self._action_button("q", "action_quit", "quit")

    def _action_button(self, key: str, label_key: str, button_id: str) -> Button:
        return Button(
            f"{key}  {self._text(label_key)}",
            id=button_id,
            compact=True,
            flat=True,
        )

    def _text(self, key: str, **values: object) -> str:
        return self.lang[key].format(**values)

    def on_mount(self) -> None:
        self.reload_dashboard()
        if self.snapshot is not None:
            self.query_one("#context-list", ContextList).focus()
        elif not self.load_error:
            self.query_one("#initialize", Button).focus()

    def reload_dashboard(self) -> None:
        """Reload local dashboard state without making AWS calls."""
        previous = self.selected_environment
        try:
            snapshot = load_dashboard(
                start_dir=self.start_dir,
                bindings_path=self.bindings_path,
            )
        except ProjectConfigNotFoundError:
            self.snapshot = None
            self.load_error = None
            self.selected_environment = None
            self.statuses.clear()
            self._render_onboarding()
            return
        except (ProjectConfigError, LocalBindingsError, ProfileCatalogError) as exc:
            self.snapshot = None
            self.load_error = str(exc)
            self.selected_environment = None
            self.statuses.clear()
            self._render_load_error()
            return

        self.snapshot = snapshot
        self.load_error = None
        self.sub_title = snapshot.project
        self.statuses = {item.name: item.status for item in snapshot.contexts}
        self.verified.clear()
        self.verified_at.clear()
        self.actual_accounts.clear()
        self.errors.clear()
        available = {item.name for item in snapshot.contexts}
        self.selected_environment = (
            previous if previous in available else snapshot.contexts[0].name
        )
        self._refresh_context_list()
        self._render_selected_context()
        self.logger.info(
            "dashboard_loaded",
            project=snapshot.project,
            contexts=len(snapshot.contexts),
        )

    def _refresh_context_list(self) -> None:
        context_list = self.query_one("#context-list", ContextList)
        if self.snapshot is None:
            context_list.clear()
            return
        context_list.set_contexts(self.snapshot.contexts, self.statuses, self.lang)
        selected_index = next(
            (
                index
                for index, item in enumerate(self.snapshot.contexts)
                if item.name == self.selected_environment
            ),
            0,
        )
        context_list.index = selected_index
        selected_environment = self.selected_environment
        if selected_environment is not None:
            self.call_after_refresh(
                self._restore_context_selection,
                selected_environment,
            )
        breadcrumb = Text(
            f"{self.snapshot.project}  ·  {self.snapshot.config_path.name}",
            style=TUI_RICH_STYLES.muted,
        )
        breadcrumb.stylize(
            TUI_RICH_STYLES.title,
            0,
            len(self.snapshot.project),
        )
        self.query_one("#breadcrumb", Static).update(breadcrumb)

    def _restore_context_selection(self, environment: str) -> None:
        """Restore selection after ListView has mounted its replacement rows."""
        if self.snapshot is None:
            return
        selected_index = next(
            (
                index
                for index, item in enumerate(self.snapshot.contexts)
                if item.name == environment
            ),
            0,
        )
        self.query_one("#context-list", ContextList).index = selected_index

    def _selected_item(self) -> ContextItem | None:
        if self.snapshot is None or self.selected_environment is None:
            return None
        return self.snapshot.get(self.selected_environment)

    def _render_selected_context(self) -> None:
        item = self._selected_item()
        if item is None:
            if self.load_error:
                self._render_load_error()
            else:
                self._render_onboarding()
            return

        status = self.statuses.get(item.name, item.status)
        symbol, label_key, style_name = STATUS_PRESENTATION[status]
        status_style = getattr(TUI_RICH_STYLES, style_name)
        label = self._text(label_key)
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style=TUI_RICH_STYLES.label, no_wrap=True)
        grid.add_column(style=TUI_RICH_STYLES.value)
        grid.add_row(
            self._text("field_environment"),
            safe_text(item.name.upper(), TUI_RICH_STYLES.value),
        )
        grid.add_row(
            self._text("field_expected_account"),
            safe_text(item.expected_account, TUI_RICH_STYLES.value),
        )
        grid.add_row(
            self._text("field_region"),
            safe_text(item.region, TUI_RICH_STYLES.value),
        )
        grid.add_row(
            self._text("field_local_profile"),
            safe_text(item.profile or "—", TUI_RICH_STYLES.value),
        )

        verified = self.verified.get(item.name)
        actual_account = (
            verified.actual_account
            if verified is not None
            else self.actual_accounts.get(item.name)
        )
        if actual_account:
            grid.add_row(
                self._text("field_actual_account"),
                safe_text(actual_account, TUI_RICH_STYLES.value),
            )
        if verified is not None:
            principal = describe_principal(verified.principal_arn)
            if principal is not None:
                principal_key = {
                    "Role": "field_role",
                    "User": "field_user",
                    "Principal": "field_principal",
                }[principal[0]]
                grid.add_row(
                    self._text(principal_key),
                    safe_text(principal[1], TUI_RICH_STYLES.value),
                )
            verified_time = (
                self.verified_at[item.name].astimezone().strftime("%H:%M:%S")
            )
            grid.add_row(
                self._text("field_last_verified"),
                safe_text(verified_time, TUI_RICH_STYLES.value),
            )

        status_text = Text.assemble(
            (f"{symbol} ", status_style),
            (label, status_style),
        )
        guidance = self._context_guidance(item, status)
        heading = Text(item.name.upper(), style=TUI_RICH_STYLES.title)
        if item.protected:
            heading.append(
                f" · {self._text('protected')}",
                style=TUI_RICH_STYLES.protected,
            )
        body: list[RenderableType] = [heading, Text(), grid, Text(), status_text]
        if guidance:
            body.extend([Text(), safe_text(guidance, TUI_RICH_STYLES.muted)])
        error = self.errors.get(item.name)
        if error:
            body.extend(
                [
                    Text(),
                    Text.assemble(
                        ("│ ", TUI_RICH_STYLES.error),
                        safe_text(error, TUI_RICH_STYLES.error),
                    ),
                ]
            )
        self.query_one("#detail-content", Static).update(Group(*body))
        self._update_actions(item)

    def _context_guidance(
        self,
        item: ContextItem,
        status: ContextStatus,
    ) -> str:
        if status is ContextStatus.UNBOUND:
            return self._text("guidance_unbound", environment=item.name)
        if status is ContextStatus.PROFILE_MISSING:
            return self._text("guidance_profile_missing")
        if status is ContextStatus.READY:
            return self._text("guidance_ready")
        if status is ContextStatus.VERIFYING:
            return self._text("guidance_verifying")
        if status is ContextStatus.VERIFIED:
            return self._text(
                "guidance_verified",
                project=self.snapshot.project,
                environment=item.name,
            )
        if status is ContextStatus.MISMATCH:
            return self._text("guidance_mismatch")
        return self._text("guidance_error")

    def _render_onboarding(self) -> None:
        self.sub_title = self._text("subtitle_no_project")
        self._refresh_context_list()
        body = Group(
            Text(
                self._text("onboarding_missing"),
                style=TUI_RICH_STYLES.warning,
            ),
            Text(),
            Text(self._text("onboarding_body"), style=TUI_RICH_STYLES.value),
            Text(),
            Text(self._text("onboarding_next"), style=TUI_RICH_STYLES.primary),
        )
        self.query_one("#breadcrumb", Static).update(
            Text(self._text("subtitle_no_project"), style=TUI_RICH_STYLES.muted)
        )
        self.query_one("#detail-content", Static).update(body)
        self._update_actions(None)

    def _render_load_error(self) -> None:
        self.sub_title = self._text("subtitle_configuration_error")
        self._refresh_context_list()
        body = Group(
            Text(self._text("load_error_heading"), style=TUI_RICH_STYLES.error),
            Text(),
            safe_text(
                self.load_error or self._text("load_error_unknown"),
                TUI_RICH_STYLES.value,
            ),
            Text(),
            Text(self._text("load_error_next"), style=TUI_RICH_STYLES.primary),
        )
        self.query_one("#breadcrumb", Static).update(
            Text(
                self._text("subtitle_configuration_error"),
                style=TUI_RICH_STYLES.error,
            )
        )
        self.query_one("#detail-content", Static).update(body)
        self._update_actions(None)

    def _update_actions(self, item: ContextItem | None) -> None:
        has_project = self.snapshot is not None
        runnable = item is not None and item.status is ContextStatus.READY
        self.query_one("#initialize", Button).display = (
            not has_project and not self.load_error
        )
        self.query_one("#doctor", Button).display = True
        self.query_one("#reload", Button).display = True
        self.query_one("#help", Button).display = True
        self.query_one("#quit", Button).display = True
        self.query_one("#bind", Button).display = has_project
        self.query_one("#verify", Button).display = runnable
        self.query_one("#launch", Button).display = runnable
        self.query_one("#shell", Button).display = runnable
        self.query_one("#bind", Button).disabled = item is None
        self.query_one("#verify", Button).disabled = False
        self.query_one("#launch", Button).disabled = False
        self.query_one("#shell", Button).disabled = False

    def on_list_view_highlighted(self, event: ListView.Highlighted) -> None:
        if event.item is None or event.item.name is None:
            return
        self.selected_environment = event.item.name
        self._render_selected_context()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.item.name is not None:
            self.selected_environment = event.item.name
        self.action_verify_context()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        actions = {
            "initialize": self.action_initialize,
            "doctor": self.action_doctor,
            "bind": self.action_bind_context,
            "verify": self.action_verify_context,
            "launch": self.action_launch,
            "shell": self.action_open_shell,
            "reload": self.action_reload,
            "help": self.action_show_help,
            "quit": self.action_quit,
        }
        action = actions.get(event.button.id or "")
        if action is not None:
            action()

    def action_reload(self) -> None:
        self.tools = detect_tools(self.base_environment)
        self.reload_dashboard()
        self.notify(self._text("notification_reloaded"), severity="information")

    def action_initialize(self) -> None:
        if self.snapshot is not None or self.load_error is not None:
            return
        try:
            screen = InitializationScreen(
                start_dir=self.start_dir,
                bindings_path=self.bindings_path,
                base_environment=self.base_environment,
                translations=self.lang,
            )
        except ProjectInitializationError as exc:
            self.notify(
                str(exc),
                severity="error",
                title=self._text("notification_init_failed"),
            )
            return
        self.push_screen(screen, self._initialization_result)

    def _initialization_result(self, outcome: InitScreenOutcome | None) -> None:
        if outcome is None:
            self.notify(
                self._text("notification_init_cancelled"),
                severity="warning",
            )
            return
        self.reload_dashboard()
        if outcome.warning is not None:
            self.notify(
                outcome.warning,
                severity="error",
                title=self._text("notification_init_failed"),
            )
            return
        self.notify(self._text("notification_initialized"), severity="information")

    def action_bind_context(self) -> None:
        item = self._selected_item()
        if item is None:
            return
        try:
            with self.suspend():
                bind_environment(
                    item.name,
                    start_dir=self.start_dir,
                    bindings_path=self.bindings_path,
                )
        except (BindCommandCancelled, KeyboardInterrupt):
            self.notify(self._text("notification_bind_cancelled"), severity="warning")
            return
        except BindCommandError as exc:
            self.notify(
                str(exc),
                severity="error",
                title=self._text("notification_bind_failed"),
            )
            return
        self.reload_dashboard()
        self.notify(
            self._text("notification_bound", environment=item.name),
            severity="information",
        )

    def action_doctor(self) -> None:
        report = diagnose(
            start_dir=self.start_dir,
            bindings_path=self.bindings_path,
        )
        self.push_screen(
            InformationScreen(
                self._text("doctor_title"),
                render_doctor_report_rich(
                    report,
                    styles=_TUI_DOCTOR_STYLES,
                    framed=False,
                ),
                close_label=self._text("action_close"),
            )
        )

    def action_show_help(self) -> None:
        help_text = Text.from_markup(self._text("help_text"))
        self.push_screen(
            InformationScreen(
                self._text("help_title"),
                help_text,
                close_label=self._text("action_close"),
            )
        )

    def action_verify_context(self) -> None:
        item = self._selected_item()
        if item is None or item.status is not ContextStatus.READY:
            return
        self._verify_and_maybe_launch(item, None)

    def action_launch(self) -> None:
        item = self._selected_item()
        if item is None or item.status is not ContextStatus.READY:
            return
        self.push_screen(
            LaunchScreen(
                item.name,
                self.tools,
                protected=item.protected,
                translations=self.lang,
            ),
            self._launch_result,
        )

    def _launch_result(self, command: str | None) -> None:
        if command is None:
            return
        try:
            argv = parse_launch_command(command)
        except LaunchCommandError as exc:
            self.notify(
                str(exc),
                severity="error",
                title=self._text("notification_invalid_command"),
            )
            return
        item = self._selected_item()
        if item is not None:
            self._verify_and_maybe_launch(item, argv)

    def action_open_shell(self) -> None:
        item = self._selected_item()
        if item is None or item.status is not ContextStatus.READY:
            return
        self._verify_and_maybe_launch(item, ())

    def _verify_and_maybe_launch(
        self,
        item: ContextItem,
        command: tuple[str, ...] | None,
    ) -> None:
        self.statuses[item.name] = ContextStatus.VERIFYING
        self.errors.pop(item.name, None)
        self._refresh_context_list()
        self._render_selected_context()
        exit_code: int | None = None
        runtime: VerifiedRuntime | None = None
        try:
            with self.suspend():
                status = self._text("authenticating")
                CliConsole(sys.stderr).print(
                    render_status_rich(status),
                    plain=status,
                    flush=True,
                )
                runtime = prepare_context_runtime(
                    item.name,
                    base_environment=self.base_environment,
                    start_dir=self.start_dir,
                    bindings_path=self.bindings_path,
                    login_output=sys.stderr,
                )
                if command is not None:
                    argv = (
                        (select_interactive_shell(runtime.environment),)
                        if not command
                        else command
                    )
                    command_text = shlex.join(argv)
                    CliConsole(sys.stderr).print(
                        render_launch_context_rich(runtime.verified, command_text),
                        plain=render_launch_context(
                            runtime.verified,
                            f"Launching: {command_text}",
                        ),
                        flush=True,
                    )
                    exit_code = run_command(argv, environment=runtime.environment)
        except AccountMismatchError as exc:
            self.statuses[item.name] = ContextStatus.MISMATCH
            self.actual_accounts[item.name] = exc.actual_account
            self.errors[item.name] = str(exc)
            self.notify(self._text("notification_mismatch"), severity="error")
        except (ContextResolutionError, ContextVerificationError) as exc:
            self.statuses[item.name] = ContextStatus.ERROR
            self.errors[item.name] = str(exc)
            self.notify(
                str(exc),
                severity="error",
                title=self._text("notification_verification_failed"),
            )
        except CommandLaunchError as exc:
            if runtime is not None:
                self._record_verified(item.name, runtime.verified)
            self.notify(
                str(exc),
                severity="error",
                title=self._text("notification_launch_failed"),
            )
        except KeyboardInterrupt:
            self.statuses[item.name] = item.status
            self.notify(self._text("notification_cancelled"), severity="warning")
        else:
            if runtime is not None:
                self._record_verified(item.name, runtime.verified)
            if exit_code is None:
                self.notify(self._text("notification_verified"), severity="information")
            elif exit_code == 0:
                self.notify(
                    self._text("notification_child_completed"),
                    severity="information",
                )
            else:
                self.notify(
                    self._text("notification_child_exit", code=exit_code),
                    severity="warning",
                )
        finally:
            self._refresh_context_list()
            self._render_selected_context()

    def _record_verified(self, environment: str, verified: VerifiedContext) -> None:
        self.statuses[environment] = ContextStatus.VERIFIED
        self.verified[environment] = verified
        self.verified_at[environment] = datetime.now().astimezone()
        self.actual_accounts.pop(environment, None)
        self.errors.pop(environment, None)


def run_tui(
    *,
    lang: str = "en",
    log_level: str = "INFO",
) -> None:
    """Create and run the project Context Dashboard."""
    AWSUIApp(lang=lang, log_level=log_level).run()
