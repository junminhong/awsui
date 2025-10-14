"""Main Textual application and entry point."""

import os
import subprocess
from argparse import ArgumentParser
from threading import Event
from typing import List
from time import time

from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import (
    Header,
    Footer,
    Input,
    ListView,
    ListItem,
    Static,
    RichLog,
)
from textual.containers import Container, Vertical, Horizontal, VerticalScroll
from textual.binding import Binding
from textual.reactive import reactive
from textual.worker import Worker
from textual.timer import Timer
from textual import events, work
from rich.console import Group
from rich.table import Table

from .config import parse_profiles
from .models import Profile
from .aws_cli import check_aws_cli_available, ensure_authenticated, sso_login
from .logging import get_logger
from .autocomplete import CommandAutocomplete
from .q_assistant import (
    check_q_cli_available,
    stream_q_cli_query,
    clean_ansi_codes,
    format_aws_context,
)
from .cheatsheet import AWS_CLI_CHEATSHEET, AWS_CLI_COMMANDS, COMMAND_CATEGORIES
from .i18n import LANG_ZH_TW, LANG_EN


def parse_args():
    """Parse command-line arguments."""
    parser = ArgumentParser(prog="awsui", description="AWS Profile/SSO switcher TUI")

    parser.add_argument("--profile", help="Pre-select profile by name")
    parser.add_argument("--region", help="Override AWS region")
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

    return parser.parse_args()


class CheatsheetScreen(Screen):
    """Modal screen for displaying AWS CLI cheatsheet."""

    CSS = """
    CheatsheetScreen {
        layout: vertical;
        background: rgba(0, 0, 0, 0.75);
        align: center middle;
    }

    #cheatsheet-container {
        width: 90%;
        max-width: 160;
        height: 90%;
        background: $surface;
        border: thick $primary;
        padding: 2;
        layout: vertical;
        align-horizontal: left;
        align-vertical: top;
    }

    #cheatsheet-title {
        text-align: center;
    }

    #cheatsheet-content {
        height: 1fr;
        width: 100%;
    }

    #cheatsheet-body {
        width: 100%;
    }
    """

    BINDINGS = [
        ("escape", "close", "Close"),
        ("q", "close", "Close"),
    ]

    def compose(self) -> ComposeResult:
        """Compose the cheatsheet modal."""
        with Container(id="cheatsheet-container"):
            title = self.app.lang["cheatsheet_title"]
            dismiss = self.app.lang["cheatsheet_dismiss"]
            yield Static(
                f"[bold cyan]{title}[/bold cyan]\n[dim]{dismiss}[/dim]",
                id="cheatsheet-title",
            )
            with VerticalScroll(id="cheatsheet-content"):
                content = ""
                for category, commands in AWS_CLI_CHEATSHEET.items():
                    content += f"\n[bold yellow]{category}:[/bold yellow]\n"
                    for cmd in commands:
                        content += f"  [green]{cmd}[/green]\n"
                yield Static(content, id="cheatsheet-body")

    def action_close(self) -> None:
        """Close the cheatsheet and return to main screen."""
        self.app.pop_screen()


class RegionInputScreen(Screen):
    """Modal screen for region override input."""

    CSS = """
    RegionInputScreen {
        layout: vertical;
        background: rgba(0, 0, 0, 0.75);
        align: center middle;
    }

    #region-container {
        width: 60;
        height: auto;
        background: $surface;
        border: thick $primary;
        padding: 2;
        layout: vertical;
    }

    #region-title {
        text-align: center;
        margin-bottom: 1;
    }

    #region-hint {
        color: $text-muted;
        text-align: center;
        margin-bottom: 1;
    }

    #region-input {
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
    ]

    def compose(self) -> ComposeResult:
        """Compose the region input modal."""
        with Container(id="region-container"):
            yield Static(
                f"[bold cyan]{self.app.lang['region_input_title']}[/bold cyan]",
                id="region-title",
            )
            yield Static(
                f"[dim]{self.app.lang['region_input_hint']}[/dim]",
                id="region-hint",
            )
            yield Input(
                placeholder=self.app.lang["region_input_placeholder"],
                id="region-input",
            )

    def on_mount(self) -> None:
        """Focus input when screen is mounted."""
        self.query_one("#region-input", Input).focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle input submission."""
        region = event.value.strip()
        self.dismiss(region if region else None)

    def action_cancel(self) -> None:
        """Cancel and close the dialog."""
        self.dismiss(None)


class ProfileList(ListView):
    """Custom ListView for profiles with filtering."""

    def __init__(self, profiles: List[Profile], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.all_profiles = profiles
        self.filtered_profiles = profiles.copy()

    def filter_profiles(self, query: str):
        """Filter profiles by search query."""
        if not query:
            self.filtered_profiles = self.all_profiles.copy()
        else:
            query_lower = query.lower()
            self.filtered_profiles = [
                p
                for p in self.all_profiles
                if query_lower in p["name"].lower()
                or (p["account"] and query_lower in p["account"])
                or (p["role"] and query_lower in p["role"].lower())
                or (p["region"] and query_lower in p["region"].lower())
            ]

        self.refresh_items()

    def refresh_items(self):
        """Refresh list items based on filtered profiles."""
        self.clear()
        for profile in self.filtered_profiles:
            title = f"[b]{profile['name']}[/b]"
            meta_parts: list[str] = []

            kind = profile.get("kind")
            if kind:
                meta_parts.append(kind.upper())
            account = profile.get("account")
            if account:
                meta_parts.append(str(account))
            role = profile.get("role")
            if role:
                meta_parts.append(role)
            region = profile.get("region")
            if region:
                meta_parts.append(region)

            body_text = title
            if meta_parts:
                meta_line = " | ".join(meta_parts)
                body_text += f"\n[dim]{meta_line}[/dim]"

            item_body = Static(body_text, markup=True, expand=True)
            item = ListItem(item_body, name=profile["name"])
            item.add_class("profile-list-item")
            self.append(item)


class AWSUIApp(App):
    MOUSE = False
    TITLE = "AWSUI"
    """Textual TUI application for AWS profile switching."""

    CSS = """
    Screen {
        layout: vertical;
        background: #0f172a;
        color: #e2e8f0;
    }

    Header {
        background: #0b1628;
        color: #f8fafc;
        text-style: bold;
    }

    Footer {
        background: #0b1628;
        color: #94a3b8;
    }

    #content {
        layout: horizontal;
        height: 1fr;
        padding: 0;
    }

    #left-pane {
        width: 30%;
        min-width: 25;
        max-width: 45;
        padding: 1 2 1 2;
        background: #0b1420;
        border-right: solid #1e293b;
    }

    #right-pane {
        layout: vertical;
        width: 1fr;
        padding: 0 1 0 1;
        background: #0f172a;
    }

    .section-title {
        text-style: bold;
        color: #38bdf8;
        background: #0d1926;
        padding: 0 1;
        margin-bottom: 1;
    }

    .section-spacing {
        margin-top: 1;
    }

    .section-hint {
        color: #64748b;
        text-style: italic;
        padding: 0 1;
        margin-bottom: 1;
    }

    #search {
        height: 3;
        margin-bottom: 1;
        border: tall $primary-darken-2;
        background: #0d1a2a;
    }

    #search:focus {
        border: tall $primary;
        background: #102339;
    }

    #profile-list {
        height: 1fr;
        width: 1fr;
        overflow-y: auto;
        border: solid #1e293b;
        background: #0a1018;
    }

    #profile-list > .list-item {
        margin: 0 1 1 1;
        padding: 1;
        border: solid transparent;
        background: transparent;
    }

    #profile-list > .list-item:last-child {
        margin-bottom: 0;
    }

    #profile-list > .list-item--highlight {
        border: solid $primary;
        background: $primary 20%;
    }

    #detail-pane {
        margin-top: 1;
        padding: 0;
        width: 1fr;
        min-height: 8;
        max-height: 14;
        overflow-y: auto;
        overflow-x: auto;
        scrollbar-size: 1 1;
        border: solid #1f2d44;
        background: #15263f;
    }

    #detail-content {
        padding: 1;
        color: #e2e8f0;
        text-align: left;
    }

    #ai-status {
        height: auto;
        margin: 0 0 0 0;
    }

    /* Output area (shared by CLI and AI) */
    #output-area {
        height: 1fr;
        padding: 0 1;
        margin-bottom: 1;
        background: #0a1018;
        border: solid #1e293b;
    }

    /* Input container */
    #input-container {
        layout: vertical;
        height: auto;
    }

    #autocomplete {
        display: none;
        max-height: 10;
        padding: 0;
        margin-bottom: 1;
        background: #0f1f33;
        border: solid $warning-darken-1;
    }

    #autocomplete > .list-item {
        padding: 0 1;
    }

    #autocomplete > .list-item--highlight {
        background: $warning 30%;
    }

    #shared-input {
        height: 3;
        border: tall $primary-darken-2;
        background: #0d1a2a;
    }

    #shared-input:focus {
        border: tall $primary;
        background: #102339;
    }

    .input-cli-mode {
        border: tall $success-darken-2;
    }

    .input-cli-mode:focus {
        border: tall $success;
    }

    .input-ai-mode {
        border: tall $warning-darken-2;
    }

    .input-ai-mode:focus {
        border: tall $warning;
    }

    Toast {
        width: 26;
        min-width: 20;
        padding: 0 1;
    }

    Toast .toast--title {
        text-style: bold;
    }

    .empty-state {
        width: 100%;
        content-align: center middle;
        text-align: center;
        color: #64748b;
        padding: 2;
    }

    .status-indicator {
        color: #38bdf8;
        padding: 0 1;
    }
    """

    BINDINGS = [
        Binding("/", "focus_search", "Search", show=True),
        Binding("c", "focus_cli", "CLI", show=True),
        Binding("a", "toggle_ai_panel", "AI", show=True),
        Binding("t", "toggle_left_pane", "Toggle", show=True),
        Binding("h", "show_cheatsheet", "Cheat", show=True),
        Binding("enter", "apply_profile", "Apply", show=True),
        Binding("l", "force_login", "Login", show=True),
        Binding("ctrl+c", "cancel_login", "Cancel", show=True),
        Binding("w", "whoami", "WhoAmI", show=True),
        Binding("r", "region_override", "Region", show=True),
        Binding("ctrl+l", "clear_cli", "Clear", show=False),
        Binding("escape", "blur_input", "Esc", show=True),
        Binding("?", "show_help", "Help", show=True),
        Binding("q", "quit", "Quit", show=True),
    ]

    show_left_pane: reactive[bool] = reactive(True)
    active_tab: reactive[str] = reactive("cli")

    def __init__(
        self,
        lang: str = "en",
        profile: str | None = None,
        region: str | None = None,
        log_level: str = "INFO",
        **kwargs,
    ):
        super().__init__(**kwargs)
        self.lang = LANG_ZH_TW if lang == "zh-TW" else LANG_EN
        self.sub_title = self.lang["app_subtitle"]
        self.preselect_profile = profile
        self.override_region = region
        self.logger = get_logger(log_level)
        self.profiles: List[Profile] = []
        self.selected_profile: Profile | None = None

        self.q_available: bool = False

        self.ai_spinner_frames: list[str] = ["⏳", "⌛", "🔄"]
        self.ai_spinner_index: int = 0
        self.ai_spinner_message: str = ""
        self.ai_spinner_timer: Timer | None = None
        self.ai_status_clear_timer: Timer | None = None

        self.command_history: List[str] = []
        self.history_index: int = -1
        self.current_input: str = ""
        self.browsing_history: bool = False
        self._autocomplete_handled_enter: bool = False

        self.auth_worker: Worker | None = None
        self.auth_worker_active: bool = False
        self.auth_cancel_event: Event | None = None
        self.authenticating_profile: Profile | None = None
        self.authenticating_fetch_identity: bool = False

    def compose(self) -> ComposeResult:
        """Compose the application layout."""
        yield Header(show_clock=True)

        with Horizontal(id="content"):
            with Vertical(id="left-pane"):
                yield Static(self.lang["panel_profiles"], classes="section-title")

                yield Input(placeholder=self.lang["search_placeholder"], id="search")

                yield ProfileList(self.profiles, id="profile-list")

                yield Static(
                    self.lang["panel_detail"],
                    classes="section-title section-spacing",
                )
                detail_placeholder = Static(
                    self.lang["detail_placeholder"],
                    id="detail-content",
                )
                detail_placeholder.add_class("empty-state")
                with VerticalScroll(id="detail-pane"):
                    yield detail_placeholder

            with Vertical(id="right-pane"):
                yield RichLog(id="output-area", highlight=True, markup=True)

                with Vertical(id="input-container"):
                    yield CommandAutocomplete(
                        AWS_CLI_COMMANDS, COMMAND_CATEGORIES, id="autocomplete"
                    )

                    ai_status = Static("", id="ai-status", classes="status-indicator")
                    ai_status.display = False
                    yield ai_status

                    yield Input(
                        placeholder=self.lang["cli_placeholder"],
                        id="shared-input",
                        classes="input-cli-mode",
                    )

        yield Footer()

    def on_mount(self):
        """Initialize app after mounting."""
        start_time = time()

        self.q_available = check_q_cli_available()
        self.logger.info("q_cli_check", available=self.q_available)

        self.active_tab = "cli"

        if not check_aws_cli_available():
            self.update_status(self.lang["no_aws_cli"], error=True)
            self.show_empty_state(self.lang["no_aws_cli"], self.lang["no_aws_cli_hint"])
            return

        self.profiles = parse_profiles()
        self.logger.info("profiles_loaded", count=len(self.profiles))

        if not self.profiles:
            self.update_status(self.lang["no_profiles"], error=True)
            self.show_empty_state(
                self.lang["no_profiles"], self.lang["no_profiles_hint"]
            )
            return

        profile_list = self.query_one("#profile-list", ProfileList)
        profile_list.all_profiles = self.profiles
        profile_list.filtered_profiles = self.profiles.copy()
        profile_list.refresh_items()

        if self.preselect_profile:
            for i, p in enumerate(self.profiles):
                if p["name"] == self.preselect_profile:
                    profile_list.index = i
                    self.selected_profile = p
                    self.update_detail_pane(p)
                    break

        duration_ms = int((time() - start_time) * 1000)
        self.logger.info("app_started", duration_ms=duration_ms)
        self.update_status(
            self.lang["profiles_loaded"].format(count=len(self.profiles))
        )

    def show_empty_state(self, title: str, hint: str):
        """Show empty state message."""
        detail_content = self.query_one("#detail-content", Static)
        detail_content.update(f"[bold]{title}[/bold]\n\n{hint}")
        detail_content.add_class("empty-state")

    def update_status(self, message: str, error: bool = False):
        """Display status notification."""
        if error:
            self.notify(
                message, severity="error", title=self.lang.get("error_title", "Error")
            )
        else:
            self.notify(message, severity="information")

    def _start_ai_spinner(self, message: str) -> None:
        """Begin animated status indicator for Amazon Q queries."""
        if self.ai_spinner_timer:
            self.ai_spinner_timer.stop()
            self.ai_spinner_timer = None
        if self.ai_status_clear_timer:
            self.ai_status_clear_timer.stop()
            self.ai_status_clear_timer = None

        self.ai_spinner_message = message
        self.ai_spinner_index = 0

        ai_status = self.query_one("#ai-status", Static)
        ai_status.display = True
        frame = self.ai_spinner_frames[self.ai_spinner_index]
        ai_status.update(f"[dim]{frame} {message}[/dim]")

        def tick() -> None:
            self.ai_spinner_index = (self.ai_spinner_index + 1) % len(
                self.ai_spinner_frames
            )
            current = self.ai_spinner_frames[self.ai_spinner_index]
            ai_status.update(f"[dim]{current} {self.ai_spinner_message}[/dim]")

        self.ai_spinner_timer = self.set_interval(0.45, tick)

    def _clear_ai_status(self) -> None:
        """Clear the Amazon Q status indicator."""
        ai_status = self.query_one("#ai-status", Static)
        ai_status.update("")
        ai_status.display = False

    def _stop_ai_spinner(self, message: str | None, success: bool = True) -> None:
        """Stop spinner and optionally show final message."""
        if self.ai_spinner_timer:
            self.ai_spinner_timer.stop()
            self.ai_spinner_timer = None

        if self.ai_status_clear_timer:
            self.ai_status_clear_timer.stop()
            self.ai_status_clear_timer = None

        if message:
            icon = "✅" if success else "⚠️"
            ai_status = self.query_one("#ai-status", Static)
            ai_status.display = True
            ai_status.update(f"{icon} {message}")
            self.ai_status_clear_timer = self.set_timer(3.0, self._clear_ai_status)
        else:
            self._clear_ai_status()

    def build_profile_detail(self, profile: Profile) -> Table:
        """Create a Rich table summarizing profile information."""
        table = Table.grid(padding=(0, 1))
        table.expand = True
        table.pad_edge = False
        table.add_column(justify="left", style="bold cyan", no_wrap=True)
        table.add_column(justify="left", no_wrap=True)

        def fmt(value: str | None, transform=None) -> str:
            if value is None or value == "":
                return "-"
            if transform:
                return transform(value)
            return str(value)

        table.add_row(self.lang["detail_name"], fmt(profile.get("name")))
        table.add_row(
            self.lang["detail_kind"],
            fmt(profile.get("kind"), lambda value: str(value).upper()),
        )
        table.add_row(self.lang["detail_account"], fmt(profile.get("account")))
        table.add_row(self.lang["detail_role"], fmt(profile.get("role")))

        # Show region with override indicator if applicable
        if self.override_region:
            region_label = self.lang["detail_region_override"]
            region_value = self.override_region
        else:
            region_label = self.lang["detail_region"]
            region_value = fmt(profile.get("region"))
        table.add_row(region_label, region_value)

        table.add_row(self.lang["detail_session"], fmt(profile.get("session")))

        return table

    def build_identity_detail(self, identity: dict) -> Table:
        """Create a Rich table summarizing identity details."""
        table = Table.grid(padding=(0, 1))
        table.expand = True
        table.pad_edge = False
        table.add_column(justify="left", style="bold yellow", no_wrap=True)
        table.add_column(justify="left", no_wrap=True)

        table.add_row(f"[b]{self.lang['whoami']}[/b]", "")
        table.add_row(self.lang["whoami_account"], identity.get("Account") or "-")
        table.add_row(self.lang["whoami_arn"], identity.get("Arn") or "-")
        table.add_row(self.lang["whoami_user"], identity.get("UserId") or "-")

        return table

    def update_detail_pane(self, profile: Profile):
        """Update detail pane with profile information."""
        detail_content = self.query_one("#detail-content", Static)
        detail_content.remove_class("empty-state")
        detail_content.update(self.build_profile_detail(profile))

    def on_key(self, event: events.Key) -> None:
        """Handle global key events when Input has focus."""
        focused = self.focused
        if not isinstance(focused, Input):
            return

        if focused.id == "shared-input":
            autocomplete = self.query_one("#autocomplete", CommandAutocomplete)

            if event.key == "ctrl+u":
                focused.value = ""
                self.browsing_history = False
                self.history_index = -1
                autocomplete.display = False
                autocomplete.clear_options()
                event.prevent_default()
                event.stop()
                return

            # Case 1: Browsing history → ↑↓ continues history navigation
            if self.browsing_history:
                if event.key == "up":
                    self.navigate_history_up(focused)
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "down":
                    self.navigate_history_down(focused)
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key not in ["up", "down"]:
                    self.browsing_history = False

            # Case 2: Input is empty → ↑↓ starts history navigation
            input_is_empty = not focused.value.strip()
            if input_is_empty:
                if event.key == "up":
                    self.navigate_history_up(focused)
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "down":
                    self.navigate_history_down(focused)
                    event.prevent_default()
                    event.stop()
                    return

            # Case 3: Input has content + autocomplete visible → ↑↓ for autocomplete, Tab/Enter to select
            elif autocomplete.display:
                if event.key == "up":
                    autocomplete.move_cursor_up()
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "down":
                    autocomplete.move_cursor_down()
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "tab":
                    selected = autocomplete.get_selected_command()
                    if selected:
                        current_value = focused.value
                        cursor_pos = focused.cursor_position

                        new_value, new_cursor_pos = autocomplete.smart_insert_selection(
                            current_value, cursor_pos, selected
                        )

                        focused.value = new_value
                        focused.cursor_position = new_cursor_pos
                        autocomplete.display = False
                        autocomplete.clear_options()
                        event.prevent_default()
                        event.stop()
                        return
                elif event.key == "enter":
                    selected = autocomplete.get_selected_command()
                    if selected:
                        current_value = focused.value
                        cursor_pos = focused.cursor_position

                        new_value, new_cursor_pos = autocomplete.smart_insert_selection(
                            current_value, cursor_pos, selected
                        )

                        focused.value = new_value
                        focused.cursor_position = new_cursor_pos
                        autocomplete.display = False
                        autocomplete.clear_options()
                        self._autocomplete_handled_enter = True
                        event.prevent_default()
                        event.stop()
                        return
                elif event.key == "escape":
                    autocomplete.display = False
                    autocomplete.clear_options()
                    event.prevent_default()
                    event.stop()
                    return

            # Case 4: Input has content but no autocomplete → ↑↓ for history navigation
            else:
                if event.key == "up":
                    self.navigate_history_up(focused)
                    event.prevent_default()
                    event.stop()
                    return
                elif event.key == "down":
                    self.navigate_history_down(focused)
                    event.prevent_default()
                    event.stop()
                    return

        if event.key == "escape":
            profile_list = self.query_one("#profile-list", ProfileList)
            profile_list.focus()
            event.prevent_default()
            event.stop()
            return

        if event.key == "q":
            self.action_quit()
            event.prevent_default()
            event.stop()
            return

        if event.key == "question_mark":
            self.action_show_help()
            event.prevent_default()
            event.stop()
            return

        if event.key == "ctrl+l":
            self.action_clear_cli()
            event.prevent_default()
            event.stop()
            return

    def on_input_changed(self, event: Input.Changed):
        """Handle search input changes and CLI autocomplete."""
        if event.input.id == "search":
            profile_list = self.query_one("#profile-list", ProfileList)
            profile_list.filter_profiles(event.value)
        elif event.input.id == "shared-input":
            autocomplete = self.query_one("#autocomplete", CommandAutocomplete)

            if self.browsing_history:
                if self.history_index != -1 and self.history_index < len(
                    self.command_history
                ):
                    expected_value = self.command_history[self.history_index]
                    if event.value != expected_value:
                        self.browsing_history = False
                        self.history_index = -1
                        self.current_input = ""
                        cursor_pos = event.input.cursor_position
                        autocomplete.filter_commands(event.value, cursor_pos)
                return

            if self.active_tab == "cli":
                cursor_pos = event.input.cursor_position
                autocomplete.filter_commands(event.value, cursor_pos)
            else:
                autocomplete.display = False

    def on_input_submitted(self, event: Input.Submitted):
        """Handle Enter key in search box and CLI input."""
        if event.input.id == "search":
            profile_list = self.query_one("#profile-list", ProfileList)

            # Check if there are filtered results
            if profile_list.filtered_profiles:
                # If only one result, apply it directly
                if len(profile_list.filtered_profiles) == 1:
                    profile_list.index = 0
                    self.selected_profile = profile_list.filtered_profiles[0]
                    self.update_detail_pane(self.selected_profile)
                    # Directly apply the single result
                    self.action_apply_profile()
                else:
                    # Multiple results: select first and move focus to list
                    profile_list.index = 0
                    self.selected_profile = profile_list.filtered_profiles[0]
                    self.update_detail_pane(self.selected_profile)
                    profile_list.focus()
                    self.notify(
                        self.lang["search_first_result"].format(
                            count=len(profile_list.filtered_profiles)
                        )
                    )
            else:
                self.notify(self.lang["search_no_results"], severity="warning")

        elif event.input.id == "shared-input":
            # Check if autocomplete just handled this Enter key
            # (the flag is set in on_key before this event fires)
            if self._autocomplete_handled_enter:
                self._autocomplete_handled_enter = False
                return

            value = event.value.strip()
            if value:
                if self.active_tab == "cli":
                    self.execute_aws_command(value)
                elif self.active_tab == "ai":
                    self.execute_q_query(value)
                event.input.value = ""

    def on_list_view_selected(self, event: ListView.Selected):
        """Handle profile selection."""
        profile_list = self.query_one("#profile-list", ProfileList)
        selected_index = profile_list.index

        if 0 <= selected_index < len(profile_list.filtered_profiles):
            self.selected_profile = profile_list.filtered_profiles[selected_index]
            self.update_detail_pane(self.selected_profile)

    def action_focus_search(self):
        """Focus on search input."""
        search_input = self.query_one("#search", Input)
        search_input.focus()

    def action_blur_input(self):
        """Leave current Input and return to profile list."""
        profile_list = self.query_one("#profile-list", ProfileList)
        profile_list.focus()

    def action_toggle_left_pane(self):
        """Toggle visibility of left pane (profile list)."""
        self.show_left_pane = not self.show_left_pane

    def watch_show_left_pane(self, show: bool) -> None:
        """React to changes in left pane visibility."""
        try:
            left_pane = self.query_one("#left-pane", Vertical)
            left_pane.display = show

            if show:
                self.screen.remove_class("fullscreen")
                self.notify(self.lang["left_pane_shown"])
            else:
                self.screen.add_class("fullscreen")
                self.notify(self.lang["cli_fullscreen"])
        except Exception:
            pass

    def action_toggle_ai_panel(self):
        """Switch to AI tab."""
        if not self.q_available:
            self.update_status(self.lang["ai_not_available"], error=True)
            return
        self.active_tab = "ai"
        # Always focus input, even if already in AI mode
        try:
            shared_input = self.query_one("#shared-input", Input)
            shared_input.focus()
        except Exception:
            pass

    def action_focus_cli(self):
        """Switch to CLI tab and focus input."""
        self.active_tab = "cli"
        # Always focus input, even if already in CLI mode
        try:
            shared_input = self.query_one("#shared-input", Input)
            shared_input.focus()
        except Exception:
            pass

    def watch_active_tab(self, tab: str) -> None:
        """React to mode changes (CLI or AI)."""
        try:
            shared_input = self.query_one("#shared-input", Input)
            autocomplete = self.query_one("#autocomplete", CommandAutocomplete)

            if tab == "cli":
                shared_input.set_classes("input-cli-mode")
                shared_input.placeholder = self.lang["cli_placeholder"]
                autocomplete.display = False

                self.notify(self.lang["cli_mode"])
                shared_input.focus()

            elif tab == "ai":
                shared_input.set_classes("input-ai-mode")
                shared_input.placeholder = self.lang["ai_placeholder"]
                autocomplete.display = False
                autocomplete.clear_options()

                if not self.q_available:
                    output_area = self.query_one("#output-area", RichLog)
                    output_area.write(
                        f"\n[bold yellow]{self.lang['ai_not_available']}[/bold yellow]"
                    )
                    output_area.write(f"[dim]{self.lang['ai_install_hint']}[/dim]")
                    output_area.write(
                        "[cyan]https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/command-line-installing.html[/cyan]\n"
                    )

                self.notify(self.lang["ai_mode"])
                shared_input.focus()

        except Exception:
            pass

    def action_apply_profile(self):
        """Apply the selected profile."""
        if not self.selected_profile:
            self.update_status(self.lang["select_profile_first"], error=True)
            return

        profile = self.selected_profile
        self.update_status(self.lang["authenticating"])
        self._start_login(profile, fetch_identity=True)

    def _start_login(self, profile: Profile, fetch_identity: bool) -> None:
        """Kick off background SSO login/authentication."""
        if self.auth_worker_active:
            self.update_status(self.lang["login_in_progress"])
            return

        cancel_event = Event()
        profile_snapshot = profile.copy()

        self.auth_worker_active = True
        self.auth_cancel_event = cancel_event
        self.authenticating_profile = profile_snapshot
        self.authenticating_fetch_identity = fetch_identity
        self.auth_worker = self.perform_login(
            profile_snapshot, fetch_identity, cancel_event
        )

    @work(exclusive=True, thread=True)
    def perform_login(
        self, profile: Profile, fetch_identity: bool, cancel_event: Event
    ):
        """Run authentication or login logic in a worker thread."""
        profile_name = profile["name"]
        start_time = time()
        identity = None
        success = False

        if fetch_identity:
            identity = ensure_authenticated(
                profile_name, cancel_check=cancel_event.is_set
            )
            success = identity is not None
        else:
            success = sso_login(profile_name, cancel_check=cancel_event.is_set)

        duration_ms = int((time() - start_time) * 1000)
        cancelled = cancel_event.is_set()

        self.call_from_thread(
            self._finish_login,
            profile,
            identity,
            success,
            duration_ms,
            cancelled,
            fetch_identity,
        )

    def _finish_login(
        self,
        profile: Profile,
        identity: dict | None,
        success: bool,
        duration_ms: int,
        cancelled: bool,
        fetch_identity: bool,
    ) -> None:
        """Handle completion of background login/authentication."""
        profile_name = profile["name"]

        self.auth_worker = None
        self.auth_worker_active = False
        self.auth_cancel_event = None
        self.authenticating_profile = None
        self.authenticating_fetch_identity = False

        if cancelled:
            if fetch_identity:
                self.logger.info(
                    "authentication_cancelled",
                    profile=profile_name,
                    duration_ms=duration_ms,
                )
                self.update_status(self.lang["auth_cancelled"])
            else:
                self.logger.info(
                    "sso_login_cancelled", profile=profile_name, duration_ms=duration_ms
                )
                self.update_status(self.lang["login_cancelled"])
            return

        if fetch_identity:
            if success and identity:
                self.logger.info(
                    "authentication_success",
                    profile=profile_name,
                    duration_ms=duration_ms,
                    account=identity.get("Account"),
                    arn=identity.get("Arn"),
                )
                self.update_status(self.lang["auth_success"])

                # Update detail pane with profile info
                if (
                    self.selected_profile
                    and self.selected_profile["name"] == profile_name
                ):
                    detail_content = self.query_one("#detail-content", Static)
                    detail_content.remove_class("empty-state")
                    renderables = [self.build_profile_detail(profile)]
                    if identity:
                        renderables.append(self.build_identity_detail(identity))

                    detail_content.update(
                        Group(*renderables) if len(renderables) > 1 else renderables[0]
                    )
            else:
                self.logger.error(
                    "authentication_failed",
                    profile=profile_name,
                    duration_ms=duration_ms,
                )
                self.update_status(self.lang["auth_failed"], error=True)
        else:
            if success:
                self.logger.info(
                    "sso_login_success", profile=profile_name, duration_ms=duration_ms
                )
                self.update_status(self.lang["login_success"])
            else:
                self.logger.error(
                    "sso_login_failed", profile=profile_name, duration_ms=duration_ms
                )
                self.update_status(self.lang["login_failed"], error=True)

    def action_force_login(self):
        """Force SSO login for selected profile."""
        if not self.selected_profile:
            self.update_status(self.lang["select_profile_first"], error=True)
            return

        profile = self.selected_profile
        profile_name = profile["name"]
        self.update_status(self.lang["login_loading"].format(profile=profile_name))
        self._start_login(profile, fetch_identity=False)

    def action_cancel_login(self):
        """Cancel an in-progress SSO login or authentication."""
        if not self.auth_worker_active or not self.auth_cancel_event:
            self.update_status(self.lang["no_login_task"], error=True)
            return

        if not self.auth_cancel_event.is_set():
            self.auth_cancel_event.set()
            if self.authenticating_profile:
                profile_name = self.authenticating_profile.get("name", "")
                event_name = (
                    "authentication_cancel_requested"
                    if self.authenticating_fetch_identity
                    else "sso_login_cancel_requested"
                )
                if profile_name:
                    self.logger.info(event_name, profile=profile_name)
                else:
                    self.logger.info(event_name)
        self.update_status(self.lang["login_cancelling"])

    def action_whoami(self):
        """Trigger whoami identity check."""
        if not self.selected_profile:
            self.update_status(self.lang["select_profile_first"], error=True)
            return

        self.update_status(self.lang["whoami_checking"])
        # Make a copy to avoid thread safety issues
        profile_snapshot = self.selected_profile.copy()
        self.perform_whoami(profile_snapshot)

    @work(exclusive=False, thread=True)
    def perform_whoami(self, profile: Profile):
        """Execute whoami in worker thread."""
        from .aws_cli import get_caller_identity

        profile_name = profile["name"]
        identity = get_caller_identity(profile_name)

        # Update UI from thread
        self.call_from_thread(self._update_whoami_result, profile, identity)

    def _update_whoami_result(self, profile: Profile, identity: dict | None):
        """Update UI with whoami result (called from worker thread)."""
        if identity:
            # Only update if this profile is still selected
            if (
                self.selected_profile
                and self.selected_profile["name"] == profile["name"]
            ):
                detail_content = self.query_one("#detail-content", Static)
                detail_content.remove_class("empty-state")
                detail_content.update(self.build_identity_detail(identity))

                # Ensure profile list stays populated after UI update
                try:
                    profile_list = self.query_one("#profile-list", ProfileList)
                    # Check if list was accidentally cleared but has data
                    if (
                        profile_list.filtered_profiles
                        and len(list(profile_list.children)) == 0
                    ):
                        self.logger.warning(
                            "profile_list_empty_after_whoami",
                            filtered_count=len(profile_list.filtered_profiles),
                        )
                        profile_list.refresh_items()
                except Exception as e:
                    self.logger.error("profile_list_check_failed", error=str(e))

            self.update_status(self.lang["whoami_updated"])
        else:
            self.update_status(self.lang["whoami_failed"], error=True)

    def action_region_override(self):
        """Show region override dialog."""

        def handle_region_result(result: str | None) -> None:
            """Handle the result from region input screen."""
            if result is not None:
                # User entered empty string - clear override
                if result == "":
                    self.override_region = None
                    self.update_status(self.lang["region_override_cleared"])
                else:
                    # Set new override
                    self.override_region = result
                    self.update_status(
                        self.lang["region_override_set"].format(region=result)
                    )

                # Update detail pane if a profile is selected
                if self.selected_profile:
                    detail_content = self.query_one("#detail-content", Static)
                    detail_content.update(
                        self.build_profile_detail(self.selected_profile)
                    )

        self.push_screen(RegionInputScreen(), handle_region_result)

    def action_clear_cli(self):
        """Clear output area."""
        output_area = self.query_one("#output-area", RichLog)
        output_area.clear()
        self.notify(self.lang["output_cleared"])

    def navigate_history_up(self, input_widget: Input) -> None:
        """Navigate up in command history (older commands)."""
        if not self.command_history:
            return

        # First time pressing up: save current input
        if self.history_index == -1:
            self.current_input = input_widget.value
            self.history_index = len(self.command_history)

        # Move up
        if self.history_index > 0:
            self.history_index -= 1
            input_widget.value = self.command_history[self.history_index]
            input_widget.action_end()

            # Enter history browsing mode
            self.browsing_history = True

            # Close autocomplete
            autocomplete = self.query_one("#autocomplete", CommandAutocomplete)
            autocomplete.display = False
            autocomplete.clear_options()

    def navigate_history_down(self, input_widget: Input) -> None:
        """Navigate down in command history (newer commands)."""
        if self.history_index == -1:
            return  # Not in browsing mode

        # Move down
        self.history_index += 1

        if self.history_index >= len(self.command_history):
            # Return to original input
            input_widget.value = self.current_input
            self.history_index = -1
            self.browsing_history = False  # Exit history mode
        else:
            input_widget.value = self.command_history[self.history_index]
            input_widget.action_end()
            self.browsing_history = True  # Still in history mode

        # Close autocomplete
        autocomplete = self.query_one("#autocomplete", CommandAutocomplete)
        autocomplete.display = False
        autocomplete.clear_options()

    @work(exclusive=True, thread=True)
    def execute_aws_command(self, command: str):
        """Execute AWS CLI command and display output in real-time."""
        # Add to command history (avoid duplicates)
        if command and (
            not self.command_history or self.command_history[-1] != command
        ):
            self.command_history.append(command)

        # Reset history browsing state
        self.history_index = -1
        self.current_input = ""
        self.browsing_history = False

        output_area = self.query_one("#output-area", RichLog)

        # Show current profile and command
        profile_name = (
            self.selected_profile["name"]
            if self.selected_profile
            else self.lang["profile_none"]
        )
        self.call_from_thread(
            output_area.write, f"[bold cyan][{profile_name}] $ {command}[/bold cyan]"
        )

        # Setup environment with selected profile
        env = os.environ.copy()
        if self.selected_profile:
            env["AWS_PROFILE"] = self.selected_profile["name"]
            # Use override_region if set, otherwise use profile's region
            region = self.override_region or self.selected_profile.get("region")
            if region:
                env["AWS_DEFAULT_REGION"] = region

        # Execute command with real-time output streaming
        start_time = time()
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
            )

            # Stream stdout in real-time
            if process.stdout:
                for line in iter(process.stdout.readline, ""):
                    if line:
                        self.call_from_thread(output_area.write, line.rstrip())

            # Wait for process to complete
            process.wait()

            # Get any remaining stderr
            if process.stderr:
                stderr_output = process.stderr.read()
                if stderr_output:
                    self.call_from_thread(
                        output_area.write, f"[red]{stderr_output.rstrip()}[/red]"
                    )

            duration_ms = int((time() - start_time) * 1000)

            # Display execution info
            if process.returncode == 0:
                self.call_from_thread(
                    output_area.write,
                    f"[dim]{self.lang['execute_success'].format(duration=duration_ms)}[/dim]\n",
                )
            else:
                self.call_from_thread(
                    output_area.write,
                    f"[red]{self.lang['cli_error_exit'].format(code=process.returncode, duration=duration_ms)}[/red]\n",
                )

            self.logger.info(
                "cli_command_executed",
                command=command,
                profile=profile_name,
                duration_ms=duration_ms,
                exit_code=process.returncode,
            )

        except Exception as e:
            self.call_from_thread(
                output_area.write,
                f"[red]{self.lang['cli_error_exception'].format(error=str(e))}[/red]\n",
            )
            self.logger.error("cli_command_error", command=command, error=str(e))

    @work(exclusive=False, thread=True)
    def execute_q_query(self, query: str):
        """Execute Amazon Q CLI query and display response."""
        output_area = self.query_one("#output-area", RichLog)

        # Show query
        self.call_from_thread(output_area.write, f"[bold cyan]Q: {query}[/bold cyan]")

        # Start animated status indicator
        self.call_from_thread(self._start_ai_spinner, self.lang["ai_spinner_wait"])

        # Prepare context
        context = ""
        if self.selected_profile:
            # Use override_region if set, otherwise use profile's region
            region = self.override_region or self.selected_profile.get("region")
            context = format_aws_context(
                profile_name=self.selected_profile.get("name"),
                region=region,
                account=self.selected_profile.get("account"),
            )

        # Show querying status
        self.call_from_thread(self.update_status, self.lang["ai_querying"])

        # Execute query with AWS profile environment (streaming)
        start_time = time()
        try:
            # Use override_region if set, otherwise use profile's region
            region = self.override_region or (
                self.selected_profile.get("region") if self.selected_profile else None
            )

            # Start streaming process
            process = stream_q_cli_query(
                prompt=query,
                context=context,
                profile_name=self.selected_profile.get("name")
                if self.selected_profile
                else None,
                region=region,
            )

            if not process:
                duration_ms = int((time() - start_time) * 1000)
                self.call_from_thread(
                    self._stop_ai_spinner, self.lang["ai_spinner_error"], False
                )
                self.call_from_thread(
                    output_area.write,
                    "[red]Amazon Q Developer CLI not available or failed to start.[/red]\n",
                )
                self.call_from_thread(
                    self.update_status, self.lang["ai_query_failed"], error=True
                )
                self.logger.error(
                    "q_query_failed", query=query, duration_ms=duration_ms
                )
                return

            # Stream output line by line
            output_lines = []
            success = True

            try:
                for line in process.stdout:
                    if line:
                        clean_line = clean_ansi_codes(line.rstrip("\n"))
                        output_lines.append(clean_line)
                        # Display line immediately
                        self.call_from_thread(
                            output_area.write, f"[green]{clean_line}[/green]\n"
                        )

                # Wait for process to complete
                process.wait()

                # Check return code
                if process.returncode != 0:
                    success = False
                    stderr_output = process.stderr.read() if process.stderr else ""
                    if stderr_output:
                        clean_error = clean_ansi_codes(stderr_output.strip())
                        self.call_from_thread(
                            output_area.write, f"[red]Error: {clean_error}[/red]\n"
                        )

            except Exception as stream_exc:
                success = False
                self.call_from_thread(
                    output_area.write,
                    f"[red]Stream error: {str(stream_exc)}[/red]\n",
                )

        except Exception as exc:  # pragma: no cover - defensive
            duration_ms = int((time() - start_time) * 1000)
            error_text = str(exc) or "Unknown error"
            self.call_from_thread(
                self._stop_ai_spinner, self.lang["ai_spinner_error"], False
            )
            self.call_from_thread(
                output_area.write,
                f"[red]{self.lang['ai_error_exception'].format(error=error_text, duration=duration_ms)}[/red]\n",
            )
            self.call_from_thread(
                self.update_status, self.lang["ai_query_failed"], error=True
            )
            self.logger.exception(
                "q_query_exception", query=query, duration_ms=duration_ms
            )
            return

        duration_ms = int((time() - start_time) * 1000)

        # Update UI after completion
        if success:
            self.call_from_thread(
                self._stop_ai_spinner, self.lang["ai_spinner_done"], True
            )
            self.call_from_thread(
                output_area.write,
                f"[dim]{self.lang['execute_success'].format(duration=duration_ms)}[/dim]\n",
            )
            self.logger.info("q_query_success", query=query, duration_ms=duration_ms)
        else:
            self.call_from_thread(
                self._stop_ai_spinner, self.lang["ai_spinner_error"], False
            )
            self.call_from_thread(
                output_area.write,
                f"[dim]{self.lang['execute_failure'].format(duration=duration_ms)}[/dim]\n",
            )
            self.call_from_thread(
                self.update_status, self.lang["ai_query_failed"], error=True
            )
            response_text = "\n".join(output_lines) if output_lines else "Unknown error"
            self.logger.error(
                "q_query_failed",
                query=query,
                duration_ms=duration_ms,
                error=response_text,
            )

    def action_show_cheatsheet(self):
        """Show AWS CLI cheatsheet in modal screen."""
        self.push_screen(CheatsheetScreen())

    def action_show_help(self):
        """Show help overlay."""
        detail_content = self.query_one("#detail-content", Static)
        detail_content.remove_class("empty-state")
        detail_content.update(self.lang["help_text"])
        self.notify(self.lang["help_displayed"])


def main():
    """Entry point for awsui CLI."""
    args = parse_args()

    # Create and run app
    app = AWSUIApp(
        lang=args.lang,
        profile=args.profile,
        region=args.region,
        log_level=args.log_level,
    )
    app.run()


if __name__ == "__main__":
    main()
