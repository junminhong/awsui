"""Modal screens used by the Textual dashboard."""

from collections.abc import Mapping, Sequence

from rich.console import RenderableType
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Select, Static

from ..i18n import LANG_EN
from .launch import DetectedTool


class InformationScreen(ModalScreen[None]):
    """Simple modal for Doctor and keyboard help renderables."""

    CSS = """
    InformationScreen {
        align: center middle;
        background: $background 88%;
    }
    #information-card {
        width: 80;
        max-width: 92%;
        height: auto;
        max-height: 82%;
        padding: 1 2;
        border: solid $border;
        background: $surface;
    }
    #information-title {
        height: 2;
        color: $text;
        text-style: bold;
    }
    #information-scroll { height: auto; max-height: 24; }
    #information-content { height: auto; color: $text; }
    #information-actions {
        height: 2;
        margin-top: 1;
        align-horizontal: right;
    }
    #information-close {
        width: auto;
        min-width: 9;
        height: 1;
        padding: 0 1;
        border: none;
        background: $panel;
        color: $text-muted;
    }
    #information-close:hover, #information-close:focus {
        background: $primary-muted;
        color: $text;
    }
    """

    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("q", "close", "Close"),
    ]

    def __init__(
        self,
        title: str,
        renderable: RenderableType,
        *,
        close_label: str,
    ) -> None:
        super().__init__()
        self.modal_title = title
        self.renderable = renderable
        self.close_label = close_label

    def compose(self) -> ComposeResult:
        with Vertical(id="information-card"):
            yield Static(self.modal_title, id="information-title")
            with VerticalScroll(id="information-scroll"):
                yield Static(self.renderable, id="information-content")
            with Horizontal(id="information-actions"):
                yield Button(
                    self.close_label,
                    id="information-close",
                    compact=True,
                    flat=True,
                )

    def action_close(self) -> None:
        self.dismiss()

    def on_button_pressed(self, _event: Button.Pressed) -> None:
        self.dismiss()


class LaunchScreen(ModalScreen[str | None]):
    """Detected-tool selector plus editable direct-argv command input."""

    CSS = """
    LaunchScreen {
        align: center middle;
        background: $background 88%;
    }
    #launch-card {
        width: 76;
        max-width: 92%;
        height: auto;
        padding: 1 2;
        border: solid $border;
        background: $surface;
    }
    #launch-title { text-style: bold; color: $text; margin-bottom: 1; }
    #launch-warning { color: $text-warning; margin-bottom: 1; }
    #launch-tools, #launch-command { margin-bottom: 1; }
    #launch-tools:focus, #launch-command:focus { border: tall $primary; }
    #launch-actions { height: auto; align-horizontal: right; }
    #launch-actions Button {
        width: auto;
        min-width: 9;
        height: 1;
        margin-left: 1;
        padding: 0 1;
        border: none;
        background: transparent;
        color: $text-muted;
    }
    #launch-actions Button:hover, #launch-actions Button:focus {
        background: $panel;
        color: $text;
    }
    #launch-confirm { color: $text-primary; }
    #launch-confirm:hover, #launch-confirm:focus { background: $primary-muted; }
    """

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(
        self,
        environment: str,
        tools: Sequence[DetectedTool],
        *,
        protected: bool,
        translations: Mapping[str, str] = LANG_EN,
    ) -> None:
        super().__init__()
        self.environment = environment
        self.tools = tuple(tools)
        self.protected = protected
        self.translations = translations

    def compose(self) -> ComposeResult:
        options = [(tool.label, tool.executable) for tool in self.tools]
        options.append((self.translations["launch_custom"], ""))
        initial = self.tools[0].executable if self.tools else ""
        with Vertical(id="launch-card"):
            yield Static(
                self.translations["launch_title"].format(
                    environment=self.environment.upper()
                ),
                id="launch-title",
            )
            warning = Static(
                self.translations["launch_warning"],
                id="launch-warning",
            )
            warning.display = self.protected
            yield warning
            yield Select(
                options,
                value=initial,
                allow_blank=False,
                compact=True,
                id="launch-tools",
            )
            yield Input(
                value=initial,
                placeholder=self.translations["launch_placeholder"],
                id="launch-command",
            )
            with Horizontal(id="launch-actions"):
                yield Button(
                    self.translations["action_cancel"],
                    id="launch-cancel",
                    compact=True,
                    flat=True,
                )
                yield Button(
                    self.translations["action_verify_launch"],
                    id="launch-confirm",
                    compact=True,
                    flat=True,
                )

    def on_mount(self) -> None:
        self.query_one("#launch-command", Input).focus()

    def on_select_changed(self, event: Select.Changed) -> None:
        if isinstance(event.value, str):
            command = self.query_one("#launch-command", Input)
            command.value = event.value
            command.cursor_position = len(event.value)
            command.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.dismiss(event.value.strip() or None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "launch-cancel":
            self.dismiss(None)
            return
        command = self.query_one("#launch-command", Input).value.strip()
        self.dismiss(command or None)

    def action_cancel(self) -> None:
        self.dismiss(None)
