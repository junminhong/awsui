"""TTY-aware Rich output primitives for awsui command-line workflows."""

from __future__ import annotations

from collections.abc import Mapping
import os
from typing import TextIO

from rich.console import Console, RenderableType
from rich.style import StyleType
from rich.text import Text
from rich.theme import Theme


CLI_THEME = Theme(
    {
        "awsui.title": "bold cyan",
        "awsui.label": "dim",
        "awsui.value": "white",
        "awsui.success": "bold green",
        "awsui.warning": "yellow",
        "awsui.error": "bold red",
        "awsui.protected": "bold yellow",
        "awsui.muted": "dim",
        "awsui.option": "bold cyan",
        "awsui.prompt": "cyan",
    }
)


class CliConsole:
    """Render Rich content on a TTY and stable plain text everywhere else."""

    def __init__(
        self,
        stream: TextIO,
        *,
        environment: Mapping[str, str] | None = None,
        force_terminal: bool | None = None,
        width: int | None = None,
    ) -> None:
        env = os.environ if environment is None else environment
        color_system = None if "NO_COLOR" in env else "auto"
        self.stream = stream
        self.console = Console(
            file=stream,
            theme=CLI_THEME,
            highlight=False,
            color_system=color_system,
            force_terminal=force_terminal,
            width=width,
        )

    @property
    def enhanced(self) -> bool:
        """Whether structured Rich output should be used for this stream."""
        return self.console.is_terminal

    def print(
        self,
        renderable: RenderableType,
        *,
        plain: str | None = None,
        end: str = "\n",
        flush: bool = False,
    ) -> None:
        """Print a Rich renderable or its explicit non-TTY fallback."""
        if self.enhanced:
            self.console.print(renderable, end=end, highlight=False)
            if flush:
                self.stream.flush()
            return
        if plain is None:
            return
        self.stream.write(plain)
        self.stream.write(end)
        if flush:
            self.stream.flush()

    def prompt(self, prompt: str) -> None:
        """Write a safe, styled prompt without consuming input."""
        self.print(Text(prompt, style="awsui.prompt"), plain=prompt, end="", flush=True)


def safe_text(value: object, style: StyleType | None = None) -> Text:
    """Create Text from dynamic content without interpreting Rich markup."""
    return Text(str(value), style=style)
