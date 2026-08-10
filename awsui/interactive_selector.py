"""Vendor-neutral arrow-key selection for interactive terminal workflows."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import os
from typing import Generic, TextIO, TypeVar

import questionary
from prompt_toolkit.formatted_text import StyleAndTextTuples
from prompt_toolkit.input.defaults import create_input
from prompt_toolkit.layout.containers import Window
from prompt_toolkit.layout.dimension import Dimension
from prompt_toolkit.output.defaults import create_output
from prompt_toolkit.styles import Style
from questionary.prompts.common import InquirerControl


T = TypeVar("T")


class SelectorInputClosed(Exception):
    """Raised when an interactive selector loses its input stream."""


@dataclass(frozen=True, slots=True)
class SelectionOption(Generic[T]):
    """One selectable value and its terminal presentation metadata."""

    label: str
    value: T
    detail: str | None = None
    disabled: str | None = None
    separator_before: bool = False


_SELECTOR_STYLE = Style.from_dict(
    {
        "qmark": "fg:#22d3ee bold",
        "question": "fg:#22d3ee bold",
        "pointer": "fg:#22d3ee bold",
        "highlighted": "fg:#f8fafc bold",
        "answer": "fg:#22c55e bold",
        "instruction": "fg:#64748b",
        "disabled": "fg:#f59e0b",
        "choice-title": "fg:#e2e8f0",
        "choice-detail": "fg:#64748b",
        "separator": "fg:#334155",
    }
)
_NO_COLOR_STYLE = Style.from_dict({})


def supports_arrow_selection(stdin: TextIO, stdout: TextIO) -> bool:
    """Return whether both workflow streams are real interactive terminals."""
    try:
        return stdin.isatty() and stdout.isatty()
    except (AttributeError, OSError):
        return False


def select_option(
    message: str,
    options: Sequence[SelectionOption[T]],
    *,
    default: T,
    stdin: TextIO,
    stdout: TextIO,
    environment: Mapping[str, str] | None = None,
    max_height: int = 12,
) -> T:
    """Select one option with arrows and Enter on an interactive terminal."""
    if not options:
        raise ValueError("interactive selector requires at least one option")

    choices: list[questionary.Choice | questionary.Separator] = []
    for option in options:
        if option.separator_before:
            choices.append(questionary.Separator("─"))
        choices.append(
            questionary.Choice(
                title=_formatted_title(option),
                value=option.value,
                disabled=option.disabled,
                shortcut_key=False,
            )
        )

    env = os.environ if environment is None else environment
    style = _NO_COLOR_STYLE if "NO_COLOR" in env else _SELECTOR_STYLE
    terminal_input = create_input(stdin=stdin)
    terminal_output = create_output(stdout=stdout)
    try:
        question = questionary.select(
            message,
            choices=choices,
            default=default,
            qmark="›",
            pointer="❯",
            style=style,
            use_shortcuts=False,
            use_arrow_keys=True,
            use_indicator=False,
            use_jk_keys=False,
            use_emacs_keys=False,
            use_search_filter=False,
            show_selected=True,
            show_description=False,
            instruction="(↑/↓ move · Enter select · Ctrl-C cancel)",
            input=terminal_input,
            output=terminal_output,
        )
        _limit_selection_height(question, max_height)
        return question.unsafe_ask()
    except EOFError as exc:
        raise SelectorInputClosed("selector input closed") from exc
    finally:
        terminal_input.close()


def _formatted_title(option: SelectionOption[object]) -> StyleAndTextTuples:
    title: StyleAndTextTuples = [("class:choice-title", option.label)]
    if option.detail:
        title.append(("class:choice-detail", f"  ·  {option.detail}"))
    return title


def _limit_selection_height(question: questionary.Question, max_height: int) -> None:
    """Cap the scrolling choices window without passing unsupported kwargs."""
    for window in question.application.layout.find_all_windows():
        if isinstance(window, Window) and isinstance(
            window.content,
            InquirerControl,
        ):
            window.height = Dimension(max=max_height)
