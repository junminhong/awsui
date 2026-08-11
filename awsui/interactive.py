"""Small, stream-oriented helpers for interactive CLI workflows."""

from typing import TextIO

from .cli_console import CliConsole
from .i18n import text


class InputClosedError(Exception):
    """Raised when an interactive input stream closes unexpectedly."""


def read_line(prompt: str, *, stdin: TextIO, stdout: TextIO) -> str:
    CliConsole(stdout).prompt(prompt)
    value = stdin.readline()
    if value == "":
        raise InputClosedError("input closed")
    return value


def prompt_value(
    prompt: str,
    *,
    default: str | None,
    stdin: TextIO,
    stdout: TextIO,
) -> str:
    output = CliConsole(stdout)
    while True:
        value = read_line(prompt, stdin=stdin, stdout=stdout).strip()
        if value:
            return value
        if default:
            return default
        output.print(
            text("cli_nonempty_required"),
            plain=text("cli_nonempty_required"),
        )


def prompt_yes_no(
    prompt: str,
    *,
    default: bool = False,
    stdin: TextIO,
    stdout: TextIO,
) -> bool:
    output = CliConsole(stdout)
    while True:
        value = read_line(prompt, stdin=stdin, stdout=stdout).strip().casefold()
        if not value:
            return default
        if value.casefold() in {"y", "yes", "是"}:
            return True
        if value.casefold() in {"n", "no", "否"}:
            return False
        output.print(text("cli_yes_no_required"), plain=text("cli_yes_no_required"))
