"""Small, stream-oriented helpers for interactive CLI workflows."""

from typing import TextIO

from .cli_console import CliConsole


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
            "A non-empty value is required.",
            plain="A non-empty value is required.",
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
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        output.print("Enter y or n.", plain="Enter y or n.")
