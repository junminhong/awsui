"""Tests for the reusable arrow-key terminal selector."""

from io import StringIO
import os
import select
import signal
import time
from unittest.mock import Mock, patch

import pytest
from questionary import Choice, Separator
from prompt_toolkit.layout.containers import Window
from questionary.prompts.common import InquirerControl

from awsui.interactive_selector import (
    SelectionOption,
    SelectorInputClosed,
    select_option,
    supports_arrow_selection,
)


class TerminalBuffer(StringIO):
    """String buffer that advertises terminal support."""

    def isatty(self) -> bool:
        return True


@pytest.mark.parametrize(
    ("stdin", "stdout", "expected"),
    [
        (TerminalBuffer(), TerminalBuffer(), True),
        (StringIO(), TerminalBuffer(), False),
        (TerminalBuffer(), StringIO(), False),
        (StringIO(), StringIO(), False),
    ],
)
def test_arrow_selection_requires_two_terminal_streams(stdin, stdout, expected):
    assert supports_arrow_selection(stdin, stdout) is expected


@patch("awsui.interactive_selector.create_output")
@patch("awsui.interactive_selector.create_input")
@patch("awsui.interactive_selector.questionary.select")
def test_selector_configures_compact_arrow_only_prompt(
    mock_select,
    mock_create_input,
    mock_create_output,
):
    prompt = Mock()
    prompt.unsafe_ask.return_value = "prod"
    choices_window = Window(InquirerControl(["Development", "Production"]))
    prompt.application.layout.find_all_windows.return_value = [choices_window]
    mock_select.return_value = prompt
    terminal_input = Mock()
    terminal_output = Mock()
    mock_create_input.return_value = terminal_input
    mock_create_output.return_value = terminal_output
    stdin = TerminalBuffer()
    stdout = TerminalBuffer()

    selected = select_option(
        "Environment",
        [
            SelectionOption("Development", "dev", "111111111111"),
            SelectionOption(
                "Production",
                "prod",
                "999999999999",
                separator_before=True,
            ),
        ],
        default="prod",
        stdin=stdin,
        stdout=stdout,
    )

    assert selected == "prod"
    mock_create_input.assert_called_once_with(stdin=stdin)
    mock_create_output.assert_called_once_with(stdout=stdout)
    kwargs = mock_select.call_args.kwargs
    assert kwargs["default"] == "prod"
    assert kwargs["use_arrow_keys"] is True
    assert kwargs["use_jk_keys"] is False
    assert kwargs["use_emacs_keys"] is False
    assert kwargs["use_shortcuts"] is False
    assert kwargs["use_search_filter"] is False
    assert "max_height" not in kwargs
    assert choices_window.height.max == 12
    assert kwargs["input"] is terminal_input
    assert kwargs["output"] is terminal_output
    assert isinstance(kwargs["choices"][0], Choice)
    assert isinstance(kwargs["choices"][1], Separator)
    assert isinstance(kwargs["choices"][2], Choice)
    terminal_input.close.assert_called_once_with()


@patch("awsui.interactive_selector.create_output", return_value=Mock())
@patch("awsui.interactive_selector.create_input")
@patch("awsui.interactive_selector.questionary.select")
def test_selector_converts_eof_and_closes_terminal_input(
    mock_select,
    mock_create_input,
    _mock_create_output,
):
    prompt = Mock()
    prompt.unsafe_ask.side_effect = EOFError
    prompt.application.layout.find_all_windows.return_value = []
    mock_select.return_value = prompt
    terminal_input = Mock()
    mock_create_input.return_value = terminal_input

    with pytest.raises(SelectorInputClosed):
        select_option(
            "Environment",
            [SelectionOption("Production", "prod")],
            default="prod",
            stdin=TerminalBuffer(),
            stdout=TerminalBuffer(),
        )

    terminal_input.close.assert_called_once_with()


@pytest.mark.skipif(not hasattr(os, "forkpty"), reason="requires a POSIX PTY")
def test_real_pty_accepts_down_arrow_and_enter():
    pid, terminal_fd = os.forkpty()
    if pid == 0:
        with (
            os.fdopen(os.dup(0)) as child_stdin,
            os.fdopen(
                os.dup(1),
                "w",
            ) as child_stdout,
        ):
            selected = select_option(
                "Environment",
                [
                    SelectionOption("Development", "dev"),
                    SelectionOption("Production", "prod"),
                ],
                default="dev",
                stdin=child_stdin,
                stdout=child_stdout,
                environment={"NO_COLOR": "1"},
            )
            print(f"SELECTED={selected}", file=child_stdout, flush=True)
        os._exit(0)

    output = bytearray()
    deadline = time.monotonic() + 5
    child_exited = False
    try:
        while time.monotonic() < deadline and b"Environment" not in output:
            readable, _, _ = select.select([terminal_fd], [], [], 0.1)
            if readable:
                output.extend(os.read(terminal_fd, 4096))

        os.write(terminal_fd, b"\x1b[B\r")
        while time.monotonic() < deadline and b"SELECTED=prod" not in output:
            readable, _, _ = select.select([terminal_fd], [], [], 0.1)
            if readable:
                try:
                    output.extend(os.read(terminal_fd, 4096))
                except OSError:
                    break
        waited_pid, status = os.waitpid(pid, os.WNOHANG)
        if waited_pid == pid:
            child_exited = True
            assert os.waitstatus_to_exitcode(status) == 0
    finally:
        os.close(terminal_fd)
        if not child_exited:
            os.kill(pid, signal.SIGTERM)
            os.waitpid(pid, 0)

    assert b"SELECTED=prod" in output
