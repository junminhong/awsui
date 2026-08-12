"""Tests for foreground verified-context command execution."""

import sys
from unittest.mock import Mock, patch

import pytest

from awsui.command_runner import (
    CommandLaunchError,
    CommandNotFoundError,
    CommandPermissionError,
    run_command,
    select_interactive_shell,
)


class TestRunCommand:
    @patch("awsui.command_runner.subprocess.Popen")
    def test_launches_exact_argv_with_environment_copy(self, mock_popen):
        process = Mock()
        process.wait.return_value = 7
        mock_popen.return_value = process
        environment = {"AWS_PROFILE": "company-prod", "PATH": "/usr/bin"}

        exit_code = run_command(
            ["terraform", "plan", "-out=my plan"],
            environment=environment,
        )

        assert exit_code == 7
        mock_popen.assert_called_once_with(
            ["terraform", "plan", "-out=my plan"],
            env=environment,
        )
        assert mock_popen.call_args.kwargs["env"] is not environment

    @patch("awsui.command_runner.subprocess.Popen")
    def test_maps_signal_return_code(self, mock_popen):
        process = Mock()
        process.wait.return_value = -15
        mock_popen.return_value = process

        assert run_command(["agent"], environment={}) == 143

    @pytest.mark.parametrize(
        ("error", "expected_type", "exit_code"),
        [
            (FileNotFoundError(), CommandNotFoundError, 127),
            (PermissionError(), CommandPermissionError, 126),
            (OSError("broken"), CommandLaunchError, 1),
        ],
    )
    @patch("awsui.command_runner.subprocess.Popen")
    def test_normalizes_launch_errors(
        self,
        mock_popen,
        error,
        expected_type,
        exit_code,
    ):
        mock_popen.side_effect = error

        with pytest.raises(expected_type) as exc_info:
            run_command(["missing"], environment={})

        assert exc_info.value.exit_code == exit_code

    def test_rejects_empty_command(self):
        with pytest.raises(ValueError, match="must not be empty"):
            run_command([], environment={})

    def test_real_child_receives_exact_environment_and_exit_code(self, capfd):
        exit_code = run_command(
            [
                sys.executable,
                "-c",
                "import os,sys; print(os.environ['AWS_PROFILE']); "
                "print(os.environ.get('AWS_ACCESS_KEY_ID', 'clean')); sys.exit(4)",
            ],
            environment={"AWS_PROFILE": "company-prod"},
        )

        assert exit_code == 4
        output = capfd.readouterr().out.replace("\r\n", "\n")
        assert output == "company-prod\nclean\n"


class TestSelectInteractiveShell:
    def test_uses_posix_shell(self):
        assert (
            select_interactive_shell({"SHELL": "/bin/zsh"}, platform="posix")
            == "/bin/zsh"
        )

    def test_posix_fallback(self):
        assert select_interactive_shell({}, platform="posix") == "/bin/sh"

    def test_uses_windows_comspec(self):
        assert (
            select_interactive_shell(
                {"COMSPEC": "C:\\Windows\\cmd.exe"},
                platform="nt",
            )
            == "C:\\Windows\\cmd.exe"
        )

    def test_windows_fallback(self):
        assert select_interactive_shell({}, platform="nt") == "cmd.exe"
