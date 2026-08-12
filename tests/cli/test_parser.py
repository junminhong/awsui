"""Tests for command-line argument parsing."""

import pytest

from awsui.cli.parser import build_parser, parse_args


class TestParseArgs:
    def test_default_arguments(self):
        args = parse_args([])

        assert not hasattr(args, "profile")
        assert not hasattr(args, "region")
        assert args.lang == "en"
        assert args.command is None

    @pytest.mark.parametrize("option", ["--profile", "--region"])
    def test_removed_legacy_tui_options_are_rejected(self, option):
        with pytest.raises(SystemExit) as exc_info:
            parse_args([option, "legacy-value"])

        assert exc_info.value.code == 2

    def test_removed_log_level_option_is_rejected(self):
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["--log-level", "DEBUG"])

        assert exc_info.value.code == 2

    def test_language_argument_english(self):
        assert parse_args(["--lang", "en"]).lang == "en"

    def test_language_argument_chinese(self):
        assert parse_args(["--lang", "zh-TW"]).lang == "zh-TW"

    def test_help_identifies_existing_options(self):
        help_text = build_parser().format_help()

        assert "--profile" not in help_text
        assert "--region" not in help_text
        assert "--lang" in help_text
        assert "--log-level" not in help_text
        for command in ("bind", "init", "context", "run", "shell", "doctor"):
            assert command in help_text

    @pytest.mark.parametrize("command", ["init", "doctor"])
    def test_argumentless_subcommands(self, command):
        assert parse_args([command]).command == command

    def test_version(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["--version"])

        assert exc_info.value.code == 0
        assert capsys.readouterr().out == "awsui 0.2.0\n"

    def test_bind_subcommand(self):
        args = parse_args(["bind", "prod"])

        assert args.command == "bind"
        assert args.environment == "prod"
        assert args.json is False

    @pytest.mark.parametrize("alias", ["ls", "list"])
    def test_bind_list_aliases(self, alias):
        args = parse_args(["bind", alias])

        assert args.command == "bind"
        assert args.environment == alias
        assert args.json is False

    def test_bind_list_json(self):
        args = parse_args(["bind", "ls", "--json"])

        assert args.environment == "ls"
        assert args.json is True

    def test_bind_requires_environment(self):
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["bind"])

        assert exc_info.value.code == 2

    def test_context_subcommand(self):
        args = parse_args(["context", "prod"])

        assert args.command == "context"
        assert args.environment == "prod"
        assert args.json is False

    def test_context_json_subcommand(self):
        args = parse_args(["context", "prod", "--json"])

        assert args.environment == "prod"
        assert args.json is True

    @pytest.mark.parametrize("alias", ["ls", "list"])
    def test_context_list_aliases(self, alias):
        args = parse_args(["context", alias])

        assert args.command == "context"
        assert args.environment == alias
        assert args.json is False

    def test_context_list_json(self):
        args = parse_args(["context", "ls", "--json"])

        assert args.environment == "ls"
        assert args.json is True

    def test_context_requires_environment(self):
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["context"])

        assert exc_info.value.code == 2

    def test_run_subcommand_with_separator(self):
        args = parse_args(["run", "prod", "--", "terraform", "plan", "-out=x"])

        assert args.command == "run"
        assert args.environment == "prod"
        assert args.child_command == ["terraform", "plan", "-out=x"]

    def test_run_subcommand_without_separator(self):
        args = parse_args(["run", "prod", "aws", "s3", "ls"])

        assert args.child_command == ["aws", "s3", "ls"]

    def test_environment_command_shorthand(self):
        args = parse_args(["prod", "--", "codex", "--quiet"])

        assert args.command == "run"
        assert args.environment == "prod"
        assert args.child_command == ["codex", "--quiet"]

    def test_language_option_precedes_environment_command_shorthand(self):
        args = parse_args(["--lang", "zh-TW", "dev", "--", "codex", "."])

        assert args.lang == "zh-TW"
        assert args.command == "run"
        assert args.environment == "dev"
        assert args.child_command == ["codex", "."]

    def test_traditional_chinese_parser_error_has_localized_wrapper(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            parse_args(["--lang", "zh-TW", "dev", "codex"])

        assert exc_info.value.code == 2
        assert "錯誤" in capsys.readouterr().err

    def test_environment_only_shorthand_opens_shell(self):
        args = parse_args(["qa"])

        assert args.command == "shell"
        assert args.environment == "qa"

    @pytest.mark.parametrize("argv", [["prod", "codex"], ["prod", "--"]])
    def test_shorthand_rejects_ambiguous_or_empty_commands(self, argv):
        with pytest.raises(SystemExit) as exc_info:
            parse_args(argv)

        assert exc_info.value.code == 2

    def test_reserved_subcommand_names_keep_existing_meaning(self):
        args = parse_args(["run", "prod", "--", "codex"])

        assert args.command == "run"
        assert args.environment == "prod"

    def test_help_documents_primary_and_compatible_syntax(self):
        help_text = build_parser().format_help()

        assert "awsui prod -- codex" in help_text
        assert "awsui prod" in help_text
        assert "awsui run prod -- codex" in help_text

    def test_shell_subcommand(self):
        args = parse_args(["shell", "prod"])

        assert args.command == "shell"
        assert args.environment == "prod"
