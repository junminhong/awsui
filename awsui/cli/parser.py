"""Argument parsing and shorthand normalization for awsui."""

from argparse import ArgumentParser, Namespace, REMAINDER
from collections.abc import Sequence
import shlex
import sys

from rich_argparse import RawDescriptionRichHelpFormatter

from .. import __version__
from ..i18n import text
from .console import CliConsole
from .presenter import render_failure_rich


_COMMANDS = frozenset({"init", "bind", "context", "run", "shell", "doctor"})
_HELP_EPILOG = """\
{quick_start}:
  awsui init
  awsui prod -- codex
  awsui prod
  awsui context prod

{compatibility}:
  awsui run prod -- codex
  awsui shell prod
"""


class AwsuiHelpFormatter(RawDescriptionRichHelpFormatter):
    """awsui-colored argparse help output."""

    styles = {
        **RawDescriptionRichHelpFormatter.styles,
        "argparse.args": "bold cyan",
        "argparse.groups": "bold cyan",
        "argparse.metavar": "cyan",
        "argparse.prog": "bright_blue",
        "argparse.syntax": "bold green",
    }
    text_markup = False
    help_markup = False


class AwsuiArgumentParser(ArgumentParser):
    """Argument parser with TTY-aware actionable errors."""

    def __init__(self, *args: object, lang: str = "en", **kwargs: object) -> None:
        self.lang = lang
        super().__init__(*args, **kwargs)

    def error(self, message: str) -> None:
        output = CliConsole(sys.stderr)
        if not output.enhanced:
            if self.lang == "zh-TW":
                self.print_usage(sys.stderr)
                self.exit(2, f"{self.prog}：錯誤：{message}\n")
            super().error(message)
        output.print(
            render_failure_rich(
                text("cli_invalid_command", lang=self.lang),
                message,
                next_step=(
                    f"執行 `{self.prog} --help` 查看用法。"
                    if self.lang == "zh-TW"
                    else f"Run `{self.prog} --help` for usage."
                ),
            )
        )
        self.exit(2)

    def format_help(self) -> str:
        rendered = super().format_help()
        if self.lang == "zh-TW":
            rendered = rendered.replace("Usage:", "用法：", 1)
        return rendered


def build_parser(lang: str = "en") -> ArgumentParser:
    """Build the awsui command-line parser."""
    parser = AwsuiArgumentParser(
        prog="awsui",
        description=text("cli_description", lang=lang),
        epilog=_HELP_EPILOG.format(
            quick_start=text("cli_quick_start", lang=lang),
            compatibility=text("cli_compatibility", lang=lang),
        ),
        formatter_class=AwsuiHelpFormatter,
        lang=lang,
        add_help=False,
    )
    _add_localized_help(parser, lang)
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help=text("cli_version_option", lang=lang),
    )
    parser.add_argument(
        "--lang",
        choices=["zh-TW", "en"],
        default=lang,
        help=text("cli_language_option", lang=lang),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        parser_class=AwsuiArgumentParser,
    )
    init_parser = subparsers.add_parser(
        "init",
        help=text("cli_init_help", lang=lang),
        description=text("cli_init_help", lang=lang),
        formatter_class=AwsuiHelpFormatter,
        lang=lang,
        add_help=False,
    )
    _add_localized_help(init_parser, lang)
    bind_parser = subparsers.add_parser(
        "bind",
        help=text("cli_bind_help", lang=lang),
        description=text("cli_bind_help", lang=lang),
        formatter_class=AwsuiHelpFormatter,
        lang=lang,
        add_help=False,
    )
    _add_localized_help(bind_parser, lang)
    bind_parser.add_argument(
        "environment",
        help=text("cli_bind_environment_help", lang=lang),
    )
    bind_parser.add_argument(
        "--json",
        action="store_true",
        help=text("cli_bind_json_help", lang=lang),
    )

    context_parser = subparsers.add_parser(
        "context",
        help=text("cli_context_help", lang=lang),
        description=text("cli_context_help", lang=lang),
        formatter_class=AwsuiHelpFormatter,
        lang=lang,
        add_help=False,
    )
    _add_localized_help(context_parser, lang)
    context_parser.add_argument(
        "environment",
        help=text("cli_context_environment_help", lang=lang),
    )
    context_parser.add_argument(
        "--json",
        action="store_true",
        help=text("cli_context_json_help", lang=lang),
    )

    run_parser = subparsers.add_parser(
        "run",
        help=text("cli_run_help", lang=lang),
        description=text("cli_run_help", lang=lang),
        formatter_class=AwsuiHelpFormatter,
        lang=lang,
        add_help=False,
    )
    _add_localized_help(run_parser, lang)
    run_parser.add_argument(
        "environment", help=text("cli_run_environment_help", lang=lang)
    )
    run_parser.add_argument(
        "child_command",
        nargs=REMAINDER,
        help=text("cli_run_command_help", lang=lang),
    )

    shell_parser = subparsers.add_parser(
        "shell",
        help=text("cli_shell_help", lang=lang),
        description=text("cli_shell_help", lang=lang),
        formatter_class=AwsuiHelpFormatter,
        lang=lang,
        add_help=False,
    )
    _add_localized_help(shell_parser, lang)
    shell_parser.add_argument(
        "environment", help=text("cli_shell_environment_help", lang=lang)
    )

    doctor_parser = subparsers.add_parser(
        "doctor",
        help=text("cli_doctor_help", lang=lang),
        description=text("cli_doctor_help", lang=lang),
        formatter_class=AwsuiHelpFormatter,
        lang=lang,
        add_help=False,
    )
    _add_localized_help(doctor_parser, lang)

    if lang == "zh-TW":
        parser._positionals.title = text("cli_commands", lang=lang)
        parser._optionals.title = text("cli_options", lang=lang)
    return parser


def _add_localized_help(parser: ArgumentParser, lang: str) -> None:
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help=text("cli_help_option", lang=lang),
    )
    if lang == "zh-TW":
        parser._positionals.title = text("cli_commands", lang=lang)
        parser._optionals.title = text("cli_options", lang=lang)


def parse_args(
    argv: Sequence[str] | None = None,
    *,
    default_lang: str = "en",
) -> Namespace:
    """Parse command-line arguments from argv or the current process."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    lang = _requested_language(raw_argv) or default_lang
    parser = build_parser(lang)
    normalized, error = _normalize_shorthand(raw_argv)
    if error is not None:
        parser.error(error)
    return parser.parse_args(normalized)


def _requested_language(argv: Sequence[str]) -> str | None:
    """Read the requested language before constructing localized help."""
    for index, value in enumerate(argv):
        if value.startswith("--lang="):
            return value.partition("=")[2]
        if value == "--lang" and index + 1 < len(argv):
            return argv[index + 1]
    return None


def _normalize_shorthand(argv: list[str]) -> tuple[list[str], str | None]:
    """Translate `awsui <environment> [-- command]` to legacy subcommands."""
    prefix: list[str] = []
    index = 0
    while index < len(argv):
        value = argv[index]
        if value.startswith("--lang="):
            prefix.append(value)
            index += 1
            continue
        if value == "--lang" and index + 1 < len(argv):
            prefix.extend(argv[index : index + 2])
            index += 2
            continue
        break

    remainder_argv = argv[index:]
    if (
        not remainder_argv
        or remainder_argv[0].startswith("-")
        or remainder_argv[0] in _COMMANDS
    ):
        return argv, None

    environment, *remainder = remainder_argv
    if not remainder:
        return [*prefix, "shell", environment], None
    if remainder[0] != "--":
        example = f"awsui {environment} -- {shlex.join(remainder)}"
        return argv, f"commands after an environment require `--`; use `{example}`"
    if len(remainder) == 1:
        return argv, "a command is required after `--`"
    return [*prefix, "run", environment, *remainder], None
