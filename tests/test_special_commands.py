"""Tests for special AWS CLI commands like help and configure."""

import pytest

from awsui.command_parser import AWSCommandParser, CompletionContext


@pytest.fixture()
def parser():
    parser = AWSCommandParser()
    parser.use_dynamic_loading = False
    return parser


def test_help_shortcut_suggestion(parser):
    parsed = parser.parse("aws h")
    assert parsed.current_context == CompletionContext.SERVICE
    assert parsed.current_token == "h"
    assert parser.get_suggestions(parsed) == ["help"]


def test_help_full_word(parser):
    parsed = parser.parse("aws help")
    assert parsed.service == "help"
    assert parsed.current_context == CompletionContext.COMMAND
    assert parsed.current_token == "help"


def test_configure_shortcut_precedes_services(parser):
    parsed = parser.parse("aws c")
    suggestions = parser.get_suggestions(parsed)
    assert suggestions[0] == "configure"
    assert "cloudformation" in suggestions


def test_special_commands_prioritized_at_root(parser):
    parsed = parser.parse("aws ")
    assert parsed.current_context == CompletionContext.SERVICE
    assert parser.get_suggestions(parsed)[:2] == AWSCommandParser.SPECIAL_COMMANDS
