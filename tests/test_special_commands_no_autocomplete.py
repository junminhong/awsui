"""Tests for special commands not showing autocomplete suggestions."""

import pytest
from awsui.command_parser import AWSCommandParser, CompletionContext


@pytest.fixture
def parser():
    parser = AWSCommandParser()
    parser.use_dynamic_loading = False
    return parser


def test_help_with_trailing_space_no_suggestions(parser):
    """Test 'aws help ' does not show command suggestions."""
    parsed = parser.parse("aws help ")
    assert parsed.service == "help"
    assert parsed.current_context == CompletionContext.COMMAND
    suggestions = parser.get_suggestions(parsed)
    assert suggestions == []


def test_help_with_parameter_no_suggestions(parser):
    """Test 'aws help --' does not show parameter suggestions."""
    parsed = parser.parse("aws help --")
    assert parsed.service == "help"
    suggestions = parser.get_suggestions(parsed)
    assert suggestions == []


def test_help_typing_text_no_suggestions(parser):
    """Test 'aws help something' does not show suggestions."""
    parsed = parser.parse("aws help something")
    assert parsed.service == "help"
    suggestions = parser.get_suggestions(parsed)
    assert suggestions == []


def test_configure_with_trailing_space_no_suggestions(parser):
    """Test 'aws configure ' does not show command suggestions."""
    parsed = parser.parse("aws configure ")
    assert parsed.service == "configure"
    assert parsed.current_context == CompletionContext.COMMAND
    suggestions = parser.get_suggestions(parsed)
    assert suggestions == []


def test_configure_with_parameter_no_suggestions(parser):
    """Test 'aws configure --' does not show parameter suggestions."""
    parsed = parser.parse("aws configure --")
    assert parsed.service == "configure"
    suggestions = parser.get_suggestions(parsed)
    assert suggestions == []


def test_help_recognized_as_service(parser):
    """Test 'help' is recognized as valid service."""
    parsed = parser.parse("aws help")
    assert parsed.service == "help"
    assert parser._is_valid_service("help") is True


def test_configure_recognized_as_service(parser):
    """Test 'configure' is recognized as valid service."""
    parsed = parser.parse("aws configure")
    assert parsed.service == "configure"
    assert parser._is_valid_service("configure") is True


def test_special_commands_in_constant(parser):
    """Test special commands are defined in SPECIAL_COMMANDS."""
    assert "help" in parser.SPECIAL_COMMANDS
    assert "configure" in parser.SPECIAL_COMMANDS
