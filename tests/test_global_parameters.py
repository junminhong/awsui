"""Tests for global parameters support."""

import pytest
from awsui.command_parser import AWSCommandParser, CompletionContext


@pytest.fixture
def parser():
    parser = AWSCommandParser()
    parser.use_dynamic_loading = False
    return parser


def test_global_parameters_at_root(parser):
    """Test global parameters shown when typing 'aws --'."""
    parsed = parser.parse("aws --")
    assert parsed.current_context == CompletionContext.PARAMETER
    suggestions = parser.get_suggestions(parsed)
    assert "--version" in suggestions
    assert "--debug" in suggestions
    assert "--region" in suggestions
    assert "--profile" in suggestions


def test_global_parameter_filter(parser):
    """Test filtering global parameters with prefix."""
    parsed = parser.parse("aws --v")
    suggestions = parser.get_suggestions(parsed)
    assert "--version" in suggestions
    assert "--debug" not in suggestions


def test_global_parameter_with_service(parser):
    """Test global parameters included with service parameters."""
    parsed = parser.parse("aws s3 ls --")
    suggestions = parser.get_suggestions(parsed)
    assert "--region" in suggestions
    assert "--output" in suggestions
    assert "--recursive" in suggestions


def test_global_parameter_before_service(parser):
    """Test global parameters can appear before service."""
    parsed = parser.parse("aws --region ")
    assert parsed.current_context == CompletionContext.PARAMETER_VALUE
    suggestions = parser.get_suggestions(parsed)
    assert "us-east-1" in suggestions
    assert "us-west-2" in suggestions


def test_no_parameters_without_dash(parser):
    """Test parameters not shown when not typing dash."""
    parsed = parser.parse("aws s")
    suggestions = parser.get_suggestions(parsed)
    assert "s3" in suggestions
    assert "--version" not in suggestions
    assert "--region" not in suggestions


def test_global_parameters_list_complete(parser):
    """Test all expected global parameters are defined."""
    expected_params = [
        "--version",
        "--debug",
        "--no-verify-ssl",
        "--no-paginate",
        "--output",
        "--query",
        "--profile",
        "--region",
        "--endpoint-url",
        "--no-cli-pager",
    ]
    for param in expected_params:
        assert param in parser.GLOBAL_PARAMETERS
