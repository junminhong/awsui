"""Tests for AWS CLI command parser."""

import pytest
from awsui.command_parser import AWSCommandParser, CompletionContext


class TestAWSCommandParser:
    """Test AWS CLI command parsing functionality."""

    @pytest.fixture
    def parser(self):
        parser = AWSCommandParser()
        parser.use_dynamic_loading = False
        return parser

    def test_parse_service_completion(self, parser):
        """Test service name completion."""
        parsed = parser.parse("aws s")
        assert parsed.current_context == CompletionContext.SERVICE
        assert parsed.current_token == "s"
        assert parsed.service == ""

    def test_parse_service_selected(self, parser):
        """Test after service is selected."""
        parsed = parser.parse("aws s3 ")
        assert parsed.current_context == CompletionContext.COMMAND
        assert parsed.service == "s3"
        assert parsed.command == ""

    def test_parse_command_completion(self, parser):
        """Test command completion."""
        parsed = parser.parse("aws s3 l")
        assert parsed.current_context == CompletionContext.COMMAND
        assert parsed.service == "s3"
        assert parsed.current_token == "l"

    def test_parse_parameter_suggestion(self, parser):
        """Test parameter suggestion after command."""
        parsed = parser.parse("aws s3 ls ")
        assert parsed.current_context == CompletionContext.PARAMETER
        assert parsed.service == "s3"
        assert parsed.command == "ls"

    def test_parse_parameter_completion(self, parser):
        """Test parameter name completion."""
        parsed = parser.parse("aws ec2 describe-instances --reg")
        assert parsed.current_context == CompletionContext.PARAMETER
        assert parsed.current_token == "--reg"
        assert parsed.command == "describe-instances"

    def test_parse_parameter_value_completion(self, parser):
        """Parameter value context is active while awaiting a value."""
        parsed = parser.parse("aws ec2 describe-instances --region ")
        assert parsed.current_context == CompletionContext.PARAMETER_VALUE
        assert parsed.current_token == ""
        assert parsed.parameters["--region"] is None

    def test_get_service_suggestions(self, parser):
        """Test service name suggestions."""
        parsed = parser.parse("aws s")
        suggestions = parser.get_suggestions(parsed)
        assert "s3" in suggestions
        assert "sns" in suggestions
        assert "sqs" in suggestions

    def test_get_command_suggestions(self, parser):
        """Test command suggestions for service."""
        parsed = parser.parse("aws s3 l")
        suggestions = parser.get_suggestions(parsed)
        assert "ls" in suggestions

    def test_get_parameter_suggestions(self, parser):
        """Test parameter suggestions."""
        parsed = parser.parse("aws s3 ls --")
        suggestions = parser.get_suggestions(parsed)
        assert "--region" in suggestions
        assert "--output" in suggestions
        assert "--recursive" in suggestions

    def test_get_region_value_suggestions(self, parser):
        """Test region value suggestions."""
        parsed = parser.parse("aws ec2 describe-instances --region ")
        suggestions = parser.get_suggestions(parsed)
        assert "us-east-1" in suggestions
        assert "us-west-2" in suggestions

    def test_multiple_parameters(self, parser):
        """Test parsing multiple parameters."""
        parsed = parser.parse("aws ec2 describe-instances --region us-east-1 --output json ")
        assert parsed.current_context == CompletionContext.PARAMETER
        assert parsed.parameters["--region"] == "us-east-1"
        assert parsed.parameters["--output"] == "json"

    def test_tokenization_with_quotes(self, parser):
        """Test tokenization handles quotes."""
        parsed = parser.parse('aws s3 cp "file with spaces.txt" s3://bucket/')
        assert parsed.service == "s3"
        assert parsed.command == "cp"
