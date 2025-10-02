"""AWS CLI command parser for intelligent autocomplete."""

import re
from dataclasses import dataclass
from enum import Enum


class CompletionContext(Enum):
    """Context for autocomplete suggestions."""
    SERVICE = "service"           # Completing AWS service name (e.g., "aws s3")
    COMMAND = "command"           # Completing command (e.g., "aws s3 ls")
    PARAMETER = "parameter"       # Completing parameter name (e.g., "--region")
    PARAMETER_VALUE = "value"     # Completing parameter value (e.g., "--region us-")


@dataclass
class ParsedCommand:
    """Parsed AWS CLI command structure."""
    raw_input: str
    service: str = ""
    command: str = ""
    subcommand: str = ""
    parameters: dict[str, str | None] = None
    current_context: CompletionContext = CompletionContext.SERVICE
    current_token: str = ""
    cursor_position: int = 0

    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}


class AWSCommandParser:
    """Parser for AWS CLI commands to enable context-aware autocomplete."""

    AWS_SERVICES = [
        "s3", "ec2", "lambda", "dynamodb", "rds", "iam", "sts", "cloudformation",
        "cloudfront", "cloudtrail", "cloudwatch", "logs", "ecr", "ecs", "eks",
        "sns", "sqs", "secretsmanager", "ssm", "stepfunctions", "kinesis", "kms",
        "glue", "organizations", "route53", "redshift"
    ]

    SERVICE_COMMANDS = {
        "s3": ["ls", "cp", "mv", "rm", "sync", "mb", "rb"],
        "ec2": ["describe-instances", "start-instances", "stop-instances", "reboot-instances",
                "describe-security-groups", "describe-vpcs", "describe-subnets", "create-image"],
        "lambda": ["list-functions", "invoke", "get-function", "update-function-code",
                   "create-function", "delete-function"],
        "iam": ["list-users", "list-roles", "get-user", "list-policies", "attach-role-policy"],
        "sts": ["get-caller-identity", "assume-role", "get-session-token"],
        "cloudformation": ["list-stacks", "describe-stacks", "create-stack", "update-stack", "delete-stack"],
        "dynamodb": ["list-tables", "describe-table", "scan", "query", "update-table"],
        "ecr": ["describe-repositories", "get-login-password", "list-images", "batch-delete-image"],
        "ecs": ["list-clusters", "list-services", "describe-services", "update-service"],
        "eks": ["list-clusters", "describe-cluster", "update-kubeconfig"],
        "rds": ["describe-db-instances", "describe-db-clusters", "create-db-snapshot"],
        "logs": ["tail", "describe-log-groups", "describe-log-streams"],
        "cloudwatch": ["list-metrics", "get-metric-statistics", "describe-alarms"],
    }

    COMMON_PARAMETERS = [
        "--region",
        "--output",
        "--profile",
        "--query",
        "--no-cli-pager",
        "--no-verify-ssl",
        "--endpoint-url",
        "--debug",
        "--no-paginate",
        "--max-items",
        "--page-size",
    ]

    PARAMETER_VALUES = {
        "--region": [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2",
            "sa-east-1", "ca-central-1"
        ],
        "--output": ["json", "yaml", "yaml-stream", "text", "table"],
    }

    SERVICE_PARAMETERS = {
        "s3": ["--recursive", "--exclude", "--include", "--delete", "--acl", "--storage-class"],
        "ec2": ["--instance-ids", "--security-group-ids", "--vpc-id", "--subnet-id", "--filters"],
        "lambda": ["--function-name", "--payload", "--zip-file", "--runtime", "--handler", "--role"],
        "iam": ["--role-name", "--policy-arn", "--user-name", "--group-name"],
        "cloudformation": ["--stack-name", "--template-body", "--template-url", "--parameters"],
        "dynamodb": ["--table-name", "--key", "--attribute-definitions", "--provisioned-throughput"],
    }

    def parse(self, command_line: str, cursor_pos: int | None = None) -> ParsedCommand:
        """
        Parse AWS CLI command and determine current context for autocomplete.

        Args:
            command_line: The command line input
            cursor_pos: Cursor position (defaults to end of string)

        Returns:
            ParsedCommand with parsed structure and context
        """
        if cursor_pos is None:
            cursor_pos = len(command_line)

        text_to_cursor = command_line[:cursor_pos]
        tokens = self._tokenize(text_to_cursor)

        parsed = ParsedCommand(
            raw_input=command_line,
            cursor_position=cursor_pos
        )

        if not tokens:
            parsed.current_context = CompletionContext.SERVICE
            return parsed

        if tokens[0].lower() == "aws":
            tokens = tokens[1:]

        if not tokens:
            parsed.current_context = CompletionContext.SERVICE
            return parsed

        is_completing_new = text_to_cursor.endswith(" ")
        current_token = "" if is_completing_new else tokens[-1] if tokens else ""
        parsed.current_token = current_token

        if len(tokens) >= 1:
            potential_service = tokens[0]
            if potential_service in self.AWS_SERVICES:
                parsed.service = potential_service
            elif not potential_service.startswith("-"):
                parsed.current_context = CompletionContext.SERVICE
                return parsed

        if len(tokens) >= 2 and parsed.service:
            potential_command = tokens[1]
            if not potential_command.startswith("-"):
                parsed.command = potential_command
                parsed.current_context = CompletionContext.COMMAND
            else:
                parsed.current_context = CompletionContext.COMMAND
                return parsed

        i = 2 if parsed.command else (1 if parsed.service else 0)
        expecting_value = None

        while i < len(tokens):
            token = tokens[i]

            if token.startswith("--"):
                if "=" in token:
                    param, value = token.split("=", 1)
                    parsed.parameters[param] = value
                else:
                    parsed.parameters[token] = None
                    expecting_value = token
            elif token.startswith("-") and len(token) == 2:
                parsed.parameters[token] = None
                expecting_value = token
            else:
                if expecting_value:
                    parsed.parameters[expecting_value] = token
                    expecting_value = None

            i += 1

        if is_completing_new or (tokens and not tokens[-1].startswith("-")):
            if expecting_value:
                parsed.current_context = CompletionContext.PARAMETER_VALUE
                parsed.current_token = current_token if not is_completing_new else ""
            elif parsed.command or (parsed.service and len(tokens) > 1):
                parsed.current_context = CompletionContext.PARAMETER
                parsed.current_token = current_token if not is_completing_new else ""
            elif parsed.service:
                parsed.current_context = CompletionContext.COMMAND
                parsed.current_token = current_token if not is_completing_new else ""
            else:
                parsed.current_context = CompletionContext.SERVICE
                parsed.current_token = current_token if not is_completing_new else ""
        else:
            if current_token.startswith("--") or current_token.startswith("-"):
                parsed.current_context = CompletionContext.PARAMETER
            elif not parsed.service:
                parsed.current_context = CompletionContext.SERVICE
            elif not parsed.command:
                parsed.current_context = CompletionContext.COMMAND
            else:
                parsed.current_context = CompletionContext.PARAMETER

        return parsed

    def _tokenize(self, text: str) -> list[str]:
        """Tokenize command line, respecting quotes."""
        tokens = []
        current_token = ""
        in_quote = None

        for char in text:
            if char in ('"', "'"):
                if in_quote == char:
                    in_quote = None
                elif in_quote is None:
                    in_quote = char
                current_token += char
            elif char.isspace() and in_quote is None:
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
            else:
                current_token += char

        if current_token:
            tokens.append(current_token)

        return tokens

    def get_suggestions(self, parsed: ParsedCommand) -> list[str]:
        """
        Get autocomplete suggestions based on parsed command context.

        Args:
            parsed: Parsed command structure

        Returns:
            List of suggestion strings
        """
        query = parsed.current_token.lower()

        if parsed.current_context == CompletionContext.SERVICE:
            return [s for s in self.AWS_SERVICES if s.startswith(query)]

        elif parsed.current_context == CompletionContext.COMMAND:
            commands = self.SERVICE_COMMANDS.get(parsed.service, [])
            return [c for c in commands if c.startswith(query)]

        elif parsed.current_context == CompletionContext.PARAMETER:
            suggestions = list(self.COMMON_PARAMETERS)

            if parsed.service in self.SERVICE_PARAMETERS:
                suggestions.extend(self.SERVICE_PARAMETERS[parsed.service])

            used_params = set(parsed.parameters.keys())
            suggestions = [p for p in suggestions if p not in used_params]

            return [p for p in suggestions if p.startswith(query)]

        elif parsed.current_context == CompletionContext.PARAMETER_VALUE:
            last_param = None
            for param, value in reversed(list(parsed.parameters.items())):
                if value is None:
                    last_param = param
                    break

            if last_param and last_param in self.PARAMETER_VALUES:
                values = self.PARAMETER_VALUES[last_param]
                return [v for v in values if v.startswith(query)]

        return []
