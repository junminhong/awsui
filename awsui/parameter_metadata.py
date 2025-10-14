"""AWS CLI parameter metadata for enhanced autocomplete."""

from dataclasses import dataclass
from enum import Enum


class ParameterType(Enum):
    """Parameter value types."""

    STRING = "string"
    INTEGER = "integer"
    BOOLEAN = "boolean"
    LIST = "list"
    JSON = "json"
    FILE = "file"


@dataclass
class ParameterMetadata:
    """Metadata for an AWS CLI parameter."""

    name: str
    description: str
    required: bool = False
    param_type: ParameterType = ParameterType.STRING
    example: str = ""


# Common AWS CLI parameters with metadata
COMMON_PARAMETER_METADATA = {
    "--region": ParameterMetadata(
        name="--region",
        description="AWS region to use for this command",
        required=False,
        param_type=ParameterType.STRING,
        example="us-east-1",
    ),
    "--output": ParameterMetadata(
        name="--output",
        description="Output format (json, yaml, text, table)",
        required=False,
        param_type=ParameterType.STRING,
        example="json",
    ),
    "--profile": ParameterMetadata(
        name="--profile",
        description="AWS credential profile to use",
        required=False,
        param_type=ParameterType.STRING,
        example="default",
    ),
    "--query": ParameterMetadata(
        name="--query",
        description="JMESPath query to filter output",
        required=False,
        param_type=ParameterType.STRING,
        example="Reservations[].Instances[].InstanceId",
    ),
    "--no-cli-pager": ParameterMetadata(
        name="--no-cli-pager",
        description="Disable AWS CLI pager",
        required=False,
        param_type=ParameterType.BOOLEAN,
        example="",
    ),
    "--max-items": ParameterMetadata(
        name="--max-items",
        description="Maximum number of items to return",
        required=False,
        param_type=ParameterType.INTEGER,
        example="100",
    ),
}

# Service-specific parameter metadata
SERVICE_PARAMETER_METADATA = {
    "s3": {
        "--recursive": ParameterMetadata(
            name="--recursive",
            description="Recursively process files and subdirectories",
            required=False,
            param_type=ParameterType.BOOLEAN,
        ),
        "--exclude": ParameterMetadata(
            name="--exclude",
            description="Exclude files matching pattern",
            required=False,
            param_type=ParameterType.STRING,
            example="*.log",
        ),
        "--include": ParameterMetadata(
            name="--include",
            description="Include only files matching pattern",
            required=False,
            param_type=ParameterType.STRING,
            example="*.txt",
        ),
        "--delete": ParameterMetadata(
            name="--delete",
            description="Delete files in destination not in source",
            required=False,
            param_type=ParameterType.BOOLEAN,
        ),
        "--acl": ParameterMetadata(
            name="--acl",
            description="Access control list (private, public-read, etc.)",
            required=False,
            param_type=ParameterType.STRING,
            example="private",
        ),
    },
    "ec2": {
        "--instance-ids": ParameterMetadata(
            name="--instance-ids",
            description="EC2 instance IDs to operate on",
            required=True,
            param_type=ParameterType.LIST,
            example="i-1234567890abcdef0",
        ),
        "--security-group-ids": ParameterMetadata(
            name="--security-group-ids",
            description="Security group IDs",
            required=False,
            param_type=ParameterType.LIST,
            example="sg-12345678",
        ),
        "--vpc-id": ParameterMetadata(
            name="--vpc-id",
            description="VPC ID",
            required=False,
            param_type=ParameterType.STRING,
            example="vpc-12345678",
        ),
        "--subnet-id": ParameterMetadata(
            name="--subnet-id",
            description="Subnet ID",
            required=False,
            param_type=ParameterType.STRING,
            example="subnet-12345678",
        ),
        "--filters": ParameterMetadata(
            name="--filters",
            description="Filter results by criteria",
            required=False,
            param_type=ParameterType.JSON,
            example="Name=instance-state-name,Values=running",
        ),
    },
    "lambda": {
        "--function-name": ParameterMetadata(
            name="--function-name",
            description="Lambda function name or ARN",
            required=True,
            param_type=ParameterType.STRING,
            example="my-function",
        ),
        "--payload": ParameterMetadata(
            name="--payload",
            description="JSON payload to pass to function",
            required=False,
            param_type=ParameterType.JSON,
            example='{"key":"value"}',
        ),
        "--zip-file": ParameterMetadata(
            name="--zip-file",
            description="Deployment package (ZIP file)",
            required=False,
            param_type=ParameterType.FILE,
            example="fileb://function.zip",
        ),
        "--runtime": ParameterMetadata(
            name="--runtime",
            description="Runtime environment (python3.11, nodejs18.x, etc.)",
            required=False,
            param_type=ParameterType.STRING,
            example="python3.11",
        ),
        "--handler": ParameterMetadata(
            name="--handler",
            description="Function handler (file.method)",
            required=False,
            param_type=ParameterType.STRING,
            example="index.handler",
        ),
        "--role": ParameterMetadata(
            name="--role",
            description="IAM role ARN for function execution",
            required=True,
            param_type=ParameterType.STRING,
            example="arn:aws:iam::123456789012:role/lambda-role",
        ),
    },
    "iam": {
        "--role-name": ParameterMetadata(
            name="--role-name",
            description="IAM role name",
            required=True,
            param_type=ParameterType.STRING,
            example="MyRole",
        ),
        "--policy-arn": ParameterMetadata(
            name="--policy-arn",
            description="IAM policy ARN",
            required=True,
            param_type=ParameterType.STRING,
            example="arn:aws:iam::aws:policy/ReadOnlyAccess",
        ),
        "--user-name": ParameterMetadata(
            name="--user-name",
            description="IAM user name",
            required=True,
            param_type=ParameterType.STRING,
            example="john.doe",
        ),
        "--group-name": ParameterMetadata(
            name="--group-name",
            description="IAM group name",
            required=True,
            param_type=ParameterType.STRING,
            example="Developers",
        ),
    },
    "dynamodb": {
        "--table-name": ParameterMetadata(
            name="--table-name",
            description="DynamoDB table name",
            required=True,
            param_type=ParameterType.STRING,
            example="MyTable",
        ),
        "--key": ParameterMetadata(
            name="--key",
            description="Primary key of the item",
            required=False,
            param_type=ParameterType.JSON,
            example='{"id":{"S":"123"}}',
        ),
        "--attribute-definitions": ParameterMetadata(
            name="--attribute-definitions",
            description="Attribute definitions for table schema",
            required=False,
            param_type=ParameterType.JSON,
            example="AttributeName=id,AttributeType=S",
        ),
    },
    "cloudformation": {
        "--stack-name": ParameterMetadata(
            name="--stack-name",
            description="CloudFormation stack name",
            required=True,
            param_type=ParameterType.STRING,
            example="my-stack",
        ),
        "--template-body": ParameterMetadata(
            name="--template-body",
            description="CloudFormation template file",
            required=False,
            param_type=ParameterType.FILE,
            example="file://template.yaml",
        ),
        "--template-url": ParameterMetadata(
            name="--template-url",
            description="S3 URL to CloudFormation template",
            required=False,
            param_type=ParameterType.STRING,
            example="https://s3.amazonaws.com/bucket/template.yaml",
        ),
        "--parameters": ParameterMetadata(
            name="--parameters",
            description="Stack parameters",
            required=False,
            param_type=ParameterType.JSON,
            example="ParameterKey=KeyName,ParameterValue=MyKey",
        ),
    },
}


def get_parameter_metadata(service: str, parameter: str) -> ParameterMetadata | None:
    """
    Get metadata for a parameter.

    Args:
        service: AWS service name
        parameter: Parameter name (e.g., "--region")

    Returns:
        ParameterMetadata if found, None otherwise
    """
    # Check common parameters first
    if parameter in COMMON_PARAMETER_METADATA:
        return COMMON_PARAMETER_METADATA[parameter]

    # Check service-specific parameters
    if service in SERVICE_PARAMETER_METADATA:
        if parameter in SERVICE_PARAMETER_METADATA[service]:
            return SERVICE_PARAMETER_METADATA[service][parameter]

    return None


def format_parameter_help(metadata: ParameterMetadata) -> str:
    """
    Format parameter metadata as help text.

    Args:
        metadata: Parameter metadata

    Returns:
        Formatted help string
    """
    required_marker = " *" if metadata.required else ""
    type_info = f"[{metadata.param_type.value}]"
    example_text = f" Example: {metadata.example}" if metadata.example else ""

    return f"{metadata.name}{required_marker} {type_info} - {metadata.description}{example_text}"
