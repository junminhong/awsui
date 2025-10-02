"""Dynamic AWS resource suggester for intelligent autocomplete."""

import subprocess
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import threading


class ResourceCache:
    """Thread-safe cache for AWS resource suggestions with TTL."""

    def __init__(self, ttl_seconds: int = 300):
        """
        Initialize cache.

        Args:
            ttl_seconds: Time-to-live for cached entries (default: 5 minutes)
        """
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, tuple[datetime, List[str]]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[List[str]]:
        """Get cached value if still valid."""
        with self._lock:
            if key in self._cache:
                timestamp, value = self._cache[key]
                if datetime.now() - timestamp < timedelta(seconds=self.ttl_seconds):
                    return value
                else:
                    del self._cache[key]
        return None

    def set(self, key: str, value: List[str]) -> None:
        """Set cached value with current timestamp."""
        with self._lock:
            self._cache[key] = (datetime.now(), value)

    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()


class ResourceSuggester:
    """Suggests AWS resource values by querying AWS CLI."""

    def __init__(self, profile: Optional[str] = None, region: Optional[str] = None):
        """
        Initialize resource suggester.

        Args:
            profile: AWS profile to use for queries
            region: AWS region to use for queries
        """
        self.profile = profile
        self.region = region
        self.cache = ResourceCache(ttl_seconds=300)  # 5 minute cache

    def _run_aws_command(self, command: List[str], timeout: int = 10) -> Optional[str]:
        """
        Run AWS CLI command and return output.

        Args:
            command: AWS CLI command as list of arguments
            timeout: Command timeout in seconds

        Returns:
            Command output or None if failed
        """
        try:
            if self.profile:
                command.extend(["--profile", self.profile])
            if self.region:
                command.extend(["--region", self.region])

            command.extend(["--output", "json"])

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            if result.returncode == 0:
                return result.stdout
            else:
                return None

        except (subprocess.TimeoutExpired, Exception):
            return None

    def get_ec2_instance_ids(self) -> List[str]:
        """Get list of EC2 instance IDs."""
        cache_key = f"ec2:instances:{self.profile}:{self.region}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        output = self._run_aws_command(
            ["aws", "ec2", "describe-instances", "--query", "Reservations[].Instances[].InstanceId"]
        )

        if output:
            try:
                instance_ids = json.loads(output)
                self.cache.set(cache_key, instance_ids)
                return instance_ids
            except json.JSONDecodeError:
                pass

        return []

    def get_s3_buckets(self) -> List[str]:
        """Get list of S3 bucket names."""
        cache_key = f"s3:buckets:{self.profile}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        output = self._run_aws_command(
            ["aws", "s3api", "list-buckets", "--query", "Buckets[].Name"]
        )

        if output:
            try:
                buckets = json.loads(output)
                self.cache.set(cache_key, buckets)
                return buckets
            except json.JSONDecodeError:
                pass

        return []

    def get_lambda_functions(self) -> List[str]:
        """Get list of Lambda function names."""
        cache_key = f"lambda:functions:{self.profile}:{self.region}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        output = self._run_aws_command(
            ["aws", "lambda", "list-functions", "--query", "Functions[].FunctionName"]
        )

        if output:
            try:
                functions = json.loads(output)
                self.cache.set(cache_key, functions)
                return functions
            except json.JSONDecodeError:
                pass

        return []

    def get_dynamodb_tables(self) -> List[str]:
        """Get list of DynamoDB table names."""
        cache_key = f"dynamodb:tables:{self.profile}:{self.region}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        output = self._run_aws_command(
            ["aws", "dynamodb", "list-tables", "--query", "TableNames"]
        )

        if output:
            try:
                tables = json.loads(output)
                self.cache.set(cache_key, tables)
                return tables
            except json.JSONDecodeError:
                pass

        return []

    def get_iam_roles(self) -> List[str]:
        """Get list of IAM role names."""
        cache_key = f"iam:roles:{self.profile}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        output = self._run_aws_command(
            ["aws", "iam", "list-roles", "--query", "Roles[].RoleName"]
        )

        if output:
            try:
                roles = json.loads(output)
                self.cache.set(cache_key, roles)
                return roles
            except json.JSONDecodeError:
                pass

        return []

    def get_security_groups(self) -> List[str]:
        """Get list of security group IDs."""
        cache_key = f"ec2:security-groups:{self.profile}:{self.region}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        output = self._run_aws_command(
            ["aws", "ec2", "describe-security-groups", "--query", "SecurityGroups[].GroupId"]
        )

        if output:
            try:
                sgs = json.loads(output)
                self.cache.set(cache_key, sgs)
                return sgs
            except json.JSONDecodeError:
                pass

        return []

    def get_vpcs(self) -> List[str]:
        """Get list of VPC IDs."""
        cache_key = f"ec2:vpcs:{self.profile}:{self.region}"
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached

        output = self._run_aws_command(
            ["aws", "ec2", "describe-vpcs", "--query", "Vpcs[].VpcId"]
        )

        if output:
            try:
                vpcs = json.loads(output)
                self.cache.set(cache_key, vpcs)
                return vpcs
            except json.JSONDecodeError:
                pass

        return []

    def get_suggestions_for_parameter(
        self, service: str, command: str, parameter: str
    ) -> Optional[List[str]]:
        """
        Get resource suggestions for a specific parameter.

        Args:
            service: AWS service (e.g., "ec2", "s3")
            command: Service command
            parameter: Parameter name (e.g., "--instance-ids")

        Returns:
            List of suggested values or None if not applicable
        """
        param_map = {
            "--instance-ids": self.get_ec2_instance_ids,
            "--instance-id": self.get_ec2_instance_ids,
            "--function-name": self.get_lambda_functions,
            "--table-name": self.get_dynamodb_tables,
            "--role-name": self.get_iam_roles,
            "--security-group-ids": self.get_security_groups,
            "--vpc-id": self.get_vpcs,
        }

        if service == "s3" and command in ["cp", "ls", "sync", "rm", "rb"]:
            return self.get_s3_buckets()

        if parameter in param_map:
            return param_map[parameter]()

        return None
