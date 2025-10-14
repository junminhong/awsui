"""Tests for AWS CLI cheatsheet data structure."""


from awsui.cheatsheet import (
    AWS_CLI_CHEATSHEET,
    AWS_CLI_COMMANDS,
    COMMAND_CATEGORIES,
)


class TestCheatsheetStructure:
    """Tests for cheatsheet data structure integrity."""

    def test_cheatsheet_not_empty(self):
        """Test that cheatsheet contains data."""
        assert len(AWS_CLI_CHEATSHEET) > 0

    def test_cheatsheet_has_expected_services(self):
        """Test that cheatsheet includes common AWS services."""
        expected_services = ["S3", "EC2", "Lambda", "IAM", "CloudFormation"]

        for service in expected_services:
            assert service in AWS_CLI_CHEATSHEET, f"{service} not found in cheatsheet"

    def test_all_categories_have_commands(self):
        """Test that all categories have at least one command."""
        for category, commands in AWS_CLI_CHEATSHEET.items():
            assert len(commands) > 0, f"Category {category} has no commands"

    def test_all_commands_are_strings(self):
        """Test that all commands are strings."""
        for category, commands in AWS_CLI_CHEATSHEET.items():
            for cmd in commands:
                assert isinstance(cmd, str), f"Command in {category} is not a string"

    def test_all_commands_start_with_aws(self):
        """Test that all commands start with 'aws'."""
        for category, commands in AWS_CLI_CHEATSHEET.items():
            for cmd in commands:
                assert cmd.startswith("aws "), f"Command '{cmd}' does not start with 'aws '"

    def test_no_duplicate_commands_in_category(self):
        """Test that there are no duplicate commands within a category."""
        for category, commands in AWS_CLI_CHEATSHEET.items():
            unique_commands = set(commands)
            assert len(unique_commands) == len(
                commands
            ), f"Category {category} has duplicate commands"


class TestCommandsList:
    """Tests for flattened commands list."""

    def test_commands_list_not_empty(self):
        """Test that commands list is not empty."""
        assert len(AWS_CLI_COMMANDS) > 0

    def test_commands_list_flattened_correctly(self):
        """Test that commands list contains all commands from cheatsheet."""
        expected_count = sum(len(cmds) for cmds in AWS_CLI_CHEATSHEET.values())
        assert len(AWS_CLI_COMMANDS) == expected_count

    def test_all_commands_in_list_are_strings(self):
        """Test that all commands in the list are strings."""
        for cmd in AWS_CLI_COMMANDS:
            assert isinstance(cmd, str)

    def test_all_commands_in_list_start_with_aws(self):
        """Test that all commands in list start with 'aws'."""
        for cmd in AWS_CLI_COMMANDS:
            assert cmd.startswith("aws ")


class TestCommandCategories:
    """Tests for command-to-category mapping."""

    def test_categories_dict_not_empty(self):
        """Test that categories dict is not empty."""
        assert len(COMMAND_CATEGORIES) > 0

    def test_all_commands_have_category(self):
        """Test that all commands have a category mapping."""
        for cmd in AWS_CLI_COMMANDS:
            assert cmd in COMMAND_CATEGORIES, f"Command '{cmd}' has no category"

    def test_category_mapping_matches_cheatsheet(self):
        """Test that category mappings match the cheatsheet."""
        for category, commands in AWS_CLI_CHEATSHEET.items():
            for cmd in commands:
                assert (
                    COMMAND_CATEGORIES[cmd] == category
                ), f"Command '{cmd}' category mismatch"

    def test_no_orphaned_categories(self):
        """Test that all categories in mapping exist in cheatsheet."""
        cheatsheet_categories = set(AWS_CLI_CHEATSHEET.keys())
        mapping_categories = set(COMMAND_CATEGORIES.values())

        assert mapping_categories.issubset(
            cheatsheet_categories
        ), "Found categories in mapping not in cheatsheet"


class TestSpecificServices:
    """Tests for specific service command coverage."""

    def test_s3_commands_present(self):
        """Test that S3 commands are present."""
        s3_commands = AWS_CLI_CHEATSHEET.get("S3", [])
        assert len(s3_commands) >= 5
        assert any("s3 ls" in cmd for cmd in s3_commands)
        assert any("s3 cp" in cmd for cmd in s3_commands)

    def test_ec2_commands_present(self):
        """Test that EC2 commands are present."""
        ec2_commands = AWS_CLI_CHEATSHEET.get("EC2", [])
        assert len(ec2_commands) >= 5
        assert any("describe-instances" in cmd for cmd in ec2_commands)
        assert any("start-instances" in cmd for cmd in ec2_commands)

    def test_lambda_commands_present(self):
        """Test that Lambda commands are present."""
        lambda_commands = AWS_CLI_CHEATSHEET.get("Lambda", [])
        assert len(lambda_commands) >= 3
        assert any("list-functions" in cmd for cmd in lambda_commands)

    def test_iam_commands_present(self):
        """Test that IAM commands are present."""
        iam_commands = AWS_CLI_CHEATSHEET.get("IAM", [])
        assert len(iam_commands) >= 3
        assert any("list-users" in cmd for cmd in iam_commands)
        assert any("list-roles" in cmd for cmd in iam_commands)

    def test_cloudformation_commands_present(self):
        """Test that CloudFormation commands are present."""
        cf_commands = AWS_CLI_CHEATSHEET.get("CloudFormation", [])
        assert len(cf_commands) >= 3
        assert any("list-stacks" in cmd for cmd in cf_commands)

    def test_sts_identity_commands_present(self):
        """Test that STS/Identity commands are present."""
        # Check if there's an Identity or STS category
        identity_categories = [
            key for key in AWS_CLI_CHEATSHEET.keys()
            if "identity" in key.lower() or "sts" in key.lower()
        ]
        assert len(identity_categories) > 0

        # Check for get-caller-identity command
        identity_commands = []
        for cat in identity_categories:
            identity_commands.extend(AWS_CLI_CHEATSHEET[cat])

        assert any("get-caller-identity" in cmd for cmd in identity_commands)


class TestCommandFormat:
    """Tests for command format consistency."""

    def test_commands_use_proper_service_names(self):
        """Test that commands use lowercase service names."""
        for cmd in AWS_CLI_COMMANDS:
            parts = cmd.split()
            if len(parts) >= 2:
                service = parts[1]
                # Service names should be lowercase (except special cases)
                assert service.islower() or service.isdigit() or "-" in service

    def test_commands_have_operations(self):
        """Test that commands have operations (not just 'aws service')."""
        # Most commands should have at least 3 parts: aws, service, operation
        commands_with_operations = [
            cmd for cmd in AWS_CLI_COMMANDS if len(cmd.split()) >= 3
        ]
        # At least 80% of commands should have operations
        assert len(commands_with_operations) >= len(AWS_CLI_COMMANDS) * 0.8

    def test_parameter_format(self):
        """Test that parameters use proper format."""
        for cmd in AWS_CLI_COMMANDS:
            if "--" in cmd:
                # Parameters should start with --
                params = [part for part in cmd.split() if part.startswith("--")]
                for param in params:
                    # Parameters should be lowercase with hyphens
                    param_name = param[2:]  # Remove --
                    if "=" not in param_name:  # Skip value assignments
                        assert param_name.replace("-", "").replace("_", "").isalnum()


class TestCheatsheetCoverage:
    """Tests for cheatsheet coverage of important AWS services."""

    def test_has_compute_services(self):
        """Test coverage of compute services."""
        compute_services = ["EC2", "Lambda", "ECS", "EKS"]
        for service in compute_services:
            assert any(
                service.lower() in key.lower() for key in AWS_CLI_CHEATSHEET.keys()
            ), f"Missing compute service: {service}"

    def test_has_storage_services(self):
        """Test coverage of storage services."""
        storage_services = ["S3"]
        for service in storage_services:
            assert any(
                service.lower() in key.lower() for key in AWS_CLI_CHEATSHEET.keys()
            ), f"Missing storage service: {service}"

    def test_has_database_services(self):
        """Test coverage of database services."""
        database_services = ["RDS", "DynamoDB"]
        for service in database_services:
            assert any(
                service.lower() in key.lower() for key in AWS_CLI_CHEATSHEET.keys()
            ), f"Missing database service: {service}"

    def test_has_networking_services(self):
        """Test coverage of networking services."""
        networking_services = ["Route53"]
        for service in networking_services:
            assert any(
                service.lower() in key.lower() for key in AWS_CLI_CHEATSHEET.keys()
            ), f"Missing networking service: {service}"

    def test_has_management_services(self):
        """Test coverage of management services."""
        management_services = ["CloudFormation", "CloudWatch"]
        for service in management_services:
            assert any(
                service.lower() in key.lower() for key in AWS_CLI_CHEATSHEET.keys()
            ), f"Missing management service: {service}"
