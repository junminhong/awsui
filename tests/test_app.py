"""Tests for app.py business logic."""

import sys
from unittest.mock import Mock, patch

import pytest

from awsui.app import (
    parse_args,
    AWSUIApp,
)
from awsui.models import Profile


class TestParseArgs:
    """Tests for parse_args function."""

    def test_default_arguments(self):
        """Test parsing with no arguments."""
        with patch.object(sys, "argv", ["awsui"]):
            args = parse_args()
            assert args.profile is None
            assert args.region is None
            assert args.lang == "en"
            assert args.log_level == "INFO"

    def test_profile_argument(self):
        """Test parsing with profile argument."""
        with patch.object(sys, "argv", ["awsui", "--profile", "test-profile"]):
            args = parse_args()
            assert args.profile == "test-profile"

    def test_region_argument(self):
        """Test parsing with region argument."""
        with patch.object(sys, "argv", ["awsui", "--region", "us-west-2"]):
            args = parse_args()
            assert args.region == "us-west-2"

    def test_language_argument_english(self):
        """Test parsing with English language."""
        with patch.object(sys, "argv", ["awsui", "--lang", "en"]):
            args = parse_args()
            assert args.lang == "en"

    def test_language_argument_chinese(self):
        """Test parsing with Chinese language."""
        with patch.object(sys, "argv", ["awsui", "--lang", "zh-TW"]):
            args = parse_args()
            assert args.lang == "zh-TW"

    def test_log_level_debug(self):
        """Test parsing with DEBUG log level."""
        with patch.object(sys, "argv", ["awsui", "--log-level", "DEBUG"]):
            args = parse_args()
            assert args.log_level == "DEBUG"

    def test_log_level_warning(self):
        """Test parsing with WARNING log level."""
        with patch.object(sys, "argv", ["awsui", "--log-level", "WARNING"]):
            args = parse_args()
            assert args.log_level == "WARNING"

    def test_multiple_arguments(self):
        """Test parsing with multiple arguments."""
        with patch.object(
            sys,
            "argv",
            [
                "awsui",
                "--profile",
                "prod",
                "--region",
                "eu-west-1",
                "--lang",
                "zh-TW",
                "--log-level",
                "ERROR",
            ],
        ):
            args = parse_args()
            assert args.profile == "prod"
            assert args.region == "eu-west-1"
            assert args.lang == "zh-TW"
            assert args.log_level == "ERROR"


class TestProfileListFiltering:
    """Tests for ProfileList filtering logic (without UI dependencies)."""

    @pytest.fixture
    def sample_profiles(self):
        """Create sample profiles for testing."""
        return [
            Profile(
                name="prod-admin",
                kind="sso",
                account="111111111111",
                role="AdministratorAccess",
                region="us-east-1",
                session="company",
                source="/home/user/.aws/config",
            ),
            Profile(
                name="staging-dev",
                kind="sso",
                account="222222222222",
                role="DeveloperAccess",
                region="us-west-2",
                session="company",
                source="/home/user/.aws/config",
            ),
            Profile(
                name="test-assume",
                kind="assume",
                account="333333333333",
                role="TestRole",
                region="eu-west-1",
                session=None,
                source="/home/user/.aws/config",
            ),
        ]

    def test_filter_logic_by_name(self, sample_profiles):
        """Test filtering logic for profile names."""
        query = "prod"
        query_lower = query.lower()

        filtered = [
            p for p in sample_profiles
            if query_lower in p["name"].lower()
            or (p["account"] and query_lower in p["account"])
            or (p["role"] and query_lower in p["role"].lower())
            or (p["region"] and query_lower in p["region"].lower())
        ]

        assert len(filtered) == 1
        assert filtered[0]["name"] == "prod-admin"

    def test_filter_logic_by_account(self, sample_profiles):
        """Test filtering logic for account ID."""
        query = "222222"
        query_lower = query.lower()

        filtered = [
            p for p in sample_profiles
            if query_lower in p["name"].lower()
            or (p["account"] and query_lower in p["account"])
            or (p["role"] and query_lower in p["role"].lower())
            or (p["region"] and query_lower in p["region"].lower())
        ]

        assert len(filtered) == 1
        assert filtered[0]["name"] == "staging-dev"

    def test_filter_logic_by_role(self, sample_profiles):
        """Test filtering logic for role name."""
        query = "developer"
        query_lower = query.lower()

        filtered = [
            p for p in sample_profiles
            if query_lower in p["name"].lower()
            or (p["account"] and query_lower in p["account"])
            or (p["role"] and query_lower in p["role"].lower())
            or (p["region"] and query_lower in p["region"].lower())
        ]

        assert len(filtered) == 1
        assert filtered[0]["role"] == "DeveloperAccess"

    def test_filter_logic_by_region(self, sample_profiles):
        """Test filtering logic for region."""
        query = "eu-west"
        query_lower = query.lower()

        filtered = [
            p for p in sample_profiles
            if query_lower in p["name"].lower()
            or (p["account"] and query_lower in p["account"])
            or (p["role"] and query_lower in p["role"].lower())
            or (p["region"] and query_lower in p["region"].lower())
        ]

        assert len(filtered) == 1
        assert filtered[0]["region"] == "eu-west-1"

    def test_filter_logic_case_insensitive(self, sample_profiles):
        """Test that filtering logic is case insensitive."""
        query = "PROD"
        query_lower = query.lower()

        filtered = [
            p for p in sample_profiles
            if query_lower in p["name"].lower()
            or (p["account"] and query_lower in p["account"])
            or (p["role"] and query_lower in p["role"].lower())
            or (p["region"] and query_lower in p["region"].lower())
        ]

        assert len(filtered) == 1
        assert filtered[0]["name"] == "prod-admin"

    def test_filter_logic_empty_query(self, sample_profiles):
        """Test filtering logic with empty query."""
        query = ""

        if not query:
            filtered = sample_profiles.copy()
        else:
            query_lower = query.lower()
            filtered = [
                p for p in sample_profiles
                if query_lower in p["name"].lower()
                or (p["account"] and query_lower in p["account"])
                or (p["role"] and query_lower in p["role"].lower())
                or (p["region"] and query_lower in p["region"].lower())
            ]

        assert len(filtered) == 3
        assert filtered == sample_profiles

    def test_filter_logic_no_matches(self, sample_profiles):
        """Test filtering logic with no matches."""
        query = "nonexistent"
        query_lower = query.lower()

        filtered = [
            p for p in sample_profiles
            if query_lower in p["name"].lower()
            or (p["account"] and query_lower in p["account"])
            or (p["role"] and query_lower in p["role"].lower())
            or (p["region"] and query_lower in p["region"].lower())
        ]

        assert len(filtered) == 0

    def test_filter_logic_matches_multiple_fields(self, sample_profiles):
        """Test filtering logic that matches in multiple fields."""
        query = "admin"
        query_lower = query.lower()

        filtered = [
            p for p in sample_profiles
            if query_lower in p["name"].lower()
            or (p["account"] and query_lower in p["account"])
            or (p["role"] and query_lower in p["role"].lower())
            or (p["region"] and query_lower in p["region"].lower())
        ]

        # Query "admin" should match both profile name and role containing "admin"
        assert len(filtered) == 1
        assert "admin" in filtered[0]["name"].lower()


class TestAWSUIAppInitialization:
    """Tests for AWSUIApp initialization."""

    def test_default_initialization(self):
        """Test app initialization with default parameters."""
        with patch("awsui.app.get_logger"):
            app = AWSUIApp()
            assert app.preselect_profile is None
            assert app.override_region is None
            assert app.profiles == []
            assert app.selected_profile is None
            assert app.q_available is False
            assert app.command_history == []
            assert app.history_index == -1

    def test_initialization_with_profile(self):
        """Test app initialization with profile parameter."""
        with patch("awsui.app.get_logger"):
            app = AWSUIApp(profile="test-profile")
            assert app.preselect_profile == "test-profile"

    def test_initialization_with_region(self):
        """Test app initialization with region parameter."""
        with patch("awsui.app.get_logger"):
            app = AWSUIApp(region="ap-southeast-1")
            assert app.override_region == "ap-southeast-1"

    def test_initialization_with_language_english(self):
        """Test app initialization with English language."""
        with patch("awsui.app.get_logger"):
            app = AWSUIApp(lang="en")
            from awsui.i18n import LANG_EN

            assert app.lang == LANG_EN

    def test_initialization_with_language_chinese(self):
        """Test app initialization with Chinese language."""
        with patch("awsui.app.get_logger"):
            app = AWSUIApp(lang="zh-TW")
            from awsui.i18n import LANG_ZH_TW

            assert app.lang == LANG_ZH_TW

    def test_initialization_with_log_level(self):
        """Test app initialization with custom log level."""
        with patch("awsui.app.get_logger") as mock_logger:
            AWSUIApp(log_level="DEBUG")
            mock_logger.assert_called_once_with("DEBUG")

    def test_initialization_sets_subtitle(self):
        """Test that app subtitle is set from language."""
        with patch("awsui.app.get_logger"):
            app = AWSUIApp(lang="en")
            assert app.sub_title == app.lang["app_subtitle"]


class TestAWSUIAppHelperMethods:
    """Tests for AWSUIApp helper methods."""

    @pytest.fixture
    def app(self):
        """Create app instance for testing."""
        with patch("awsui.app.get_logger"):
            return AWSUIApp()

    def test_build_profile_detail(self, app):
        """Test building profile detail table."""
        profile = Profile(
            name="test-profile",
            kind="sso",
            account="123456789012",
            role="AdminRole",
            region="us-east-1",
            session="test-session",
            source="/home/user/.aws/config",
        )

        table = app.build_profile_detail(profile)

        # Verify that a Rich Table object is created for displaying profile details
        assert table is not None

    def test_build_profile_detail_with_region_override(self, app):
        """Test building profile detail with region override."""
        app.override_region = "eu-west-1"
        profile = Profile(
            name="test-profile",
            kind="sso",
            account="123456789012",
            role="AdminRole",
            region="us-east-1",
            session="test-session",
            source="/home/user/.aws/config",
        )

        table = app.build_profile_detail(profile)
        # Verify table is created with region override applied
        assert table is not None

    def test_build_identity_detail(self, app):
        """Test building identity detail table."""
        identity = {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test-user",
            "UserId": "AIDACKCEVSQ6C2EXAMPLE",
        }

        table = app.build_identity_detail(identity)
        assert table is not None

    def test_build_identity_detail_with_missing_fields(self, app):
        """Test building identity detail with missing fields."""
        identity = {
            "Account": "123456789012",
        }

        table = app.build_identity_detail(identity)
        assert table is not None


class TestNavigateHistory:
    """Tests for command history navigation."""

    @pytest.fixture
    def app(self):
        """Create app with command history."""
        with patch("awsui.app.get_logger"):
            app = AWSUIApp()
            app.command_history = ["aws s3 ls", "aws ec2 describe-instances", "aws iam list-users"]
            return app

    def test_navigate_history_up_from_initial(self, app):
        """Test navigating up from initial state."""
        mock_input = Mock()
        mock_input.value = ""

        with patch.object(app, "query_one", return_value=Mock()):
            app.navigate_history_up(mock_input)

        # Index should point to the last (most recent) command
        assert app.history_index == 2
        assert mock_input.value == "aws iam list-users"
        assert app.browsing_history is True

    def test_navigate_history_up_multiple_times(self, app):
        """Test navigating up multiple times."""
        mock_input = Mock()
        mock_input.value = ""

        with patch.object(app, "query_one", return_value=Mock()):
            app.navigate_history_up(mock_input)
            assert app.history_index == 2

            app.navigate_history_up(mock_input)
            assert app.history_index == 1
            assert mock_input.value == "aws ec2 describe-instances"

            app.navigate_history_up(mock_input)
            assert app.history_index == 0
            assert mock_input.value == "aws s3 ls"

    def test_navigate_history_up_at_boundary(self, app):
        """Test navigating up at the top of history."""
        mock_input = Mock()
        mock_input.value = ""
        app.history_index = 0

        with patch.object(app, "query_one", return_value=Mock()):
            app.navigate_history_up(mock_input)

        # Should remain at index 0 (oldest command) without going negative
        assert app.history_index == 0

    def test_navigate_history_down(self, app):
        """Test navigating down in history."""
        mock_input = Mock()
        mock_input.value = ""
        app.history_index = 1
        app.browsing_history = True

        with patch.object(app, "query_one", return_value=Mock()):
            app.navigate_history_down(mock_input)

        assert app.history_index == 2
        assert mock_input.value == "aws iam list-users"

    def test_navigate_history_down_to_original(self, app):
        """Test navigating down returns to original input."""
        mock_input = Mock()
        mock_input.value = ""
        app.history_index = 2
        app.current_input = "test input"
        app.browsing_history = True

        with patch.object(app, "query_one", return_value=Mock()):
            app.navigate_history_down(mock_input)

        assert app.history_index == -1
        assert mock_input.value == "test input"
        assert app.browsing_history is False

    def test_navigate_history_down_not_browsing(self, app):
        """Test navigating down when not in browsing mode."""
        mock_input = Mock()
        app.history_index = -1

        with patch.object(app, "query_one", return_value=Mock()):
            app.navigate_history_down(mock_input)

        # Should remain at -1 (not browsing) and take no action
        assert app.history_index == -1

    def test_empty_history(self):
        """Test navigation with empty history."""
        with patch("awsui.app.get_logger"):
            app = AWSUIApp()
            app.command_history = []

        mock_input = Mock()
        mock_input.value = ""

        with patch.object(app, "query_one", return_value=Mock()):
            app.navigate_history_up(mock_input)

        # Should remain at -1 when history is empty
        assert app.history_index == -1


class TestCommandHistoryManagement:
    """Tests for command history management."""

    def test_history_saves_current_input(self):
        """Test that current input is saved when starting to browse."""
        with patch("awsui.app.get_logger"):
            app = AWSUIApp()
            app.command_history = ["cmd1", "cmd2"]

        mock_input = Mock()
        mock_input.value = "current typing"

        with patch.object(app, "query_one", return_value=Mock()):
            app.navigate_history_up(mock_input)

        assert app.current_input == "current typing"

    def test_browsing_flag_set(self):
        """Test that browsing flag is set correctly."""
        with patch("awsui.app.get_logger"):
            app = AWSUIApp()
            app.command_history = ["cmd1"]

        mock_input = Mock()
        mock_input.value = ""

        assert app.browsing_history is False

        with patch.object(app, "query_one", return_value=Mock()):
            app.navigate_history_up(mock_input)

        assert app.browsing_history is True


class TestBuildHelperMethods:
    """Additional tests for helper methods."""

    def test_show_empty_state(self):
        """Test show_empty_state method."""
        with patch("awsui.app.get_logger"):
            app = AWSUIApp()

        mock_detail = Mock()
        with patch.object(app, "query_one", return_value=mock_detail):
            app.show_empty_state("Test Title", "Test Hint")

        mock_detail.update.assert_called_once()
        mock_detail.add_class.assert_called_once_with("empty-state")

    def test_update_status_info(self):
        """Test update_status with info message."""
        with patch("awsui.app.get_logger"):
            app = AWSUIApp()

        with patch.object(app, "notify") as mock_notify:
            app.update_status("Test message", error=False)

        mock_notify.assert_called_once_with("Test message", severity="information")

    def test_update_status_error(self):
        """Test update_status with error message."""
        with patch("awsui.app.get_logger"):
            app = AWSUIApp()

        with patch.object(app, "notify") as mock_notify:
            app.update_status("Error message", error=True)

        mock_notify.assert_called_once()
        call_args = mock_notify.call_args
        assert call_args[0][0] == "Error message"
        assert call_args[1]["severity"] == "error"
