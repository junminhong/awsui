"""Tests for CommandAutocomplete widget."""

import pytest
from awsui.autocomplete import CommandAutocomplete
from awsui.command_parser import CompletionContext


@pytest.fixture
def autocomplete():
    """Create autocomplete instance for testing."""
    commands = [
        "aws s3 ls",
        "aws s3 cp",
        "aws ec2 describe-instances",
        "aws lambda list-functions",
    ]
    categories = {
        "aws s3 ls": "s3/storage",
        "aws s3 cp": "s3/storage",
        "aws ec2 describe-instances": "ec2/compute",
        "aws lambda list-functions": "lambda/compute",
    }
    ac = CommandAutocomplete(commands, categories)
    return ac


def test_filter_commands_with_trailing_space(autocomplete):
    """Test filter_commands works with trailing space (strip bug fix)."""
    autocomplete.filter_commands("aws ", 4)
    assert autocomplete.display is True
    assert len(autocomplete.filtered_commands) > 0


def test_filter_commands_without_strip(autocomplete):
    """Test filter_commands doesn't strip query before checking startswith."""
    autocomplete.filter_commands("aws ", 4)
    # Should use intelligent filter, not fuzzy
    assert autocomplete.display is True


def test_smart_insert_full_command_replacement(autocomplete):
    """Test smart_insert replaces entire input for full commands."""
    current_value = "aws s3"
    cursor_pos = 6
    selection = "aws s3 ls"

    new_value, new_cursor = autocomplete.smart_insert_selection(
        current_value, cursor_pos, selection
    )

    assert new_value == "aws s3 ls"
    assert new_cursor == 9
    assert new_value.count("aws") == 1


def test_smart_insert_token_insertion(autocomplete):
    """Test smart_insert correctly inserts token at cursor position."""
    current_value = "aws s3 "
    cursor_pos = 7
    selection = "ls"

    new_value, new_cursor = autocomplete.smart_insert_selection(
        current_value, cursor_pos, selection
    )

    assert new_value == "aws s3 ls "
    assert new_cursor == 10


def test_smart_insert_replaces_partial_token(autocomplete):
    """Test smart_insert replaces partial token correctly."""
    current_value = "aws s3 l"
    cursor_pos = 8
    selection = "ls"

    new_value, new_cursor = autocomplete.smart_insert_selection(
        current_value, cursor_pos, selection
    )

    assert new_value == "aws s3 ls "
    assert new_value.endswith("ls ")


def test_smart_insert_cursor_in_middle_of_token(autocomplete):
    """Test smart_insert with cursor in middle of token."""
    current_value = "aws ec2 describe --instance-ids i-123"
    cursor_pos = 15  # In middle of "describe"
    selection = "describe-instances"

    new_value, new_cursor = autocomplete.smart_insert_selection(
        current_value, cursor_pos, selection
    )

    # Should replace entire "describe" token
    assert "describe-instances" in new_value
    assert "describe" not in new_value or "describe-instances" in new_value
    # Parameters should be preserved
    assert "--instance-ids i-123" in new_value


def test_smart_insert_preserves_text_after_token(autocomplete):
    """Test smart_insert preserves text after current token."""
    current_value = "aws s3 ls --region us-east-1"
    cursor_pos = 8  # After "ls"
    selection = "cp"

    new_value, new_cursor = autocomplete.smart_insert_selection(
        current_value, cursor_pos, selection
    )

    assert "--region us-east-1" in new_value
    assert "cp" in new_value


def test_fuzzy_match_exact_substring(autocomplete):
    """Test fuzzy matching with exact substring."""
    matched, score = autocomplete.fuzzy_match("aws s3 ls", "s3")
    assert matched is True
    assert score > 0


def test_fuzzy_match_scattered_letters(autocomplete):
    """Test fuzzy matching with scattered letters."""
    matched, score = autocomplete.fuzzy_match("describe-instances", "dscins")
    assert matched is True


def test_intelligent_filter_calls_parser(autocomplete):
    """Test intelligent filter uses parser for suggestions."""
    autocomplete.filter_commands("aws s3 ", 7)
    assert autocomplete.display is True
    # Should show s3 commands
    assert len(autocomplete.filtered_commands) > 0


def test_filter_commands_min_length(autocomplete):
    """Test filter_commands requires minimum length."""
    autocomplete.filter_commands("a", 1)
    assert autocomplete.display is False
    assert autocomplete.filtered_commands == []


def test_filter_commands_empty_input(autocomplete):
    """Test filter_commands with empty input."""
    autocomplete.filter_commands("", 0)
    assert autocomplete.display is False
    assert autocomplete.filtered_commands == []


def test_get_selected_command(autocomplete):
    """Test getting currently selected command."""
    autocomplete.filter_commands("aws s3 ", 7)
    autocomplete.highlighted = 0
    selected = autocomplete.get_selected_command()
    assert selected is not None
    assert selected in autocomplete.filtered_commands


def test_move_cursor_down(autocomplete):
    """Test moving selection down."""
    autocomplete.filter_commands("aws s3 ", 7)
    autocomplete.highlighted = 0
    initial = autocomplete.highlighted
    autocomplete.move_cursor_down()
    assert autocomplete.highlighted == initial + 1


def test_move_cursor_up(autocomplete):
    """Test moving selection up."""
    autocomplete.filter_commands("aws s3 ", 7)
    autocomplete.highlighted = 2
    autocomplete.move_cursor_up()
    assert autocomplete.highlighted == 1


def test_move_cursor_up_boundary(autocomplete):
    """Test moving selection up doesn't go below 0."""
    autocomplete.filter_commands("aws s3 ", 7)
    autocomplete.highlighted = 0
    autocomplete.move_cursor_up()
    assert autocomplete.highlighted == 0


def test_move_cursor_down_boundary(autocomplete):
    """Test moving selection down doesn't exceed list."""
    autocomplete.filter_commands("aws s3 ", 7)
    max_idx = len(autocomplete.filtered_commands) - 1
    autocomplete.highlighted = max_idx
    autocomplete.move_cursor_down()
    assert autocomplete.highlighted == max_idx
