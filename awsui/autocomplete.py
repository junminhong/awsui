"""Custom autocomplete widget for AWS CLI commands."""

from textual.widgets import OptionList
from textual.widgets.option_list import Option
from textual.message import Message

from .command_parser import AWSCommandParser, CompletionContext
from .parameter_metadata import get_parameter_metadata, format_parameter_help
from .resource_suggester import ResourceSuggester


class CommandAutocomplete(OptionList):
    """Enhanced autocomplete with fuzzy matching and highlighting."""

    class CommandSelected(Message):
        """Message sent when a command is selected from autocomplete."""

        def __init__(self, command: str) -> None:
            self.command = command
            super().__init__()

    def __init__(self, commands: list[str], command_categories: dict[str, str], *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.all_commands = commands
        self.command_categories = command_categories
        self.filtered_commands: list[str] = []
        self.display = False
        self.can_focus = False

        self.parser = AWSCommandParser()
        self.use_intelligent_autocomplete = True
        self.resource_suggester: ResourceSuggester | None = None
        self.enable_resource_suggestions = True

    def set_aws_context(self, profile: str | None, region: str | None) -> None:
        """Set AWS profile and region for resource suggestions."""
        if self.enable_resource_suggestions:
            self.resource_suggester = ResourceSuggester(profile, region)

    def fuzzy_match(self, text: str, query: str) -> tuple[bool, int]:
        """
        Check if query fuzzy matches text with scoring.
        Returns (matched, score) where higher score = better match.
        """
        text_lower = text.lower()
        query_lower = query.lower()

        if query_lower in text_lower:
            position = text_lower.find(query_lower)
            score = 100 - (position * 2)
            return (True, max(score, 80))

        text_idx = 0
        query_idx = 0
        matches = 0

        while text_idx < len(text_lower) and query_idx < len(query_lower):
            if text_lower[text_idx] == query_lower[query_idx]:
                matches += 1
                query_idx += 1
            text_idx += 1

        if query_idx == len(query_lower):
            score = int((matches / len(text_lower)) * 60)
            return (True, max(score, 20))

        return (False, 0)

    def highlight_match(self, text: str, query: str) -> str:
        """Highlight matching substring in text."""
        if not query:
            return text

        lower_text = text.lower()
        lower_query = query.lower()
        start = lower_text.find(lower_query)

        if start >= 0:
            end = start + len(query)
            return f"{text[:start]}[bold yellow]{text[start:end]}[/]{text[end:]}"

        return text

    def filter_commands(self, query: str, cursor_pos: int | None = None) -> None:
        """
        Filter commands with intelligent or fuzzy matching.

        Args:
            query: The command line input
            cursor_pos: Cursor position in the input (for intelligent parsing)
        """
        if not query or len(query) < 2:
            self.display = False
            self.filtered_commands = []
            self.clear_options()
            return

        if self.use_intelligent_autocomplete and query.startswith("aws "):
            self._intelligent_filter(query, cursor_pos)
        else:
            self._fuzzy_filter(query)

    def _intelligent_filter(self, query: str, cursor_pos: int | None = None) -> None:
        """Use intelligent parser for context-aware suggestions."""
        parsed = self.parser.parse(query, cursor_pos)
        suggestions = self.parser.get_suggestions(parsed)

        if (parsed.current_context == CompletionContext.PARAMETER_VALUE and
                self.resource_suggester and parsed.service and parsed.command):
            last_param = None
            for param, value in reversed(list(parsed.parameters.items())):
                if value is None:
                    last_param = param
                    break

            if last_param:
                resource_suggestions = self.resource_suggester.get_suggestions_for_parameter(
                    parsed.service, parsed.command, last_param
                )
                if resource_suggestions:
                    query_lower = parsed.current_token.lower()
                    filtered_resources = [
                        r for r in resource_suggestions
                        if query_lower in r.lower()
                    ]
                    if filtered_resources:
                        suggestions = filtered_resources[:10]

        if suggestions:
            self.filtered_commands = suggestions[:10]

            self.clear_options()
            for suggestion in self.filtered_commands:
                if parsed.current_context == CompletionContext.SERVICE:
                    badge = "[dim cyan]SVC[/dim cyan]"
                    description = ""
                elif parsed.current_context == CompletionContext.COMMAND:
                    badge = "[dim green]CMD[/dim green]"
                    description = ""
                elif parsed.current_context == CompletionContext.PARAMETER:
                    badge = "[dim yellow]OPT[/dim yellow]"
                    metadata = get_parameter_metadata(parsed.service, suggestion)
                    if metadata:
                        required_mark = "*" if metadata.required else ""
                        description = f" [{metadata.param_type.value}]{required_mark} {metadata.description[:40]}"
                    else:
                        description = ""
                elif parsed.current_context == CompletionContext.PARAMETER_VALUE:
                    badge = "[dim magenta]VAL[/dim magenta]"
                    description = ""
                else:
                    badge = ""
                    description = ""

                highlighted = self.highlight_match(suggestion, parsed.current_token)
                label_text = f"{badge} {highlighted}{description}"
                self.add_option(Option(label_text, id=suggestion))

            self.display = True
            if len(self.filtered_commands) > 0:
                self.highlighted = 0
        else:
            self._fuzzy_filter(query)

    def _fuzzy_filter(self, query: str) -> None:
        """Legacy fuzzy matching filter (fallback)."""
        matches = []
        for cmd in self.all_commands:
            matched, score = self.fuzzy_match(cmd, query)
            if matched:
                matches.append((cmd, score))

        if matches:
            matches.sort(key=lambda x: x[1], reverse=True)
            self.filtered_commands = [cmd for cmd, _ in matches[:10]]

            self.clear_options()
            for cmd in self.filtered_commands:
                category = self.command_categories.get(cmd, "")
                if category:
                    badge_text = category.split("/")[0][:4].upper()
                    badge = f"[dim cyan]{badge_text}[/dim cyan]"
                else:
                    badge = ""

                highlighted = self.highlight_match(cmd, query)
                label_text = f"{badge} {highlighted}" if badge else highlighted
                self.add_option(Option(label_text, id=cmd))

            self.display = True
            if len(self.filtered_commands) > 0:
                self.highlighted = 0
        else:
            self.display = False
            self.filtered_commands = []
            self.clear_options()

    def get_selected_command(self) -> str | None:
        """Get currently highlighted command."""
        if self.highlighted is not None and 0 <= self.highlighted < len(self.filtered_commands):
            return self.filtered_commands[self.highlighted]
        return None

    def move_cursor_down(self) -> None:
        """Move selection down."""
        if self.filtered_commands and self.highlighted is not None:
            self.highlighted = min(self.highlighted + 1, len(self.filtered_commands) - 1)

    def move_cursor_up(self) -> None:
        """Move selection up."""
        if self.filtered_commands and self.highlighted is not None:
            self.highlighted = max(self.highlighted - 1, 0)

    def smart_insert_selection(
        self, current_value: str, cursor_pos: int, selection: str
    ) -> tuple[str, int]:
        """
        Intelligently insert the selected suggestion into the command line.

        Preserves all content before and after the current token being completed,
        replacing only the incomplete token with the selection.

        Args:
            current_value: Current command line text
            cursor_pos: Current cursor position
            selection: Selected suggestion to insert

        Returns:
            Tuple of (new_value, new_cursor_position)
        """
        if selection.startswith("aws "):
            return (selection, len(selection))

        if not self.use_intelligent_autocomplete or not current_value.strip().startswith("aws "):
            return (selection, len(selection))

        parsed = self.parser.parse(current_value, cursor_pos)
        token_start = cursor_pos - len(parsed.current_token)

        # Find where the current token actually ends (could be beyond cursor)
        token_end = cursor_pos
        while token_end < len(current_value) and not current_value[token_end].isspace():
            token_end += 1

        text_after_token = current_value[token_end:]

        if parsed.current_context in (
            CompletionContext.SERVICE,
            CompletionContext.COMMAND,
            CompletionContext.PARAMETER,
            CompletionContext.PARAMETER_VALUE,
        ):
            new_value = (
                current_value[:token_start] +
                selection +
                " " +
                text_after_token.lstrip()
            )
            new_cursor = token_start + len(selection) + 1
        else:
            if parsed.current_token:
                new_value = (
                    current_value[:token_start] +
                    selection +
                    " " +
                    text_after_token.lstrip()
                )
                new_cursor = token_start + len(selection) + 1
            else:
                new_value = current_value.rstrip() + " " + selection + " "
                new_cursor = len(new_value)

        return (new_value, new_cursor)