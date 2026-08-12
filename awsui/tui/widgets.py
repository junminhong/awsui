"""Reusable widgets for the Textual dashboard."""

from collections.abc import Mapping, Sequence

from rich.text import Text
from textual.widgets import ListItem, ListView, Static

from ..context.dashboard import ContextItem, ContextStatus
from .theme import TUI_RICH_STYLES


STATUS_PRESENTATION = {
    ContextStatus.UNBOUND: ("!", "status_unbound", "warning"),
    ContextStatus.PROFILE_MISSING: ("!", "status_profile_missing", "error"),
    ContextStatus.READY: ("○", "status_ready", "primary"),
    ContextStatus.VERIFYING: ("◌", "status_verifying", "primary"),
    ContextStatus.VERIFIED: ("✓", "status_verified", "success"),
    ContextStatus.MISMATCH: ("✗", "status_mismatch", "error"),
    ContextStatus.ERROR: ("✗", "status_error", "error"),
}


class ContextList(ListView):
    """Environment list whose labels reflect session verification state."""

    def set_contexts(
        self,
        contexts: Sequence[ContextItem],
        statuses: Mapping[str, ContextStatus],
        translations: Mapping[str, str],
    ) -> None:
        renderables = [
            self._render_context(
                context,
                statuses.get(context.name, context.status),
                translations,
            )
            for context in contexts
        ]
        existing_items = list(self.children)
        existing_names = [item.name for item in existing_items]
        expected_names = [context.name for context in contexts]
        if existing_names == expected_names:
            for item, renderable in zip(existing_items, renderables, strict=True):
                item.query_one(Static).update(renderable)
            return

        self.clear()
        for context, renderable in zip(contexts, renderables, strict=True):
            self.append(ListItem(Static(renderable), name=context.name))

    @staticmethod
    def _render_context(
        context: ContextItem,
        status: ContextStatus,
        translations: Mapping[str, str],
    ) -> Text:
        """Render one environment row without changing ListView selection."""
        symbol, label_key, style_name = STATUS_PRESENTATION[status]
        status_style = getattr(TUI_RICH_STYLES, style_name)
        label = translations[label_key]
        body = Text()
        body.append(f"{symbol} ", style=status_style)
        body.append(context.name.upper(), style=TUI_RICH_STYLES.title)
        if context.protected:
            body.append(
                f" · {translations['protected']}",
                style=TUI_RICH_STYLES.protected,
            )
        body.append("\n")
        body.append(label, style=status_style)
        if context.profile:
            body.append(f" · {context.profile}", style=TUI_RICH_STYLES.muted)
        return body
