"""Restrained graphite visual system for the Textual application only."""

from dataclasses import dataclass

from rich.style import Style
from textual.theme import Theme


@dataclass(frozen=True, slots=True)
class TuiPalette:
    """Shared color tokens for Textual CSS and embedded Rich renderables."""

    background: str = "#0E1013"
    surface: str = "#15181C"
    panel: str = "#1B1F24"
    foreground: str = "#E5E7EA"
    muted: str = "#8D949E"
    primary: str = "#8197B2"
    success: str = "#79A88B"
    warning: str = "#C0A060"
    error: str = "#C9787D"
    border: str = "#2B3037"
    border_blurred: str = "#22262C"


PALETTE = TuiPalette()

AWSUI_GRAPHITE_THEME = Theme(
    name="awsui-graphite",
    primary=PALETTE.primary,
    secondary=PALETTE.muted,
    accent=PALETTE.primary,
    warning=PALETTE.warning,
    error=PALETTE.error,
    success=PALETTE.success,
    foreground=PALETTE.foreground,
    background=PALETTE.background,
    surface=PALETTE.surface,
    panel=PALETTE.panel,
    boost=PALETTE.foreground,
    dark=True,
    luminosity_spread=0.08,
    variables={
        "text": PALETTE.foreground,
        "text-muted": PALETTE.muted,
        "foreground-muted": PALETTE.muted,
        "border": PALETTE.border,
        "border-blurred": PALETTE.border_blurred,
        "block-cursor-background": "#252B33",
        "block-cursor-foreground": PALETTE.foreground,
        "block-cursor-text-style": "none",
        "block-cursor-blurred-background": PALETTE.panel,
        "block-cursor-blurred-foreground": PALETTE.foreground,
        "block-hover-background": "#20252B",
        "input-selection-background": "#8197B240",
        "button-color-foreground": PALETTE.foreground,
        "button-focus-text-style": "none",
        "scrollbar": PALETTE.border,
        "scrollbar-hover": PALETTE.primary,
        "scrollbar-active": PALETTE.primary,
    },
)


class TuiRichStyles:
    """Concrete Rich styles that never depend on a Console named theme."""

    title = Style(color=PALETTE.foreground, bold=True)
    label = Style(color=PALETTE.muted)
    value = Style(color=PALETTE.foreground)
    muted = Style(color=PALETTE.muted)
    primary = Style(color=PALETTE.primary)
    primary_bold = Style(color=PALETTE.primary, bold=True)
    success = Style(color=PALETTE.success, bold=True)
    warning = Style(color=PALETTE.warning, bold=True)
    error = Style(color=PALETTE.error, bold=True)
    protected = Style(color=PALETTE.warning)


TUI_RICH_STYLES = TuiRichStyles()
