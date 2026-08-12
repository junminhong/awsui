"""Translations used by the project dashboard and command-line interface."""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

from awsui.i18n.en import LANG_EN
from awsui.i18n.zh_tw import LANG_ZH_TW

_CURRENT_LANGUAGE: ContextVar[str] = ContextVar("awsui_language", default="en")


def text(key: str, /, *, lang: str | None = None, **values: object) -> str:
    """Return one translated string for the active CLI language."""
    selected = _CURRENT_LANGUAGE.get() if lang is None else lang
    catalog = LANG_ZH_TW if selected == "zh-TW" else LANG_EN
    return catalog[key].format(**values)


@contextmanager
def use_language(lang: str) -> Iterator[None]:
    """Scope CLI translations to one invocation without leaking global state."""
    token = _CURRENT_LANGUAGE.set(lang)
    try:
        yield
    finally:
        _CURRENT_LANGUAGE.reset(token)
