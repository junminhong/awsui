"""Tests for Context Dashboard translations."""

from string import Formatter

from awsui.i18n import LANG_EN, LANG_ZH_TW, text, use_language


def test_languages_have_the_same_nonempty_string_keys():
    assert set(LANG_EN) == set(LANG_ZH_TW)
    assert all(isinstance(value, str) and value for value in LANG_EN.values())
    assert all(isinstance(value, str) and value for value in LANG_ZH_TW.values())


def _format_fields(value: str) -> set[str]:
    return {
        field_name
        for _, field_name, _, _ in Formatter().parse(value)
        if field_name is not None
    }


def test_format_placeholders_match_between_languages():
    for key, english in LANG_EN.items():
        assert _format_fields(english) == _format_fields(LANG_ZH_TW[key]), key


def test_dashboard_translations_cover_primary_states_and_actions():
    required = {
        "action_bind",
        "action_verify",
        "action_launch",
        "action_shell",
        "status_unbound",
        "status_profile_missing",
        "status_ready",
        "status_verifying",
        "status_verified",
        "status_mismatch",
        "status_error",
        "help_text",
    }

    assert required <= LANG_EN.keys()


def test_removed_legacy_tui_features_are_not_translated():
    text = " ".join((*LANG_EN.keys(), *LANG_EN.values())).lower()

    assert "amazon q" not in text
    assert "autocomplete" not in text
    assert "cheatsheet" not in text


def test_cli_language_scope_is_isolated_and_restored():
    assert text("cli_project") == "Project"

    with use_language("zh-TW"):
        assert text("cli_project") == "專案"

    assert text("cli_project") == "Project"
