"""Tests for Context Dashboard translations."""

import re

from awsui.i18n import LANG_EN, LANG_ZH_TW


def test_languages_have_the_same_nonempty_string_keys():
    assert set(LANG_EN) == set(LANG_ZH_TW)
    assert all(isinstance(value, str) and value for value in LANG_EN.values())
    assert all(isinstance(value, str) and value for value in LANG_ZH_TW.values())


def test_format_placeholders_match_between_languages():
    for key, english in LANG_EN.items():
        assert set(re.findall(r"\{(\w+)\}", english)) == set(
            re.findall(r"\{(\w+)\}", LANG_ZH_TW[key])
        )


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
