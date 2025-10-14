"""Tests for internationalization (i18n) translations."""


from awsui.i18n import LANG_EN, LANG_ZH_TW


class TestTranslationCompleteness:
    """Tests for translation completeness between languages."""

    def test_both_languages_defined(self):
        """Test that both language dictionaries are defined."""
        assert LANG_EN is not None
        assert LANG_ZH_TW is not None
        assert isinstance(LANG_EN, dict)
        assert isinstance(LANG_ZH_TW, dict)

    def test_same_keys_in_both_languages(self):
        """Test that both languages have the same keys."""
        en_keys = set(LANG_EN.keys())
        zh_keys = set(LANG_ZH_TW.keys())

        missing_in_zh = en_keys - zh_keys
        missing_in_en = zh_keys - en_keys

        assert not missing_in_zh, f"Keys missing in ZH-TW: {missing_in_zh}"
        assert not missing_in_en, f"Keys missing in EN: {missing_in_en}"

    def test_no_empty_translations(self):
        """Test that no translations are empty strings."""
        for key, value in LANG_EN.items():
            assert value, f"Empty English translation for key: {key}"

        for key, value in LANG_ZH_TW.items():
            assert value, f"Empty Chinese translation for key: {key}"

    def test_all_values_are_strings(self):
        """Test that all translation values are strings."""
        for key, value in LANG_EN.items():
            assert isinstance(value, str), f"English value for '{key}' is not a string"

        for key, value in LANG_ZH_TW.items():
            assert isinstance(
                value, str
            ), f"Chinese value for '{key}' is not a string"


class TestRequiredTranslations:
    """Tests for required translation keys."""

    def test_ui_component_translations(self):
        """Test that UI component translations exist."""
        required_keys = [
            "search_placeholder",
            "cli_placeholder",
            "panel_profiles",
            "panel_detail",
            "detail_placeholder",
        ]

        for key in required_keys:
            assert key in LANG_EN, f"Missing English key: {key}"
            assert key in LANG_ZH_TW, f"Missing Chinese key: {key}"

    def test_error_message_translations(self):
        """Test that error message translations exist."""
        error_keys = [
            "no_profiles",
            "no_aws_cli",
            "auth_failed",
            "login_failed",
            "whoami_failed",
            "ai_query_failed",
        ]

        for key in error_keys:
            assert key in LANG_EN, f"Missing English error: {key}"
            assert key in LANG_ZH_TW, f"Missing Chinese error: {key}"

    def test_status_message_translations(self):
        """Test that status message translations exist."""
        status_keys = [
            "authenticating",
            "login_success",
            "auth_success",
            "whoami_updated",
            "cli_mode",
            "ai_mode",
        ]

        for key in status_keys:
            assert key in LANG_EN, f"Missing English status: {key}"
            assert key in LANG_ZH_TW, f"Missing Chinese status: {key}"

    def test_detail_field_translations(self):
        """Test that profile detail field translations exist."""
        detail_keys = [
            "detail_name",
            "detail_kind",
            "detail_account",
            "detail_role",
            "detail_region",
            "detail_session",
        ]

        for key in detail_keys:
            assert key in LANG_EN, f"Missing English detail: {key}"
            assert key in LANG_ZH_TW, f"Missing Chinese detail: {key}"

    def test_ai_translations(self):
        """Test that AI-related translations exist."""
        ai_keys = [
            "ai_placeholder",
            "ai_not_available",
            "ai_install_hint",
            "ai_spinner_wait",
            "ai_spinner_done",
            "ai_spinner_error",
            "ai_querying",
        ]

        for key in ai_keys:
            assert key in LANG_EN, f"Missing English AI key: {key}"
            assert key in LANG_ZH_TW, f"Missing Chinese AI key: {key}"


class TestFormatStringConsistency:
    """Tests for format string consistency between languages."""

    def test_format_placeholders_match(self):
        """Test that format placeholders match between languages."""
        for key in LANG_EN.keys():
            en_value = LANG_EN[key]
            zh_value = LANG_ZH_TW[key]

            # Extract format placeholders
            import re

            en_placeholders = set(re.findall(r"\{(\w+)\}", en_value))
            zh_placeholders = set(re.findall(r"\{(\w+)\}", zh_value))

            assert en_placeholders == zh_placeholders, (
                f"Format placeholder mismatch for '{key}':\n"
                f"EN: {en_placeholders}\n"
                f"ZH: {zh_placeholders}"
            )


class TestTranslationQuality:
    """Tests for translation quality."""

    def test_no_placeholder_translations(self):
        """Test that translations are not placeholder text."""
        placeholder_indicators = ["TODO", "FIXME", "XXX", "???"]

        for key, value in LANG_EN.items():
            for indicator in placeholder_indicators:
                assert indicator not in value, f"Placeholder in English '{key}': {value}"

        for key, value in LANG_ZH_TW.items():
            for indicator in placeholder_indicators:
                assert indicator not in value, f"Placeholder in Chinese '{key}': {value}"

    def test_critical_translations_have_chinese(self):
        """Test that critical user-facing translations contain Chinese characters."""
        # These are the most user-visible translations that should be in Chinese
        critical_keys = [
            "authenticating",
            "login_success",
            "login_failed",
            "auth_success",
            "auth_failed",
            "whoami_updated",
            "cli_mode",
            "ai_mode",
        ]

        import re

        for key in critical_keys:
            if key in LANG_ZH_TW:
                value = LANG_ZH_TW[key]
                chinese_chars = re.findall(r"[\u4e00-\u9fff]", value)
                # Critical translations should have Chinese
                assert (
                    len(chinese_chars) > 0
                ), f"Critical translation '{key}' has no Chinese characters: {value}"

    def test_translations_are_meaningful(self):
        """Test that translations are not just empty or identical to keys."""
        for key, value in LANG_ZH_TW.items():
            # Should not be empty
            assert len(value.strip()) > 0, f"Empty translation for key: {key}"
            # Should not be identical to the key
            assert value != key, f"Translation identical to key: {key}"


class TestSpecificTranslations:
    """Tests for specific important translations."""

    def test_app_subtitle(self):
        """Test app subtitle translation."""
        assert "app_subtitle" in LANG_EN
        assert "app_subtitle" in LANG_ZH_TW
        assert len(LANG_EN["app_subtitle"]) > 0
        assert len(LANG_ZH_TW["app_subtitle"]) > 0

    def test_whoami_translations(self):
        """Test whoami-related translations."""
        whoami_keys = ["whoami", "whoami_account", "whoami_arn", "whoami_user"]

        for key in whoami_keys:
            assert key in LANG_EN
            assert key in LANG_ZH_TW

    def test_region_override_translations(self):
        """Test region override translations."""
        region_keys = [
            "region_input_title",
            "region_input_placeholder",
            "region_input_hint",
            "region_override_set",
            "region_override_cleared",
            "detail_region_override",
        ]

        for key in region_keys:
            assert key in LANG_EN
            assert key in LANG_ZH_TW

    def test_execution_status_translations(self):
        """Test execution status translations."""
        status_keys = [
            "execute_success",
            "execute_failure",
            "cli_error_exit",
            "ai_error_exception",
            "cli_error_exception",
        ]

        for key in status_keys:
            assert key in LANG_EN
            assert key in LANG_ZH_TW

            # These should have format placeholders
            en_value = LANG_EN[key]
            zh_value = LANG_ZH_TW[key]

            # Should contain at least one placeholder
            import re

            en_has_placeholder = bool(re.search(r"\{[^}]+\}", en_value))
            zh_has_placeholder = bool(re.search(r"\{[^}]+\}", zh_value))

            assert (
                en_has_placeholder
            ), f"English '{key}' missing format placeholder: {en_value}"
            assert (
                zh_has_placeholder
            ), f"Chinese '{key}' missing format placeholder: {zh_value}"


class TestHelpText:
    """Tests for help text completeness."""

    def test_help_text_exists(self):
        """Test that help text exists in both languages."""
        assert "help_text" in LANG_EN
        assert "help_text" in LANG_ZH_TW

    def test_help_text_not_empty(self):
        """Test that help text is not empty."""
        assert len(LANG_EN["help_text"]) > 100
        assert len(LANG_ZH_TW["help_text"]) > 100

    def test_help_text_has_sections(self):
        """Test that help text has multiple sections."""
        en_help = LANG_EN["help_text"]
        zh_help = LANG_ZH_TW["help_text"]

        # Should have keyboard shortcuts section
        assert "shortcut" in en_help.lower() or "key" in en_help.lower()
        assert "快捷" in zh_help or "快速鍵" in zh_help

        # Should mention important features
        assert "cli" in en_help.lower()
        assert "CLI" in zh_help or "cli" in zh_help.lower()
