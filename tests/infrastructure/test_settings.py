"""Tests for versioned local awsui user settings."""

import json
import os

import pytest

from awsui.settings import (
    SETTINGS_VERSION,
    UserSettingsLoadError,
    UserSettingsValidationError,
    UserSettingsWriteError,
    load_settings,
    save_settings,
    settings_with_language,
)


def test_missing_settings_use_english_without_creating_a_file(tmp_path):
    path = tmp_path / "settings.json"

    settings = load_settings(path)

    assert settings.language == "en"
    assert settings.version == SETTINGS_VERSION
    assert not path.exists()


def test_round_trip_persists_language(tmp_path):
    path = tmp_path / ".config" / "awsui" / "settings.json"

    save_settings(settings_with_language("zh-TW", path))

    assert load_settings(path).language == "zh-TW"
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "language": "zh-TW",
        "version": 1,
    }
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
        assert path.parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"version": 2, "language": "en"},
        {"version": 1, "language": "fr"},
        {"version": 1},
        {"version": 1, "language": "en", "extra": True},
    ],
)
def test_rejects_invalid_schema(tmp_path, payload):
    path = tmp_path / "settings.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(UserSettingsValidationError):
        load_settings(path)


def test_rejects_invalid_and_duplicate_json(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text("{invalid", encoding="utf-8")
    with pytest.raises(UserSettingsLoadError):
        load_settings(path)

    path.write_text('{"version": 1, "language": "en", "language": "zh-TW"}')
    with pytest.raises(UserSettingsValidationError):
        load_settings(path)


def test_atomic_replace_failure_preserves_existing_settings(tmp_path, monkeypatch):
    path = tmp_path / "settings.json"
    save_settings(settings_with_language("en", path))
    original = path.read_text(encoding="utf-8")

    def fail_replace(source, target):
        raise OSError("replace denied")

    monkeypatch.setattr("awsui.settings.os.replace", fail_replace)
    with pytest.raises(UserSettingsWriteError):
        save_settings(settings_with_language("zh-TW", path))

    assert path.read_text(encoding="utf-8") == original
    assert not tuple(tmp_path.glob(".settings.*.tmp"))
