"""Tests for local AWS profile binding storage."""

import json
import os
from pathlib import Path
import stat

import pytest

import awsui.bindings as bindings_module
from awsui.bindings import (
    BINDINGS_VERSION,
    LocalBindings,
    LocalBindingsLoadError,
    LocalBindingsValidationError,
    LocalBindingsWriteError,
    get_default_bindings_path,
    load_bindings,
    save_bindings,
)


def make_bindings(
    path: Path,
    data: dict[str, dict[str, str]] | None = None,
) -> LocalBindings:
    return LocalBindings(
        version=BINDINGS_VERSION,
        bindings=data or {},
        source_path=path,
    )


class TestBindingsPath:
    """Tests for the fixed PRD-defined bindings path."""

    def test_default_path_is_under_home(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            Path,
            "home",
            classmethod(lambda cls: tmp_path),
        )

        assert (
            get_default_bindings_path()
            == tmp_path / ".config" / "awsui" / "bindings.json"
        )

    def test_missing_default_file_returns_empty_store(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            Path,
            "home",
            classmethod(lambda cls: tmp_path),
        )

        bindings = load_bindings()

        assert bindings.version == 1
        assert dict(bindings.bindings) == {}
        assert (
            bindings.source_path
            == (tmp_path / ".config" / "awsui" / "bindings.json").resolve()
        )


class TestLocalBindings:
    """Tests for the immutable bindings model."""

    def test_get_profile(self, tmp_path):
        bindings = make_bindings(
            tmp_path / "bindings.json",
            {
                "payment-service": {
                    "dev": "company-dev",
                    "prod": "company-prod",
                }
            },
        )

        assert bindings.get_profile("payment-service", "prod") == "company-prod"
        assert bindings.get_profile("payment-service", "missing") is None
        assert bindings.get_profile("missing", "prod") is None

    def test_with_binding_returns_updated_copy(self, tmp_path):
        original = make_bindings(tmp_path / "bindings.json")

        updated = original.with_binding(
            "payment-service",
            "prod",
            "company-prod",
        )

        assert original.get_profile("payment-service", "prod") is None
        assert updated.get_profile("payment-service", "prod") == "company-prod"
        assert updated.source_path == original.source_path

    def test_with_binding_replaces_only_selected_environment(self, tmp_path):
        original = make_bindings(
            tmp_path / "bindings.json",
            {
                "payment-service": {
                    "dev": "company-dev",
                    "prod": "old-prod",
                },
                "other-service": {
                    "prod": "other-prod",
                },
            },
        )

        updated = original.with_binding(
            "payment-service",
            "prod",
            "new-prod",
        )

        assert updated.get_profile("payment-service", "dev") == "company-dev"
        assert updated.get_profile("payment-service", "prod") == "new-prod"
        assert updated.get_profile("other-service", "prod") == "other-prod"

    def test_nested_mappings_are_read_only(self, tmp_path):
        bindings = make_bindings(
            tmp_path / "bindings.json",
            {"payment-service": {"prod": "company-prod"}},
        )

        with pytest.raises(TypeError):
            bindings.bindings["other"] = {}  # type: ignore[index]

        with pytest.raises(TypeError):
            bindings.bindings["payment-service"]["prod"] = "changed"  # type: ignore[index]

    @pytest.mark.parametrize(
        ("project", "environment", "profile", "message"),
        [
            ("", "prod", "profile", "project must be a non-empty string"),
            ("project", "", "profile", "environment must be a non-empty string"),
            ("project", "prod", "", "profile must be a non-empty string"),
            ("project", "prod", "   ", "profile must be a non-empty string"),
        ],
    )
    def test_with_binding_rejects_blank_values(
        self,
        tmp_path,
        project,
        environment,
        profile,
        message,
    ):
        bindings = make_bindings(tmp_path / "bindings.json")

        with pytest.raises(LocalBindingsValidationError, match=message):
            bindings.with_binding(project, environment, profile)


class TestLoadBindings:
    """Tests for loading and validating bindings JSON."""

    def test_loads_valid_bindings(self, tmp_path):
        path = tmp_path / "bindings.json"
        path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "bindings": {
                        "payment-service": {
                            "dev": "company-dev",
                            "prod": "company-prod",
                        }
                    },
                }
            ),
            encoding="utf-8",
        )

        bindings = load_bindings(path)

        assert bindings.version == 1
        assert bindings.source_path == path.resolve()
        assert bindings.get_profile("payment-service", "dev") == "company-dev"
        assert bindings.get_profile("payment-service", "prod") == "company-prod"

    def test_missing_custom_file_returns_empty_store(self, tmp_path):
        path = tmp_path / "nested" / "bindings.json"

        bindings = load_bindings(path)

        assert dict(bindings.bindings) == {}
        assert bindings.source_path == path.resolve()

    def test_directory_path_is_a_load_error(self, tmp_path):
        with pytest.raises(LocalBindingsLoadError, match="path is not a file"):
            load_bindings(tmp_path)

    def test_invalid_utf8_is_a_load_error(self, tmp_path):
        path = tmp_path / "bindings.json"
        path.write_bytes(b"\xff\xfe")

        with pytest.raises(LocalBindingsLoadError, match="unable to read"):
            load_bindings(path)

    @pytest.mark.parametrize(
        ("content", "message", "error_type"),
        [
            ("", "invalid JSON", LocalBindingsLoadError),
            ("{", "invalid JSON", LocalBindingsLoadError),
            ("[]", "root must be a mapping", LocalBindingsValidationError),
            (
                "{}",
                "root is missing required fields: bindings, version",
                LocalBindingsValidationError,
            ),
            (
                '{"version": 1, "bindings": {}, "metadata": {}}',
                "root contains unknown fields: metadata",
                LocalBindingsValidationError,
            ),
            (
                '{"version": "1", "bindings": {}}',
                "version must be the integer 1",
                LocalBindingsValidationError,
            ),
            (
                '{"version": true, "bindings": {}}',
                "version must be the integer 1",
                LocalBindingsValidationError,
            ),
            (
                '{"version": 2, "bindings": {}}',
                "version must be the integer 1",
                LocalBindingsValidationError,
            ),
            (
                '{"version": 1, "bindings": []}',
                "bindings must be a mapping",
                LocalBindingsValidationError,
            ),
            (
                '{"version": 1, "bindings": {"": {"prod": "profile"}}}',
                "bindings project key must be a non-empty string",
                LocalBindingsValidationError,
            ),
            (
                '{"version": 1, "bindings": {"project": {}}}',
                "bindings.project must contain at least one environment",
                LocalBindingsValidationError,
            ),
            (
                '{"version": 1, "bindings": {"project": []}}',
                "bindings.project must be a mapping",
                LocalBindingsValidationError,
            ),
            (
                '{"version": 1, "bindings": {"project": {"": "profile"}}}',
                "bindings.project environment key must be a non-empty string",
                LocalBindingsValidationError,
            ),
            (
                '{"version": 1, "bindings": {"project": {"prod": ""}}}',
                "bindings.project.prod must be a non-empty string",
                LocalBindingsValidationError,
            ),
            (
                '{"version": 1, "bindings": {"project": {"prod": 123}}}',
                "bindings.project.prod must be a non-empty string",
                LocalBindingsValidationError,
            ),
        ],
    )
    def test_rejects_invalid_files(
        self,
        tmp_path,
        content,
        message,
        error_type,
    ):
        path = tmp_path / "bindings.json"
        path.write_text(content, encoding="utf-8")

        with pytest.raises(error_type, match=message):
            load_bindings(path)

    @pytest.mark.parametrize(
        "content",
        [
            '{"version": 1, "version": 1, "bindings": {}}',
            ('{"version": 1, "bindings": {"project": {"prod": "one", "prod": "two"}}}'),
        ],
    )
    def test_rejects_duplicate_json_keys(self, tmp_path, content):
        path = tmp_path / "bindings.json"
        path.write_text(content, encoding="utf-8")

        with pytest.raises(
            LocalBindingsValidationError,
            match="duplicate JSON key",
        ):
            load_bindings(path)


class TestSaveBindings:
    """Tests for deterministic and atomic persistence."""

    def test_creates_parent_directory_and_file(self, tmp_path):
        path = tmp_path / "config" / "awsui" / "bindings.json"
        bindings = make_bindings(path).with_binding(
            "payment-service",
            "prod",
            "company-prod",
        )

        save_bindings(bindings)

        assert path.is_file()
        loaded = load_bindings(path)
        assert loaded.get_profile("payment-service", "prod") == "company-prod"

    def test_writes_deterministic_json(self, tmp_path):
        path = tmp_path / "bindings.json"
        bindings = make_bindings(
            path,
            {
                "z-service": {"prod": "z-profile"},
                "a-service": {
                    "prod": "prod-profile",
                    "dev": "dev-profile",
                },
            },
        )

        save_bindings(bindings)

        assert (
            path.read_text(encoding="utf-8")
            == """\
{
  "bindings": {
    "a-service": {
      "dev": "dev-profile",
      "prod": "prod-profile"
    },
    "z-service": {
      "prod": "z-profile"
    }
  },
  "version": 1
}
"""
        )

    def test_path_override_does_not_change_model(self, tmp_path):
        original_path = tmp_path / "original" / "bindings.json"
        override_path = tmp_path / "override" / "bindings.json"
        bindings = make_bindings(
            original_path,
            {"project": {"prod": "profile"}},
        )

        save_bindings(bindings, path=override_path)

        assert not original_path.exists()
        assert load_bindings(override_path).get_profile("project", "prod") == "profile"
        assert bindings.source_path == original_path.resolve()

    def test_replace_failure_preserves_original_and_cleans_temp(
        self,
        tmp_path,
        monkeypatch,
    ):
        path = tmp_path / "bindings.json"
        original = make_bindings(
            path,
            {"project": {"prod": "original-profile"}},
        )
        save_bindings(original)
        original_content = path.read_text(encoding="utf-8")
        updated = original.with_binding("project", "prod", "updated-profile")

        def fail_replace(source, target):
            raise OSError("replace failed")

        monkeypatch.setattr(bindings_module.os, "replace", fail_replace)

        with pytest.raises(LocalBindingsWriteError, match="unable to write"):
            save_bindings(updated)

        assert path.read_text(encoding="utf-8") == original_content
        assert list(tmp_path.glob(".bindings.*.tmp")) == []

    def test_parent_path_failure_is_a_write_error(self, tmp_path):
        parent = tmp_path / "not-a-directory"
        parent.write_text("content", encoding="utf-8")
        path = parent / "bindings.json"
        bindings = make_bindings(
            path,
            {"project": {"prod": "profile"}},
        )

        with pytest.raises(
            LocalBindingsWriteError,
            match="unable to create bindings directory",
        ):
            save_bindings(bindings)

    @pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
    def test_new_directory_and_file_use_private_permissions(self, tmp_path):
        parent = tmp_path / "awsui"
        path = parent / "bindings.json"
        bindings = make_bindings(
            path,
            {"project": {"prod": "profile"}},
        )

        save_bindings(bindings)

        assert stat.S_IMODE(parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
