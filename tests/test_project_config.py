"""Tests for shared project configuration discovery and validation."""

from pathlib import Path

import pytest

from awsui.project_config import (
    PROJECT_CONFIG_FILENAME,
    ProjectConfig,
    ProjectConfigLoadError,
    ProjectConfigNotFoundError,
    ProjectConfigValidationError,
    ProjectConfigWriteError,
    ProjectContext,
    find_project_config,
    load_project_config,
    save_project_config,
)


VALID_CONFIG = """\
version: 1
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: ap-northeast-1
  prod:
    account: "999999999999"
    region: ap-northeast-1
    protected: true
"""


def write_project_config(directory: Path, content: str = VALID_CONFIG) -> Path:
    path = directory / PROJECT_CONFIG_FILENAME
    path.write_text(content, encoding="utf-8")
    return path


class TestFindProjectConfig:
    """Tests for locating the nearest project configuration."""

    def test_finds_config_in_start_directory(self, tmp_path):
        config_path = write_project_config(tmp_path)

        assert find_project_config(tmp_path) == config_path.resolve()

    def test_finds_config_in_parent_directory(self, tmp_path):
        config_path = write_project_config(tmp_path)
        nested = tmp_path / "services" / "api"
        nested.mkdir(parents=True)

        assert find_project_config(nested) == config_path.resolve()

    def test_nearest_config_takes_precedence(self, tmp_path):
        write_project_config(tmp_path)
        project = tmp_path / "project"
        project.mkdir()
        nearest = write_project_config(project)
        nested = project / "src"
        nested.mkdir()

        assert find_project_config(nested) == nearest.resolve()

    def test_defaults_to_current_working_directory(self, tmp_path, monkeypatch):
        config_path = write_project_config(tmp_path)
        nested = tmp_path / "src"
        nested.mkdir()
        monkeypatch.chdir(nested)

        assert find_project_config() == config_path.resolve()

    def test_raises_when_config_is_missing(self, tmp_path):
        nested = tmp_path / "project"
        nested.mkdir()

        with pytest.raises(
            ProjectConfigNotFoundError,
            match=r"\.awsui\.yaml was not found",
        ):
            find_project_config(nested)

    def test_raises_for_nonexistent_search_directory(self, tmp_path):
        missing = tmp_path / "missing"

        with pytest.raises(
            ProjectConfigNotFoundError,
            match="search directory does not exist",
        ):
            find_project_config(missing)

    def test_raises_when_search_path_is_a_file(self, tmp_path):
        file_path = tmp_path / "file.txt"
        file_path.write_text("content", encoding="utf-8")

        with pytest.raises(
            ProjectConfigNotFoundError,
            match="search path is not a directory",
        ):
            find_project_config(file_path)


class TestLoadProjectConfig:
    """Tests for loading valid project configurations."""

    def test_loads_valid_config(self, tmp_path):
        config_path = write_project_config(tmp_path)

        config = load_project_config(config_path)

        assert config.version == 1
        assert config.project == "payment-service"
        assert config.source_path == config_path.resolve()
        assert list(config.contexts) == ["dev", "prod"]

        dev = config.contexts["dev"]
        assert dev.name == "dev"
        assert dev.account == "111111111111"
        assert dev.region == "ap-northeast-1"
        assert dev.protected is False

        prod = config.contexts["prod"]
        assert prod.name == "prod"
        assert prod.account == "999999999999"
        assert prod.region == "ap-northeast-1"
        assert prod.protected is True

    def test_context_mapping_is_read_only(self, tmp_path):
        config = load_project_config(write_project_config(tmp_path))

        with pytest.raises(TypeError):
            config.contexts["staging"] = config.contexts["dev"]  # type: ignore[index]

    def test_raises_when_config_file_is_missing(self, tmp_path):
        missing = tmp_path / PROJECT_CONFIG_FILENAME

        with pytest.raises(
            ProjectConfigNotFoundError,
            match="configuration file does not exist",
        ):
            load_project_config(missing)

    def test_raises_when_config_path_is_a_directory(self, tmp_path):
        with pytest.raises(
            ProjectConfigNotFoundError,
            match="configuration path is not a file",
        ):
            load_project_config(tmp_path)

    def test_invalid_utf8_is_a_load_error(self, tmp_path):
        config_path = tmp_path / PROJECT_CONFIG_FILENAME
        config_path.write_bytes(b"\xff\xfe")

        with pytest.raises(ProjectConfigLoadError, match="unable to read"):
            load_project_config(config_path)


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("", "root must be a mapping"),
        ("- version\n- 1\n", "root must be a mapping"),
        (
            """\
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: us-east-1
""",
            "root is missing required fields: version",
        ),
        (
            """\
version: "1"
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: us-east-1
""",
            "version must be the integer 1",
        ),
        (
            """\
version: true
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: us-east-1
""",
            "version must be the integer 1",
        ),
        (
            """\
version: 2
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: us-east-1
""",
            "version must be the integer 1",
        ),
        (
            """\
version: 1
project: ""
contexts:
  dev:
    account: "111111111111"
    region: us-east-1
""",
            "project must be a non-empty string",
        ),
        (
            """\
version: 1
project: payment-service
contexts: {}
""",
            "contexts must contain at least one environment",
        ),
        (
            """\
version: 1
project: payment-service
contexts: []
""",
            "contexts must be a mapping",
        ),
        (
            """\
version: 1
project: payment-service
contexts:
  "":
    account: "111111111111"
    region: us-east-1
""",
            "contexts keys must be non-empty strings",
        ),
        (
            """\
version: 1
project: payment-service
contexts:
  dev:
""",
            "contexts.dev must be a mapping",
        ),
        (
            """\
version: 1
project: payment-service
contexts:
  dev:
    region: us-east-1
""",
            "contexts.dev is missing required fields: account",
        ),
        (
            """\
version: 1
project: payment-service
contexts:
  dev:
    account: 111111111111
    region: us-east-1
""",
            "contexts.dev.account must be a quoted 12-digit string",
        ),
        (
            """\
version: 1
project: payment-service
contexts:
  dev:
    account: "123"
    region: us-east-1
""",
            "contexts.dev.account must be a quoted 12-digit string",
        ),
        (
            """\
version: 1
project: payment-service
contexts:
  dev:
    account: "１２３４５６７８９０１２"
    region: us-east-1
""",
            "contexts.dev.account must be a quoted 12-digit string",
        ),
        (
            """\
version: 1
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: ""
""",
            "contexts.dev.region must be a non-empty string",
        ),
        (
            """\
version: 1
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: 123
""",
            "contexts.dev.region must be a non-empty string",
        ),
        (
            """\
version: 1
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: us-east-1
    protected: "true"
""",
            "contexts.dev.protected must be a boolean",
        ),
        (
            """\
version: 1
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: us-east-1
    protectd: true
""",
            "contexts.dev contains unknown fields: protectd",
        ),
        (
            """\
version: 1
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: us-east-1
metadata: {}
""",
            "root contains unknown fields: metadata",
        ),
        (
            """\
version: 1
project: payment-service
contexts:
  123:
    account: "111111111111"
    region: us-east-1
""",
            "contexts keys must be non-empty strings",
        ),
    ],
)
def test_rejects_invalid_schema(tmp_path, content, message):
    config_path = write_project_config(tmp_path, content)

    with pytest.raises(ProjectConfigValidationError, match=message):
        load_project_config(config_path)


@pytest.mark.parametrize(
    "content",
    [
        """\
version: 1
version: 1
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: us-east-1
""",
        """\
version: 1
project: payment-service
contexts:
  dev:
    account: "111111111111"
    account: "222222222222"
    region: us-east-1
""",
    ],
)
def test_rejects_duplicate_yaml_keys(tmp_path, content):
    config_path = write_project_config(tmp_path, content)

    with pytest.raises(ProjectConfigValidationError, match="duplicate YAML key"):
        load_project_config(config_path)


@pytest.mark.parametrize(
    "content",
    [
        "version: [1\n",
        "!!python/object/apply:os.system ['echo unsafe']\n",
    ],
)
def test_rejects_invalid_or_unsafe_yaml(tmp_path, content):
    config_path = write_project_config(tmp_path, content)

    with pytest.raises(ProjectConfigLoadError, match="invalid YAML"):
        load_project_config(config_path)


class TestSaveProjectConfig:
    """Tests for safely writing shared project configuration."""

    def test_round_trips_and_keeps_account_ids_as_strings(self, tmp_path):
        config_path = tmp_path / PROJECT_CONFIG_FILENAME
        config = ProjectConfig(
            version=1,
            project="payment-service",
            contexts={
                "dev": ProjectContext(
                    name="dev",
                    account="111111111111",
                    region="us-east-1",
                ),
                "prod": ProjectContext(
                    name="prod",
                    account="999999999999",
                    region="ap-northeast-1",
                    protected=True,
                ),
            },
            source_path=config_path,
        )

        save_project_config(config)

        loaded = load_project_config(config_path)
        assert loaded.project == "payment-service"
        assert loaded.contexts["dev"].account == "111111111111"
        assert loaded.contexts["prod"].protected is True
        content = config_path.read_text(encoding="utf-8")
        assert "account: '111111111111'" in content
        assert "protected: false" not in content
        assert "protected: true" in content

    def test_refuses_to_overwrite_existing_configuration(self, tmp_path):
        config_path = write_project_config(tmp_path)
        original = config_path.read_text(encoding="utf-8")
        config = load_project_config(config_path)

        with pytest.raises(ProjectConfigWriteError, match="already exists"):
            save_project_config(config, overwrite=False)

        assert config_path.read_text(encoding="utf-8") == original

    def test_validates_before_creating_parent_directory(self, tmp_path):
        config_path = tmp_path / "missing" / PROJECT_CONFIG_FILENAME
        invalid = ProjectConfig(
            version=1,
            project="payment-service",
            contexts={
                "prod": ProjectContext(
                    name="prod",
                    account="invalid",
                    region="ap-northeast-1",
                )
            },
            source_path=config_path,
        )

        with pytest.raises(ProjectConfigValidationError):
            save_project_config(invalid)

        assert not config_path.parent.exists()
