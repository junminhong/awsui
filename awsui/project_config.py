"""Project configuration discovery and validation."""

from collections.abc import Mapping
from dataclasses import dataclass
import os
from pathlib import Path
import re
from tempfile import NamedTemporaryFile
from types import MappingProxyType
from typing import Any

import yaml
from yaml.nodes import MappingNode
from yaml.resolver import BaseResolver


PROJECT_CONFIG_FILENAME = ".awsui.yaml"
SUPPORTED_PROJECT_CONFIG_VERSION = 1
_ACCOUNT_ID_PATTERN = re.compile(r"[0-9]{12}")


@dataclass(frozen=True, slots=True)
class ProjectContext:
    """A logical project environment and its expected AWS identity."""

    name: str
    account: str
    region: str
    protected: bool = False


@dataclass(frozen=True, slots=True)
class ProjectConfig:
    """A validated shared project configuration."""

    version: int
    project: str
    contexts: Mapping[str, ProjectContext]
    source_path: Path


class ProjectConfigError(Exception):
    """Base error for project configuration failures."""

    def __init__(self, path: Path, detail: str) -> None:
        self.path = path
        self.detail = detail
        super().__init__(f"{path}: {detail}")


class ProjectConfigNotFoundError(ProjectConfigError):
    """Raised when a project configuration cannot be found."""


class ProjectConfigLoadError(ProjectConfigError):
    """Raised when a project configuration cannot be read or parsed."""


class ProjectConfigValidationError(ProjectConfigError):
    """Raised when a project configuration violates the schema."""


class ProjectConfigWriteError(ProjectConfigError):
    """Raised when a project configuration cannot be persisted."""


class _DuplicateKeyError(yaml.YAMLError):
    """Internal YAML error carrying duplicate key details."""

    def __init__(self, key: Any, line: int) -> None:
        self.key = key
        self.line = line
        super().__init__(f"duplicate key {key!r} at line {line}")


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}

    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            is_duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc

        if is_duplicate:
            raise _DuplicateKeyError(key, key_node.start_mark.line + 1)

        mapping[key] = loader.construct_object(value_node, deep=deep)

    return mapping


_UniqueKeySafeLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def find_project_config(start_dir: Path | None = None) -> Path:
    """Find the nearest project configuration from a directory or its parents."""
    requested_start = Path.cwd() if start_dir is None else Path(start_dir)

    try:
        search_dir = requested_start.expanduser().resolve(strict=True)
    except OSError as exc:
        raise ProjectConfigNotFoundError(
            requested_start,
            "project configuration search directory does not exist",
        ) from exc

    if not search_dir.is_dir():
        raise ProjectConfigNotFoundError(
            search_dir,
            "project configuration search path is not a directory",
        )

    for directory in (search_dir, *search_dir.parents):
        candidate = directory / PROJECT_CONFIG_FILENAME
        if candidate.is_file():
            return candidate.resolve()

    raise ProjectConfigNotFoundError(
        search_dir,
        f"{PROJECT_CONFIG_FILENAME} was not found in this directory or its parents",
    )


def load_project_config(path: Path) -> ProjectConfig:
    """Load and validate a project configuration file."""
    requested_path = Path(path).expanduser()

    try:
        source_path = requested_path.resolve(strict=True)
    except OSError as exc:
        raise ProjectConfigNotFoundError(
            requested_path,
            "project configuration file does not exist",
        ) from exc

    if not source_path.is_file():
        raise ProjectConfigNotFoundError(
            source_path,
            "project configuration path is not a file",
        )

    try:
        content = source_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ProjectConfigLoadError(
            source_path,
            f"unable to read project configuration: {exc}",
        ) from exc

    try:
        raw_config = yaml.load(content, Loader=_UniqueKeySafeLoader)
    except _DuplicateKeyError as exc:
        raise ProjectConfigValidationError(
            source_path,
            f"duplicate YAML key {exc.key!r} at line {exc.line}",
        ) from exc
    except yaml.YAMLError as exc:
        raise ProjectConfigLoadError(
            source_path,
            f"invalid YAML: {_format_yaml_error(exc)}",
        ) from exc

    return _validate_project_config(raw_config, source_path)


def save_project_config(
    config: ProjectConfig,
    path: Path | None = None,
    *,
    overwrite: bool = True,
) -> None:
    """Validate and atomically persist a shared project configuration."""
    target_path = (
        (config.source_path if path is None else Path(path))
        .expanduser()
        .resolve(strict=False)
    )
    if not overwrite and target_path.exists():
        raise ProjectConfigWriteError(
            target_path,
            "project configuration already exists",
        )

    contexts: dict[str, dict[str, object]] = {}
    for name, context in config.contexts.items():
        serialized_context: dict[str, object] = {
            "account": context.account,
            "region": context.region,
        }
        if context.protected:
            serialized_context["protected"] = True
        contexts[name] = serialized_context

    payload = {
        "version": config.version,
        "project": config.project,
        "contexts": contexts,
    }
    _validate_project_config(payload, target_path)
    serialized = yaml.safe_dump(
        payload,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
    )

    parent = target_path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ProjectConfigWriteError(
            target_path,
            f"unable to create project directory: {exc}",
        ) from exc

    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=parent,
            prefix=".awsui.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            temporary_file.write(serialized)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        if not overwrite and target_path.exists():
            raise FileExistsError(target_path)
        os.replace(temporary_path, target_path)
        temporary_path = None
    except (OSError, UnicodeError) as exc:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
        detail = (
            "project configuration already exists"
            if isinstance(exc, FileExistsError)
            else f"unable to write project configuration: {exc}"
        )
        raise ProjectConfigWriteError(target_path, detail) from exc


def _format_yaml_error(error: yaml.YAMLError) -> str:
    problem = getattr(error, "problem", None)
    problem_mark = getattr(error, "problem_mark", None)

    if problem and problem_mark:
        return f"{problem} at line {problem_mark.line + 1}, column {problem_mark.column + 1}"
    if problem:
        return str(problem)
    return error.__class__.__name__


def _validate_project_config(raw_config: Any, source_path: Path) -> ProjectConfig:
    root = _require_mapping(raw_config, source_path, "root")
    _validate_fields(
        root,
        source_path,
        "root",
        required={"version", "project", "contexts"},
        allowed={"version", "project", "contexts"},
    )

    version = root["version"]
    if type(version) is not int or version != SUPPORTED_PROJECT_CONFIG_VERSION:
        raise ProjectConfigValidationError(
            source_path,
            f"version must be the integer {SUPPORTED_PROJECT_CONFIG_VERSION}",
        )

    project = _require_non_empty_string(root["project"], source_path, "project")
    raw_contexts = _require_mapping(root["contexts"], source_path, "contexts")
    if not raw_contexts:
        raise ProjectConfigValidationError(
            source_path,
            "contexts must contain at least one environment",
        )

    contexts: dict[str, ProjectContext] = {}
    for environment, raw_context in raw_contexts.items():
        if not isinstance(environment, str) or not environment.strip():
            raise ProjectConfigValidationError(
                source_path,
                "contexts keys must be non-empty strings",
            )

        context_path = f"contexts.{environment}"
        context = _require_mapping(raw_context, source_path, context_path)
        _validate_fields(
            context,
            source_path,
            context_path,
            required={"account", "region"},
            allowed={"account", "region", "protected"},
        )

        account = context["account"]
        if not isinstance(account, str) or not _ACCOUNT_ID_PATTERN.fullmatch(account):
            raise ProjectConfigValidationError(
                source_path,
                f"{context_path}.account must be a quoted 12-digit string",
            )

        region = _require_non_empty_string(
            context["region"],
            source_path,
            f"{context_path}.region",
        )

        protected = context.get("protected", False)
        if type(protected) is not bool:
            raise ProjectConfigValidationError(
                source_path,
                f"{context_path}.protected must be a boolean",
            )

        contexts[environment] = ProjectContext(
            name=environment,
            account=account,
            region=region,
            protected=protected,
        )

    return ProjectConfig(
        version=version,
        project=project,
        contexts=MappingProxyType(contexts),
        source_path=source_path,
    )


def _require_mapping(
    value: Any,
    source_path: Path,
    field_path: str,
) -> Mapping[Any, Any]:
    if not isinstance(value, Mapping):
        raise ProjectConfigValidationError(
            source_path,
            f"{field_path} must be a mapping",
        )
    return value


def _require_non_empty_string(
    value: Any,
    source_path: Path,
    field_path: str,
) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProjectConfigValidationError(
            source_path,
            f"{field_path} must be a non-empty string",
        )
    return value


def _validate_fields(
    value: Mapping[Any, Any],
    source_path: Path,
    field_path: str,
    *,
    required: set[str],
    allowed: set[str],
) -> None:
    non_string_keys = [key for key in value if not isinstance(key, str)]
    if non_string_keys:
        rendered_keys = ", ".join(repr(key) for key in non_string_keys)
        raise ProjectConfigValidationError(
            source_path,
            f"{field_path} contains non-string keys: {rendered_keys}",
        )

    keys = set(value)
    missing = sorted(required - keys)
    if missing:
        raise ProjectConfigValidationError(
            source_path,
            f"{field_path} is missing required fields: {', '.join(missing)}",
        )

    unknown = sorted(keys - allowed)
    if unknown:
        raise ProjectConfigValidationError(
            source_path,
            f"{field_path} contains unknown fields: {', '.join(unknown)}",
        )
