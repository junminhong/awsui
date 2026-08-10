"""Local AWS profile binding storage."""

from collections.abc import Mapping
from dataclasses import dataclass
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from types import MappingProxyType
from typing import Any


BINDINGS_VERSION = 1
BINDINGS_DIRECTORY = Path(".config") / "awsui"
BINDINGS_FILENAME = "bindings.json"


class LocalBindingsError(Exception):
    """Base error for local binding failures."""

    def __init__(self, path: Path, detail: str) -> None:
        self.path = path
        self.detail = detail
        super().__init__(f"{path}: {detail}")


class LocalBindingsLoadError(LocalBindingsError):
    """Raised when a bindings file cannot be read or parsed."""


class LocalBindingsValidationError(LocalBindingsError):
    """Raised when local bindings violate the storage schema."""


class LocalBindingsWriteError(LocalBindingsError):
    """Raised when local bindings cannot be persisted."""


class _DuplicateJsonKeyError(ValueError):
    """Internal JSON error carrying duplicate key details."""

    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"duplicate key {key!r}")


@dataclass(frozen=True, slots=True)
class LocalBindings:
    """An immutable set of local project environment bindings."""

    version: int
    bindings: Mapping[str, Mapping[str, str]]
    source_path: Path

    def __post_init__(self) -> None:
        source_path = Path(self.source_path).expanduser().resolve(strict=False)
        normalized = _validate_bindings(
            version=self.version,
            bindings=self.bindings,
            source_path=source_path,
        )
        object.__setattr__(self, "source_path", source_path)
        object.__setattr__(self, "bindings", _freeze_bindings(normalized))

    def get_profile(self, project: str, environment: str) -> str | None:
        """Return the bound profile, or None when no binding exists."""
        project_bindings = self.bindings.get(project)
        if project_bindings is None:
            return None
        return project_bindings.get(environment)

    def with_binding(
        self,
        project: str,
        environment: str,
        profile: str,
    ) -> "LocalBindings":
        """Return a new store with one binding added or replaced."""
        _require_non_empty_string(project, self.source_path, "project")
        _require_non_empty_string(environment, self.source_path, "environment")
        _require_non_empty_string(profile, self.source_path, "profile")

        updated = {
            project_name: dict(project_bindings)
            for project_name, project_bindings in self.bindings.items()
        }
        updated.setdefault(project, {})[environment] = profile

        return LocalBindings(
            version=self.version,
            bindings=updated,
            source_path=self.source_path,
        )


def get_default_bindings_path() -> Path:
    """Return the PRD-defined local bindings path."""
    return Path.home() / BINDINGS_DIRECTORY / BINDINGS_FILENAME


def load_bindings(path: Path | None = None) -> LocalBindings:
    """Load local bindings, returning an empty store when the file is absent."""
    source_path = _resolve_path(path)

    if not source_path.exists():
        return LocalBindings(
            version=BINDINGS_VERSION,
            bindings={},
            source_path=source_path,
        )

    if not source_path.is_file():
        raise LocalBindingsLoadError(
            source_path,
            "bindings path is not a file",
        )

    try:
        content = source_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise LocalBindingsLoadError(
            source_path,
            f"unable to read bindings: {exc}",
        ) from exc

    try:
        raw = json.loads(content, object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateJsonKeyError as exc:
        raise LocalBindingsValidationError(
            source_path,
            f"duplicate JSON key {exc.key!r}",
        ) from exc
    except json.JSONDecodeError as exc:
        raise LocalBindingsLoadError(
            source_path,
            f"invalid JSON at line {exc.lineno}, column {exc.colno}",
        ) from exc

    root = _require_mapping(raw, source_path, "root")
    _validate_root_fields(root, source_path)

    return LocalBindings(
        version=root["version"],
        bindings=root["bindings"],
        source_path=source_path,
    )


def save_bindings(
    bindings: LocalBindings,
    path: Path | None = None,
) -> None:
    """Persist local bindings atomically."""
    target_path = bindings.source_path if path is None else _resolve_path(path)
    normalized = _validate_bindings(
        version=bindings.version,
        bindings=bindings.bindings,
        source_path=target_path,
    )
    payload = {
        "version": bindings.version,
        "bindings": normalized,
    }
    serialized = (
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )

    parent = target_path.parent
    parent_existed = parent.exists()

    try:
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if os.name == "posix" and not parent_existed:
            parent.chmod(0o700)
    except OSError as exc:
        raise LocalBindingsWriteError(
            target_path,
            f"unable to create bindings directory: {exc}",
        ) from exc

    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=parent,
            prefix=".bindings.",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            if os.name == "posix":
                os.fchmod(temporary_file.fileno(), 0o600)
            temporary_file.write(serialized)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        os.replace(temporary_path, target_path)
        temporary_path = None
    except (OSError, UnicodeError) as exc:
        if temporary_path is not None:
            try:
                temporary_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise LocalBindingsWriteError(
            target_path,
            f"unable to write bindings: {exc}",
        ) from exc


def _resolve_path(path: Path | None) -> Path:
    selected_path = get_default_bindings_path() if path is None else Path(path)
    return selected_path.expanduser().resolve(strict=False)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError(key)
        result[key] = value
    return result


def _validate_root_fields(
    root: Mapping[Any, Any],
    source_path: Path,
) -> None:
    keys = set(root)
    required = {"version", "bindings"}

    missing = sorted(required - keys)
    if missing:
        raise LocalBindingsValidationError(
            source_path,
            f"root is missing required fields: {', '.join(missing)}",
        )

    unknown = sorted(str(key) for key in keys - required)
    if unknown:
        raise LocalBindingsValidationError(
            source_path,
            f"root contains unknown fields: {', '.join(unknown)}",
        )


def _validate_bindings(
    *,
    version: Any,
    bindings: Any,
    source_path: Path,
) -> dict[str, dict[str, str]]:
    if type(version) is not int or version != BINDINGS_VERSION:
        raise LocalBindingsValidationError(
            source_path,
            f"version must be the integer {BINDINGS_VERSION}",
        )

    binding_map = _require_mapping(bindings, source_path, "bindings")
    normalized: dict[str, dict[str, str]] = {}

    for project, raw_project_bindings in binding_map.items():
        _require_non_empty_string(project, source_path, "bindings project key")
        project_path = f"bindings.{project}"
        project_bindings = _require_mapping(
            raw_project_bindings,
            source_path,
            project_path,
        )
        if not project_bindings:
            raise LocalBindingsValidationError(
                source_path,
                f"{project_path} must contain at least one environment",
            )

        normalized_project: dict[str, str] = {}
        for environment, profile in project_bindings.items():
            _require_non_empty_string(
                environment,
                source_path,
                f"{project_path} environment key",
            )
            _require_non_empty_string(
                profile,
                source_path,
                f"{project_path}.{environment}",
            )
            normalized_project[environment] = profile

        normalized[project] = normalized_project

    return normalized


def _require_mapping(
    value: Any,
    source_path: Path,
    field_path: str,
) -> Mapping[Any, Any]:
    if not isinstance(value, Mapping):
        raise LocalBindingsValidationError(
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
        raise LocalBindingsValidationError(
            source_path,
            f"{field_path} must be a non-empty string",
        )
    return value


def _freeze_bindings(
    bindings: Mapping[str, Mapping[str, str]],
) -> Mapping[str, Mapping[str, str]]:
    frozen_projects = {
        project: MappingProxyType(dict(project_bindings))
        for project, project_bindings in bindings.items()
    }
    return MappingProxyType(frozen_projects)
