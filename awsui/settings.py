"""Versioned local user preferences for the awsui CLI."""

from collections.abc import Mapping
from dataclasses import dataclass
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Literal, cast


SETTINGS_VERSION = 1
SETTINGS_DIRECTORY = Path(".config") / "awsui"
SETTINGS_FILENAME = "settings.json"
SUPPORTED_LANGUAGES = frozenset({"en", "zh-TW"})
Language = Literal["en", "zh-TW"]


class UserSettingsError(Exception):
    """Base error for local user preference failures."""

    def __init__(self, path: Path, detail: str) -> None:
        self.path = path
        self.detail = detail
        super().__init__(f"{path}: {detail}")


class UserSettingsLoadError(UserSettingsError):
    """Raised when settings cannot be read or decoded."""


class UserSettingsValidationError(UserSettingsError):
    """Raised when settings violate the versioned schema."""


class UserSettingsWriteError(UserSettingsError):
    """Raised when settings cannot be persisted."""


class _DuplicateJsonKeyError(ValueError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(f"duplicate key {key!r}")


@dataclass(frozen=True, slots=True)
class UserSettings:
    """Validated user-level awsui preferences."""

    version: int
    language: Language
    source_path: Path

    def __post_init__(self) -> None:
        source_path = Path(self.source_path).expanduser().resolve(strict=False)
        _validate(self.version, self.language, source_path)
        object.__setattr__(self, "source_path", source_path)


def get_default_settings_path() -> Path:
    """Return the user-level settings path shared by every project."""
    return Path.home() / SETTINGS_DIRECTORY / SETTINGS_FILENAME


def load_settings(path: Path | None = None) -> UserSettings:
    """Load settings, returning an in-memory English default when absent."""
    source_path = _resolve_path(path)
    if not source_path.exists():
        return UserSettings(SETTINGS_VERSION, "en", source_path)
    if not source_path.is_file():
        raise UserSettingsLoadError(source_path, "settings path is not a file")

    try:
        content = source_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise UserSettingsLoadError(
            source_path, f"unable to read settings: {exc}"
        ) from exc

    try:
        raw = json.loads(content, object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateJsonKeyError as exc:
        raise UserSettingsValidationError(
            source_path, f"duplicate JSON key {exc.key!r}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise UserSettingsLoadError(
            source_path,
            f"invalid JSON at line {exc.lineno}, column {exc.colno}",
        ) from exc

    root = _require_mapping(raw, source_path)
    required = {"version", "language"}
    missing = sorted(required - set(root))
    if missing:
        raise UserSettingsValidationError(
            source_path, f"root is missing required fields: {', '.join(missing)}"
        )
    unknown = sorted(str(key) for key in set(root) - required)
    if unknown:
        raise UserSettingsValidationError(
            source_path, f"root contains unknown fields: {', '.join(unknown)}"
        )

    version = root["version"]
    language = root["language"]
    _validate(version, language, source_path)
    return UserSettings(version, cast(Language, language), source_path)


def save_settings(settings: UserSettings, path: Path | None = None) -> None:
    """Persist validated settings atomically with private permissions."""
    target_path = settings.source_path if path is None else _resolve_path(path)
    _validate(settings.version, settings.language, target_path)
    serialized = (
        json.dumps(
            {"version": settings.version, "language": settings.language},
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
        raise UserSettingsWriteError(
            target_path, f"unable to create settings directory: {exc}"
        ) from exc

    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=parent,
            prefix=".settings.",
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
        raise UserSettingsWriteError(
            target_path, f"unable to write settings: {exc}"
        ) from exc


def settings_with_language(language: str, path: Path | None = None) -> UserSettings:
    """Build replacement settings without needing to read a damaged file."""
    source_path = _resolve_path(path)
    _validate(SETTINGS_VERSION, language, source_path)
    return UserSettings(SETTINGS_VERSION, cast(Language, language), source_path)


def _resolve_path(path: Path | None) -> Path:
    selected = get_default_settings_path() if path is None else Path(path)
    return selected.expanduser().resolve(strict=False)


def _validate(version: Any, language: Any, source_path: Path) -> None:
    if type(version) is not int or version != SETTINGS_VERSION:
        raise UserSettingsValidationError(
            source_path, f"version must be the integer {SETTINGS_VERSION}"
        )
    if not isinstance(language, str) or language not in SUPPORTED_LANGUAGES:
        supported = ", ".join(sorted(SUPPORTED_LANGUAGES))
        raise UserSettingsValidationError(
            source_path, f"language must be one of: {supported}"
        )


def _require_mapping(value: Any, source_path: Path) -> Mapping[Any, Any]:
    if not isinstance(value, Mapping):
        raise UserSettingsValidationError(source_path, "root must be an object")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKeyError(key)
        result[key] = value
    return result
