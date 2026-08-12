"""Loading and indexing local AWS profiles."""

from collections.abc import Callable, Iterable, Mapping
from configparser import Error as ConfigParserError
from dataclasses import dataclass
from types import MappingProxyType

from .config import parse_profiles
from .models import Profile


class ProfileCatalogError(Exception):
    """Raised when local AWS profiles cannot be loaded or resolved."""


@dataclass(frozen=True, slots=True)
class ProfileCatalog:
    """An immutable, deterministically ordered collection of profiles."""

    profiles: tuple[Profile, ...]
    by_name: Mapping[str, Profile]

    @classmethod
    def from_profiles(cls, profiles: Iterable[Profile]) -> "ProfileCatalog":
        ordered = tuple(
            sorted(
                profiles,
                key=lambda profile: (
                    profile["name"].casefold(),
                    profile["name"],
                ),
            )
        )
        return cls(
            profiles=ordered,
            by_name=MappingProxyType({profile["name"]: profile for profile in ordered}),
        )

    def get(self, name: str) -> Profile | None:
        return self.by_name.get(name)


def load_profile_catalog(
    profiles_loader: Callable[[], list[Profile]] | None = None,
) -> ProfileCatalog:
    """Read local AWS profiles and normalize loader failures."""
    loader = parse_profiles if profiles_loader is None else profiles_loader
    try:
        return ProfileCatalog.from_profiles(loader())
    except (ConfigParserError, OSError, UnicodeError) as exc:
        raise ProfileCatalogError(f"unable to read local AWS profiles: {exc}") from exc
