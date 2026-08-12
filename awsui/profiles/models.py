"""Shared AWS profile data models."""

from typing import Literal, NotRequired, TypedDict


ProfileKind = Literal["sso", "login", "assume", "process", "basic"]


class Profile(TypedDict):
    """AWS Profile representation."""

    name: str
    kind: ProfileKind
    account: str | None
    role: str | None
    region: str | None
    session: str | None  # sso-session name
    source: str  # source file path
    source_profile: NotRequired[str]
    credential_source: NotRequired[str]
    login_session: NotRequired[str]
    credential_process: NotRequired[str]
