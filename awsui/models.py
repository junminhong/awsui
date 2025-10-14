"""Data models and AWS config parsing."""

from typing import TypedDict, Literal


class Profile(TypedDict):
    """AWS Profile representation."""

    name: str
    kind: Literal["sso", "assume", "basic"]
    account: str | None
    role: str | None
    region: str | None
    session: str | None  # sso-session name
    source: str  # source file path
