"""Local, non-authenticating diagnostics for project AWS contexts."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .aws_cli import check_aws_cli_available
from .bindings import LocalBindingsError, load_bindings
from .config import parse_profiles
from .models import Profile
from .profile_catalog import ProfileCatalogError, load_profile_catalog
from .project_config import (
    ProjectConfigError,
    ProjectConfigNotFoundError,
    find_project_config,
    load_project_config,
)


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    passed: bool
    detail: str
    remediation: str | None = None


@dataclass(frozen=True, slots=True)
class DoctorReport:
    checks: tuple[DoctorCheck, ...]

    @property
    def healthy(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def remediations(self) -> tuple[str, ...]:
        """Return failed-check remediations in diagnostic order without duplicates."""
        ordered: list[str] = []
        seen: set[str] = set()
        for check in self.checks:
            remediation = check.remediation
            if check.passed or remediation is None or remediation in seen:
                continue
            seen.add(remediation)
            ordered.append(remediation)
        return tuple(ordered)


def diagnose(
    *,
    start_dir: Path | None = None,
    bindings_path: Path | None = None,
    aws_cli_checker: Callable[[], bool] = check_aws_cli_available,
    profiles_loader: Callable[[], Sequence[Profile]] = parse_profiles,
) -> DoctorReport:
    """Run local diagnostics without calling STS or triggering SSO."""
    checks: list[DoctorCheck] = []
    aws_cli_available = aws_cli_checker()
    checks.append(
        DoctorCheck(
            name="AWS CLI v2",
            passed=aws_cli_available,
            detail="available" if aws_cli_available else "not found or not AWS CLI v2",
            remediation=(
                None
                if aws_cli_available
                else "Install or upgrade to AWS CLI v2, then rerun `awsui doctor`."
            ),
        )
    )

    try:
        config_path = find_project_config(start_dir)
        config = load_project_config(config_path)
    except ProjectConfigNotFoundError as exc:
        checks.append(
            DoctorCheck(
                "Project configuration",
                False,
                str(exc),
                "Run `awsui init` from the project root.",
            )
        )
        return DoctorReport(tuple(checks))
    except ProjectConfigError as exc:
        checks.append(
            DoctorCheck(
                "Project configuration",
                False,
                str(exc),
                f"Fix `{exc.path}`, then rerun `awsui doctor`.",
            )
        )
        return DoctorReport(tuple(checks))
    checks.append(
        DoctorCheck(
            "Project configuration",
            True,
            f"{config.project} at {config.source_path}",
        )
    )

    try:
        bindings = load_bindings(bindings_path)
    except LocalBindingsError as exc:
        checks.append(
            DoctorCheck(
                "Local bindings",
                False,
                str(exc),
                f"Check permissions and JSON format for `{exc.path}`, then rerun "
                "`awsui doctor`.",
            )
        )
        return DoctorReport(tuple(checks))
    checks.append(DoctorCheck("Local bindings", True, str(bindings.source_path)))

    try:
        catalog = load_profile_catalog(lambda: list(profiles_loader()))
        profile_names = set(catalog.by_name)
    except ProfileCatalogError as exc:
        checks.append(
            DoctorCheck(
                "Local AWS profiles",
                False,
                str(exc),
                "Check your AWS config and credentials files, then rerun "
                "`awsui doctor`.",
            )
        )
        return DoctorReport(tuple(checks))
    first_environment = min(config.contexts)
    checks.append(
        DoctorCheck(
            "Local AWS profiles",
            bool(profile_names),
            f"{len(profile_names)} profile(s) found" if profile_names else "none found",
            (
                None
                if profile_names
                else f"Run `awsui bind {first_environment}` and press `c` to create "
                "a local AWS profile."
            ),
        )
    )

    for environment in sorted(config.contexts):
        profile = bindings.get_profile(config.project, environment)
        check_name = f"Context {environment}"
        if profile is None:
            checks.append(
                DoctorCheck(
                    check_name,
                    False,
                    "not bound",
                    f"Run `awsui bind {environment}`.",
                )
            )
        elif profile not in profile_names:
            checks.append(
                DoctorCheck(
                    check_name,
                    False,
                    f"bound profile {profile!r} was not found locally",
                    f"Run `awsui bind {environment}` to select or create a "
                    "replacement profile.",
                )
            )
        else:
            checks.append(DoctorCheck(check_name, True, f"bound to {profile}"))

    return DoctorReport(tuple(checks))
