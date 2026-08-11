"""Local, non-authenticating diagnostics for project AWS contexts."""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

from .aws_cli import check_aws_cli_available
from .bindings import LocalBindingsError, load_bindings
from .i18n import text
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
            name=text("doctor_aws_cli"),
            passed=aws_cli_available,
            detail=(
                text("doctor_available")
                if aws_cli_available
                else text("doctor_not_found")
            ),
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
                text("doctor_project_config"),
                False,
                str(exc),
                "Run `awsui init` from the project root.",
            )
        )
        return DoctorReport(tuple(checks))
    except ProjectConfigError as exc:
        checks.append(
            DoctorCheck(
                text("doctor_project_config"),
                False,
                str(exc),
                f"Fix `{exc.path}`, then rerun `awsui doctor`.",
            )
        )
        return DoctorReport(tuple(checks))
    checks.append(
        DoctorCheck(
            text("doctor_project_config"),
            True,
            f"{config.project} at {config.source_path}",
        )
    )

    try:
        bindings = load_bindings(bindings_path)
    except LocalBindingsError as exc:
        checks.append(
            DoctorCheck(
                text("doctor_local_bindings"),
                False,
                str(exc),
                f"Check permissions and JSON format for `{exc.path}`, then rerun "
                "`awsui doctor`.",
            )
        )
        return DoctorReport(tuple(checks))
    checks.append(
        DoctorCheck(text("doctor_local_bindings"), True, str(bindings.source_path))
    )

    try:
        catalog = load_profile_catalog(lambda: list(profiles_loader()))
        profile_names = set(catalog.by_name)
    except ProfileCatalogError as exc:
        checks.append(
            DoctorCheck(
                text("doctor_local_profiles"),
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
            text("doctor_local_profiles"),
            bool(profile_names),
            text("doctor_profiles_found", count=len(profile_names))
            if profile_names
            else text("doctor_none_found"),
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
        check_name = text("doctor_context", environment=environment)
        if profile is None:
            checks.append(
                DoctorCheck(
                    check_name,
                    False,
                    text("doctor_not_bound"),
                    f"Run `awsui bind {environment}`.",
                )
            )
        elif profile not in profile_names:
            checks.append(
                DoctorCheck(
                    check_name,
                    False,
                    text("doctor_profile_missing", profile=profile),
                    f"Run `awsui bind {environment}` to select or create a "
                    "replacement profile.",
                )
            )
        else:
            checks.append(
                DoctorCheck(check_name, True, text("doctor_bound", profile=profile))
            )

    return DoctorReport(tuple(checks))
