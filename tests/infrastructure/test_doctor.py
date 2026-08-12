"""Tests for local awsui diagnostics."""

from pathlib import Path
from unittest.mock import patch

from awsui.doctor import DoctorCheck, DoctorReport, diagnose
from awsui.project.bindings import load_bindings, save_bindings


PROJECT_CONFIG = """\
version: 1
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: us-east-1
  prod:
    account: "999999999999"
    region: ap-northeast-1
"""


def profile(name: str):
    return {
        "name": name,
        "kind": "sso",
        "account": None,
        "role": None,
        "region": "ap-northeast-1",
        "session": "company",
        "source": "/home/user/.aws/config",
    }


def prepare_project(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".awsui.yaml").write_text(PROJECT_CONFIG, encoding="utf-8")
    bindings_path = tmp_path / "bindings.json"
    bindings = load_bindings(bindings_path)
    bindings = bindings.with_binding("payment-service", "dev", "company-dev")
    bindings = bindings.with_binding("payment-service", "prod", "company-prod")
    save_bindings(bindings)
    return project, bindings_path


def test_healthy_project_passes_all_local_checks(tmp_path):
    project, bindings_path = prepare_project(tmp_path)

    report = diagnose(
        start_dir=project,
        bindings_path=bindings_path,
        aws_cli_checker=lambda: True,
        profiles_loader=lambda: [profile("company-dev"), profile("company-prod")],
    )

    assert report.healthy is True
    assert [check.name for check in report.checks] == [
        "AWS CLI v2",
        "Project configuration",
        "Local bindings",
        "Local AWS profiles",
        "Context dev",
        "Context prod",
    ]
    assert report.remediations == ()


def test_reports_missing_binding_and_removed_profile(tmp_path):
    project, bindings_path = prepare_project(tmp_path)
    bindings = load_bindings(bindings_path).with_binding(
        "payment-service", "prod", "removed-profile"
    )
    save_bindings(bindings)

    report = diagnose(
        start_dir=project,
        bindings_path=bindings_path,
        aws_cli_checker=lambda: False,
        profiles_loader=lambda: [profile("company-dev")],
    )

    assert report.healthy is False
    failed = {check.name: check.detail for check in report.checks if not check.passed}
    assert failed["AWS CLI v2"] == "not found or not AWS CLI v2"
    assert "removed-profile" in failed["Context prod"]
    assert report.remediations == (
        "Install or upgrade to AWS CLI v2, then rerun `awsui doctor`.",
        "Run `awsui bind prod` to select or create a replacement profile.",
    )


def test_missing_project_stops_after_local_discovery(tmp_path):
    profiles_loader_called = False

    def load_profiles():
        nonlocal profiles_loader_called
        profiles_loader_called = True
        return []

    report = diagnose(
        start_dir=tmp_path,
        aws_cli_checker=lambda: True,
        profiles_loader=load_profiles,
    )

    assert report.healthy is False
    assert report.checks[-1].name == "Project configuration"
    assert report.remediations == ("Run `awsui init` from the project root.",)
    assert profiles_loader_called is False


def test_invalid_project_config_recommends_fixing_existing_file(tmp_path):
    config_path = tmp_path / ".awsui.yaml"
    config_path.write_text("version: 1\n", encoding="utf-8")

    report = diagnose(
        start_dir=tmp_path,
        aws_cli_checker=lambda: True,
    )

    assert report.healthy is False
    assert report.remediations == (f"Fix `{config_path}`, then rerun `awsui doctor`.",)
    assert "awsui init" not in report.remediations[0]


def test_broken_bindings_recommends_checking_file(tmp_path):
    project, bindings_path = prepare_project(tmp_path)
    bindings_path.write_text("{", encoding="utf-8")

    report = diagnose(
        start_dir=project,
        bindings_path=bindings_path,
        aws_cli_checker=lambda: True,
    )

    assert report.healthy is False
    assert report.checks[-1].name == "Local bindings"
    assert report.remediations == (
        f"Check permissions and JSON format for `{bindings_path}`, then rerun "
        "`awsui doctor`.",
    )


def test_profile_load_failure_recommends_checking_aws_files(tmp_path):
    project, bindings_path = prepare_project(tmp_path)

    def fail_to_load_profiles():
        raise OSError("permission denied")

    report = diagnose(
        start_dir=project,
        bindings_path=bindings_path,
        aws_cli_checker=lambda: True,
        profiles_loader=fail_to_load_profiles,
    )

    assert report.healthy is False
    assert report.checks[-1].name == "Local AWS profiles"
    assert report.remediations == (
        "Check your AWS config and credentials files, then rerun `awsui doctor`.",
    )


def test_no_profiles_and_unbound_contexts_provide_concrete_commands(tmp_path):
    project, _bindings_path = prepare_project(tmp_path)
    empty_bindings_path = tmp_path / "empty-bindings.json"

    report = diagnose(
        start_dir=project,
        bindings_path=empty_bindings_path,
        aws_cli_checker=lambda: True,
        profiles_loader=lambda: [],
    )

    failed = {check.name: check.detail for check in report.checks if not check.passed}
    assert failed["Local AWS profiles"] == "none found"
    assert failed["Context dev"] == "not bound"
    assert failed["Context prod"] == "not bound"
    assert report.remediations == (
        "Run `awsui bind dev` and press `c` to create a local AWS profile.",
        "Run `awsui bind dev`.",
        "Run `awsui bind prod`.",
    )


def test_report_remediations_are_failed_only_ordered_and_deduplicated():
    report = DoctorReport(
        checks=(
            DoctorCheck("one", False, "failed", "Do this."),
            DoctorCheck("healthy", True, "passed", "Do not show this."),
            DoctorCheck("duplicate", False, "failed", "Do this."),
            DoctorCheck("two", False, "failed", "Then this."),
        )
    )

    assert report.remediations == ("Do this.", "Then this.")


def test_diagnostics_never_call_sts_or_sso(tmp_path):
    project, bindings_path = prepare_project(tmp_path)

    with (
        patch("awsui.aws_cli.get_caller_identity") as identity,
        patch("awsui.aws_cli.sso_login") as login,
    ):
        diagnose(
            start_dir=project,
            bindings_path=bindings_path,
            aws_cli_checker=lambda: True,
            profiles_loader=lambda: [
                profile("company-dev"),
                profile("company-prod"),
            ],
        )

    identity.assert_not_called()
    login.assert_not_called()
