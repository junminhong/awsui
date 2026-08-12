"""Tests for pure Context Dashboard state and launch parsing."""

import json
from pathlib import Path

import pytest

from awsui.context.dashboard import (
    ContextStatus,
    load_dashboard,
)
from awsui.tui.launch import LaunchCommandError, detect_tools, parse_launch_command


def profile(name: str):
    return {
        "name": name,
        "kind": "sso",
        "account": None,
        "role": None,
        "region": "ap-northeast-1",
        "session": "company",
        "source": "/tmp/aws/config",
    }


def write_project(path: Path) -> None:
    (path / ".awsui.yaml").write_text(
        """version: 1
project: payment-service
contexts:
  dev:
    account: "111111111111"
    region: ap-northeast-1
  qa:
    account: "222222222222"
    region: ap-northeast-1
  prod:
    account: "999999999999"
    region: ap-northeast-1
    protected: true
""",
        encoding="utf-8",
    )


def test_load_dashboard_preserves_order_and_classifies_bindings(tmp_path):
    write_project(tmp_path)
    bindings_path = tmp_path / "bindings.json"
    bindings_path.write_text(
        json.dumps(
            {
                "version": 1,
                "bindings": {
                    "payment-service": {
                        "qa": "missing-profile",
                        "prod": "company-prod",
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    snapshot = load_dashboard(
        start_dir=tmp_path,
        bindings_path=bindings_path,
        profiles_loader=lambda: [profile("company-prod")],
    )

    assert snapshot.project == "payment-service"
    assert [context.name for context in snapshot.contexts] == ["dev", "qa", "prod"]
    assert [context.status for context in snapshot.contexts] == [
        ContextStatus.UNBOUND,
        ContextStatus.PROFILE_MISSING,
        ContextStatus.READY,
    ]
    assert snapshot.get("prod").protected is True
    assert snapshot.get("unknown") is None


def test_detect_tools_keeps_known_order_and_resolved_path():
    available = {
        "codex": "/tools/codex",
        "terraform": "/tools/terraform",
        "aws": "/tools/aws",
    }

    tools = detect_tools(
        {"PATH": "/tools"},
        resolver=lambda executable, _path: available.get(executable),
    )

    assert [(tool.label, tool.executable, tool.path) for tool in tools] == [
        ("Codex", "codex", "/tools/codex"),
        ("Terraform", "terraform", "/tools/terraform"),
        ("AWS CLI", "aws", "/tools/aws"),
    ]


def test_parse_launch_command_returns_direct_argv():
    assert parse_launch_command('codex --model "gpt 5"') == (
        "codex",
        "--model",
        "gpt 5",
    )


@pytest.mark.parametrize(
    "command",
    ["", "   ", "aws s3 ls | jq", "terraform plan && echo done", "'unterminated"],
)
def test_parse_launch_command_rejects_empty_shell_or_invalid_input(command):
    with pytest.raises(LaunchCommandError):
        parse_launch_command(command)
