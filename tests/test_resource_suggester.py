"""Tests for awsui.resource_suggester."""

from datetime import datetime, timedelta

from awsui.resource_suggester import ResourceCache, ResourceSuggester


def test_resource_cache_respects_ttl(monkeypatch):
    cache = ResourceCache(ttl_seconds=10)
    start_time = datetime(2024, 1, 1, 0, 0, 0)

    class FrozenDatetime(datetime):
        @classmethod
        def now(cls):
            return start_time

    monkeypatch.setattr("awsui.resource_suggester.datetime", FrozenDatetime)
    cache.set("key", ["value"])
    assert cache.get("key") == ["value"]

    class SlightlyLaterDatetime(datetime):
        @classmethod
        def now(cls):
            return start_time + timedelta(seconds=5)

    monkeypatch.setattr("awsui.resource_suggester.datetime", SlightlyLaterDatetime)
    assert cache.get("key") == ["value"]

    class ExpiredDatetime(datetime):
        @classmethod
        def now(cls):
            return start_time + timedelta(seconds=11)

    monkeypatch.setattr("awsui.resource_suggester.datetime", ExpiredDatetime)
    assert cache.get("key") is None


def test_run_aws_command_appends_context(monkeypatch):
    captured = {}

    def fake_run(args, capture_output, text, timeout, check):
        captured["args"] = list(args)

        class Result:
            returncode = 0
            stdout = "[]"

        return Result()

    monkeypatch.setattr("awsui.resource_suggester.subprocess.run", fake_run)
    suggester = ResourceSuggester(profile="dev", region="us-west-2")
    command = ["aws", "ec2", "describe-instances"]

    output = suggester._run_aws_command(command)

    assert output == "[]"
    assert command == [
        "aws",
        "ec2",
        "describe-instances",
        "--profile",
        "dev",
        "--region",
        "us-west-2",
        "--output",
        "json",
    ]
    assert captured["args"] == command


def test_get_suggestions_for_parameter_uses_mapping(monkeypatch):
    suggester = ResourceSuggester()
    calls = {}

    def fake_instances():
        calls["instances"] = True
        return ["i-123"]

    monkeypatch.setattr(suggester, "get_ec2_instance_ids", fake_instances)
    suggestions = suggester.get_suggestions_for_parameter(
        "ec2", "describe-instances", "--instance-ids"
    )

    assert calls == {"instances": True}
    assert suggestions == ["i-123"]


def test_get_suggestions_for_parameter_s3(monkeypatch):
    suggester = ResourceSuggester()
    monkeypatch.setattr(suggester, "get_s3_buckets", lambda: ["bucket-a"])

    assert suggester.get_suggestions_for_parameter("s3", "ls", "--any") == ["bucket-a"]
