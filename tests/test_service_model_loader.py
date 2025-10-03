"""Tests for awsui.service_model_loader."""

import json

from awsui.service_model_loader import ServiceModelLoader


def test_camel_to_kebab_conversion():
    assert ServiceModelLoader._camel_to_kebab("DescribeInstances") == "describe-instances"
    assert ServiceModelLoader._camel_to_kebab("DBCluster") == "db-cluster"


def test_get_service_operations_reads_model(tmp_path):
    loader = ServiceModelLoader()
    service_dir = tmp_path / "ec2" / "2024-01-01"
    service_dir.mkdir(parents=True)
    service_file = service_dir / "service-2.json"
    service_file.write_text(
        json.dumps({
            "operations": {
                "DescribeInstances": {},
                "StartInstances": {},
            }
        }),
        encoding="utf-8",
    )

    loader.botocore_data_path = tmp_path
    loader._service_cache.clear()

    operations = loader.get_service_operations("ec2")
    assert operations == ["describe-instances", "start-instances"]

    # Removing the file should not break cached result on subsequent calls
    service_file.unlink()
    assert loader.get_service_operations("ec2") == operations


def test_get_service_operations_uses_cache(monkeypatch):
    loader = ServiceModelLoader()
    calls = {"count": 0}

    def fake_load(service):
        calls["count"] += 1
        return {"operations": {"ListThings": {}}}

    monkeypatch.setattr(loader, "_load_service_model", fake_load)

    assert loader.get_service_operations("iot") == ["list-things"]
    assert loader.get_service_operations("iot") == ["list-things"]
    assert calls["count"] == 1


def test_get_operation_parameters_returns_cli_names(monkeypatch):
    loader = ServiceModelLoader()

    def fake_load(service):
        return {
            "operations": {
                "DescribeInstances": {
                    "input": {"shape": "DescribeInstancesRequest"}
                }
            },
            "shapes": {
                "DescribeInstancesRequest": {
                    "members": {
                        "InstanceIds": {},
                        "MaxResults": {},
                    }
                }
            },
        }

    monkeypatch.setattr(loader, "_load_service_model", fake_load)

    params = loader.get_operation_parameters("ec2", "describe-instances")
    assert set(params) == {"--instance-ids", "--max-results"}


def test_get_operation_parameters_missing_input(monkeypatch):
    loader = ServiceModelLoader()

    def fake_load(service):
        return {"operations": {"Describe": {}}}

    monkeypatch.setattr(loader, "_load_service_model", fake_load)
    assert loader.get_operation_parameters("ec2", "describe") == []
