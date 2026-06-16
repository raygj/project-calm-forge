"""P6-003: intake_backstage and intake_terraform tests."""
from __future__ import annotations

import json
from pathlib import Path

from calm_forge.intake_backstage import (
    _component_to_workload_node,
    _resource_to_env_node,
    intake_backstage,
    intake_backstage_from_file,
)
from calm_forge.intake_terraform import (
    intake_terraform,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

RESOURCE_ENTITY = {
    "apiVersion": "backstage.io/v1alpha1",
    "kind": "Resource",
    "metadata": {
        "name": "prod-east-ocp-01",
        "annotations": {
            "calm.io/environment-id": "env:acm:prod-east-ocp-01",
            "calm.io/cluster-status": "ready",
            "calm.io/region": "us-east-1",
            "calm.io/advertised-capabilities": "encryption_at_rest,http_read",
            "calm.io/label-environment": "prod",
            "calm.io/label-compliance": "pci",
        },
    },
    "spec": {"type": "kubernetes-cluster", "lifecycle": "production", "owner": "group:platform-engineering"},
}

COMPONENT_ENTITY = {
    "apiVersion": "backstage.io/v1alpha1",
    "kind": "Component",
    "metadata": {
        "name": "pci-payments-prod-us-east-1",
        "annotations": {
            "calm.io/workload-id": "workload:pci-payments-prod-us-east-1",
            "calm.io/provenance": "reconstructed",
            "calm.io/review-required": "true",
        },
    },
    "spec": {"type": "service", "lifecycle": "experimental", "owner": "group:platform-engineering"},
}

NON_CLUSTER_RESOURCE = {
    "apiVersion": "backstage.io/v1alpha1",
    "kind": "Resource",
    "metadata": {"name": "some-database", "annotations": {}},
    "spec": {"type": "database", "lifecycle": "production", "owner": "group:dba"},
}

API_ENTITY = {
    "apiVersion": "backstage.io/v1alpha1",
    "kind": "API",
    "metadata": {"name": "my-api", "annotations": {}},
    "spec": {"type": "openapi"},
}

TF_STATE_BASIC = {
    "version": 4,
    "terraform_version": "1.6.0",
    "resources": [
        {
            "type": "aws_instance",
            "name": "app_server",
            "provider": "provider[\"registry.terraform.io/hashicorp/aws\"]",
            "instances": [
                {
                    "attributes": {
                        "id": "i-1234567890abcdef0",
                        "availability_zone": "us-east-1a",
                        "tags": {
                            "workload": "fraud-detection-pipeline",
                            "environment": "prod",
                            "region": "us-east-1",
                        },
                    }
                }
            ],
        }
    ],
}


# ---------------------------------------------------------------------------
# intake_backstage — Resource → ExecutionEnvironment
# ---------------------------------------------------------------------------


def test_resource_to_env_node_id():
    node = _resource_to_env_node(RESOURCE_ENTITY)
    assert node["@id"] == "env:acm:prod-east-ocp-01"


def test_resource_to_env_node_region():
    node = _resource_to_env_node(RESOURCE_ENTITY)
    assert node["region"] == "us-east-1"


def test_resource_to_env_node_status():
    node = _resource_to_env_node(RESOURCE_ENTITY)
    assert node["status"] == "ready"


def test_resource_to_env_node_capabilities_as_list():
    node = _resource_to_env_node(RESOURCE_ENTITY)
    assert node["advertised_capabilities"] == ["encryption_at_rest", "http_read"]


def test_resource_to_env_node_labels():
    node = _resource_to_env_node(RESOURCE_ENTITY)
    assert node["labels"] == {"environment": "prod", "compliance": "pci"}


def test_resource_to_env_node_type():
    node = _resource_to_env_node(RESOURCE_ENTITY)
    assert node["@type"] == "ExecutionEnvironment"


def test_resource_to_env_node_provenance_source():
    node = _resource_to_env_node(RESOURCE_ENTITY)
    assert node["_provenance"]["source"] == "backstage"


# ---------------------------------------------------------------------------
# intake_backstage — Component → Workload
# ---------------------------------------------------------------------------


def test_component_to_workload_node_id():
    node = _component_to_workload_node(COMPONENT_ENTITY)
    assert node["@id"] == "workload:pci-payments-prod-us-east-1"


def test_component_to_workload_node_review_required_true():
    node = _component_to_workload_node(COMPONENT_ENTITY)
    assert node["review_required"] is True


def test_component_to_workload_node_review_required_false():
    entity = {
        "kind": "Component",
        "metadata": {"name": "safe-service", "annotations": {"calm.io/workload-id": "workload:safe", "calm.io/review-required": "false"}},
        "spec": {"owner": "group:eng"},
    }
    node = _component_to_workload_node(entity)
    assert node["review_required"] is False


def test_component_to_workload_node_type():
    node = _component_to_workload_node(COMPONENT_ENTITY)
    assert node["@type"] == "Workload"


def test_component_to_workload_node_provenance_source():
    node = _component_to_workload_node(COMPONENT_ENTITY)
    assert node["_provenance"]["source"] == "backstage"


def test_component_to_workload_node_name():
    node = _component_to_workload_node(COMPONENT_ENTITY)
    assert node["name"] == "pci-payments-prod-us-east-1"


# ---------------------------------------------------------------------------
# intake_backstage — filtering
# ---------------------------------------------------------------------------


def test_non_cluster_resource_is_skipped():
    result = intake_backstage([NON_CLUSTER_RESOURCE])
    assert result["environments"] == []
    assert result["workloads"] == []


def test_non_resource_component_kind_skipped():
    result = intake_backstage([API_ENTITY])
    assert result["environments"] == []
    assert result["workloads"] == []


def test_intake_backstage_list_returns_both():
    result = intake_backstage([RESOURCE_ENTITY, COMPONENT_ENTITY])
    assert len(result["environments"]) == 1
    assert len(result["workloads"]) == 1


def test_intake_backstage_from_file_reads_example():
    catalog_path = Path(__file__).parent.parent / "examples/backstage-catalog/catalog-info.yaml"
    result = intake_backstage_from_file(catalog_path)
    assert len(result["environments"]) == 3
    assert len(result["workloads"]) == 2


# ---------------------------------------------------------------------------
# intake_terraform
# ---------------------------------------------------------------------------


def test_terraform_tags_region():
    nodes = intake_terraform(TF_STATE_BASIC)
    assert len(nodes) == 1
    assert nodes[0]["region"] == "us-east-1"


def test_terraform_availability_zone_strips_letter():
    state = {
        "resources": [
            {
                "type": "aws_instance",
                "name": "web",
                "instances": [{"attributes": {"availability_zone": "us-east-1a", "tags": {}}}],
            }
        ]
    }
    nodes = intake_terraform(state)
    assert nodes[0]["region"] == "us-east-1"


def test_terraform_tags_workload_prefixed():
    nodes = intake_terraform(TF_STATE_BASIC)
    assert nodes[0]["workload_id"] == "workload:fraud-detection-pipeline"


def test_terraform_calm_workload_id_tag_used_directly():
    state = {
        "resources": [
            {
                "type": "aws_rds_instance",
                "name": "db",
                "instances": [
                    {
                        "attributes": {
                            "region": "eu-west-1",
                            "tags": {"calm_workload_id": "workload:my-service"},
                        }
                    }
                ],
            }
        ]
    }
    nodes = intake_terraform(state)
    assert nodes[0]["workload_id"] == "workload:my-service"


def test_terraform_deduplication():
    state = {
        "resources": [
            {
                "type": "aws_instance",
                "name": "server_a",
                "instances": [{"attributes": {"region": "us-east-1", "tags": {"workload": "svc"}}}],
            },
            {
                "type": "aws_instance",
                "name": "server_b",
                "instances": [{"attributes": {"region": "us-east-1", "tags": {"workload": "svc"}}}],
            },
        ]
    }
    nodes = intake_terraform(state)
    assert len(nodes) == 1


def test_terraform_no_region_skipped():
    state = {
        "resources": [
            {
                "type": "aws_s3_bucket",
                "name": "logs",
                "instances": [{"attributes": {"tags": {"workload": "logger"}}}],
            }
        ]
    }
    nodes = intake_terraform(state)
    assert nodes == []


def test_terraform_empty_state():
    assert intake_terraform({}) == []


def test_terraform_node_type():
    nodes = intake_terraform(TF_STATE_BASIC)
    assert nodes[0]["@type"] == "Placement"


def test_terraform_provenance_source():
    nodes = intake_terraform(TF_STATE_BASIC)
    assert nodes[0]["_provenance"]["source"] == "terraform"


# ---------------------------------------------------------------------------
# kg_bootstrap integration
# ---------------------------------------------------------------------------


def test_bootstrap_backstage_source_writes_nodes(tmp_path):
    from calm_forge.kg_bootstrap import BootstrapConfig, kg_bootstrap

    catalog_path = Path(__file__).parent.parent / "examples/backstage-catalog/catalog-info.yaml"
    cfg = BootstrapConfig(
        kg_dir=tmp_path,
        sources=["backstage"],
        backstage_path=catalog_path,
    )
    result = kg_bootstrap(cfg)
    assert "backstage" in result.sources_run
    assert result.nodes_written["backstage"] == 5  # 3 envs + 2 workloads
    assert (tmp_path / "environments").exists()
    assert (tmp_path / "workloads").exists()


def test_bootstrap_terraform_source_writes_nodes(tmp_path):
    from calm_forge.kg_bootstrap import BootstrapConfig, kg_bootstrap

    state_path = tmp_path / "test.tfstate"
    state_path.write_text(json.dumps(TF_STATE_BASIC))

    cfg = BootstrapConfig(
        kg_dir=tmp_path,
        sources=["terraform"],
        terraform_state_paths=[state_path],
    )
    result = kg_bootstrap(cfg)
    assert "terraform" in result.sources_run
    assert result.nodes_written["terraform"] == 1
    assert (tmp_path / "placements").exists()


def test_bootstrap_history_records_sources(tmp_path):
    from calm_forge.kg_bootstrap import BootstrapConfig, kg_bootstrap, load_bootstrap_history

    catalog_path = Path(__file__).parent.parent / "examples/backstage-catalog/catalog-info.yaml"
    state_path = tmp_path / "test.tfstate"
    state_path.write_text(json.dumps(TF_STATE_BASIC))

    cfg = BootstrapConfig(
        kg_dir=tmp_path,
        sources=["backstage", "terraform"],
        backstage_path=catalog_path,
        terraform_state_paths=[state_path],
    )
    kg_bootstrap(cfg)
    history = load_bootstrap_history(tmp_path)
    assert len(history) == 1
    assert "backstage" in history[0]["sources_run"]
    assert "terraform" in history[0]["sources_run"]
