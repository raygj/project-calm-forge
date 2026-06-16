"""Tests for P4-002 — deployment observation, KG writeback, and post-deploy drift check."""
from __future__ import annotations

import json
from pathlib import Path

from calm_forge.dashboard import build_fabric_feed
from calm_forge.drift_evaluator import drift_check_post_deploy
from calm_forge.intake import (
    intake_acm,
    intake_ansible,
    intake_deployment_completion,
    load_deployment_statuses,
    write_deployment_request,
    write_deployment_status,
    write_environment_nodes,
    write_placement_nodes,
)
from calm_forge.interviewer import build_workload, write_workload_node
from calm_forge.kg_inspect import kg_status
from calm_forge.webhook import handle_deployment_completion

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

COMPLETION_PAYLOAD = {
    "jobs": [
        {
            "id": "j1",
            "workload_name": "fraud-v1",
            "target_cluster": "prod-east",
            "region": "us-east-1",
            "finished": "2026-05-08T12:00:00Z",
            "outcome": "success",
            "observed_capabilities": ["http_read", "confidential_compute"],
            "deployment_request_id": "deploy-req:fraud-v1:abcd1234",
        }
    ]
}

FAILED_PAYLOAD = {
    "jobs": [
        {
            "id": "j2",
            "workload_name": "fraud-v1",
            "target_cluster": "shared-dev",
            "region": "us-west-2",
            "finished": "2026-05-08T13:00:00Z",
            "outcome": "failed",
            "observed_capabilities": [],
        }
    ]
}

ACM = {
    "clusters": [
        {"name": "prod-east", "region": "us-east-1", "status": "ready",
         "substrate": "x86", "labels": {"compliance": "pci"},
         "capabilities": ["confidential_compute", "http_read"]},
    ]
}

AAP = {
    "jobs": [
        {"id": "j0", "workload_name": "fraud-v1", "target_cluster": "prod-east",
         "namespace": "fraud", "region": "us-east-1", "finished": "2026-05-01T00:00:00Z",
         "observed_capabilities": ["http_read"]},
    ]
}

WORKLOAD_SPEC = {
    "name": "fraud-v1",
    "purpose": "Fraud detection",
    "owner": "fraud-team",
    "components": [{"name": "scorer", "capabilities": ["http_read"]}],
    "compliance_scope": ["PCI-DSS-v4:req-3"],
    "allowed_regions": ["us-east-1"],
}


def _build_kg(kg_dir: Path) -> None:
    envs = intake_acm(ACM)
    write_environment_nodes(envs, kg_dir)
    placements = intake_ansible(AAP, envs)
    write_placement_nodes(placements, kg_dir)
    node = build_workload(WORKLOAD_SPEC)
    write_workload_node(node, kg_dir)


# ---------------------------------------------------------------------------
# intake_deployment_completion
# ---------------------------------------------------------------------------

def test_intake_completion_returns_list():
    nodes = intake_deployment_completion(COMPLETION_PAYLOAD)
    assert isinstance(nodes, list)


def test_intake_completion_produces_one_node():
    nodes = intake_deployment_completion(COMPLETION_PAYLOAD)
    assert len(nodes) == 1


def test_intake_completion_node_type():
    nodes = intake_deployment_completion(COMPLETION_PAYLOAD)
    assert nodes[0]["@type"] == "DeploymentStatus"


def test_intake_completion_workload_id():
    nodes = intake_deployment_completion(COMPLETION_PAYLOAD)
    assert nodes[0]["workload_id"] == "workload:fraud-v1"


def test_intake_completion_environment_id():
    nodes = intake_deployment_completion(COMPLETION_PAYLOAD)
    assert nodes[0]["environment_id"] == "env:acm:prod-east"


def test_intake_completion_outcome():
    nodes = intake_deployment_completion(COMPLETION_PAYLOAD)
    assert nodes[0]["outcome"] == "success"


def test_intake_completion_links_request_id():
    nodes = intake_deployment_completion(COMPLETION_PAYLOAD)
    assert nodes[0]["deployment_request_id"] == "deploy-req:fraud-v1:abcd1234"


def test_intake_completion_no_request_id_is_none():
    nodes = intake_deployment_completion(FAILED_PAYLOAD)
    assert nodes[0]["deployment_request_id"] is None


def test_intake_completion_observed_capabilities():
    nodes = intake_deployment_completion(COMPLETION_PAYLOAD)
    assert "http_read" in nodes[0]["observed_capabilities"]


def test_intake_completion_empty_fixture():
    nodes = intake_deployment_completion({"jobs": []})
    assert nodes == []


# ---------------------------------------------------------------------------
# write_deployment_status + load_deployment_statuses
# ---------------------------------------------------------------------------

def test_write_deployment_status_creates_file(tmp_path):
    node = intake_deployment_completion(COMPLETION_PAYLOAD)[0]
    path = write_deployment_status(node, tmp_path)
    assert path.exists()


def test_write_deployment_status_correct_type(tmp_path):
    node = intake_deployment_completion(COMPLETION_PAYLOAD)[0]
    path = write_deployment_status(node, tmp_path)
    assert json.loads(path.read_text())["@type"] == "DeploymentStatus"


def test_load_deployment_statuses_empty(tmp_path):
    assert load_deployment_statuses(tmp_path) == []


def test_load_deployment_statuses_returns_node(tmp_path):
    node = intake_deployment_completion(COMPLETION_PAYLOAD)[0]
    write_deployment_status(node, tmp_path)
    loaded = load_deployment_statuses(tmp_path)
    assert len(loaded) == 1


def test_load_deployment_statuses_filters_by_workload(tmp_path):
    nodes = intake_deployment_completion(COMPLETION_PAYLOAD)
    write_deployment_status(nodes[0], tmp_path)
    result = load_deployment_statuses(tmp_path, workload_id="workload:fraud-v1")
    assert len(result) == 1
    result_other = load_deployment_statuses(tmp_path, workload_id="workload:other")
    assert result_other == []


def test_load_deployment_statuses_filters_by_request_id(tmp_path):
    nodes = intake_deployment_completion(COMPLETION_PAYLOAD)
    write_deployment_status(nodes[0], tmp_path)
    result = load_deployment_statuses(tmp_path, deployment_request_id="deploy-req:fraud-v1:abcd1234")
    assert len(result) == 1
    result_other = load_deployment_statuses(tmp_path, deployment_request_id="deploy-req:other:0000")
    assert result_other == []


# ---------------------------------------------------------------------------
# drift_check_post_deploy
# ---------------------------------------------------------------------------

def test_drift_check_post_deploy_returns_dict(tmp_path):
    _build_kg(tmp_path)
    node = intake_deployment_completion(COMPLETION_PAYLOAD)[0]
    result = drift_check_post_deploy(node, tmp_path)
    assert isinstance(result, dict)


def test_drift_check_post_deploy_has_deployment_status_id(tmp_path):
    _build_kg(tmp_path)
    node = intake_deployment_completion(COMPLETION_PAYLOAD)[0]
    result = drift_check_post_deploy(node, tmp_path)
    assert "deployment_status_id" in result


def test_drift_check_post_deploy_updates_node_drift_result(tmp_path):
    _build_kg(tmp_path)
    node = intake_deployment_completion(COMPLETION_PAYLOAD)[0]
    drift_check_post_deploy(node, tmp_path)
    assert node["drift_result"] is not None
    assert "status" in node["drift_result"]


def test_drift_check_post_deploy_no_workload(tmp_path):
    # No workload in KG — graceful no-op
    node = intake_deployment_completion(COMPLETION_PAYLOAD)[0]
    result = drift_check_post_deploy(node, tmp_path)
    assert result["status"] == "no_workload_found"


def test_drift_check_post_deploy_emits_drift_event(tmp_path):
    _build_kg(tmp_path)
    node = intake_deployment_completion(COMPLETION_PAYLOAD)[0]
    drift_check_post_deploy(node, tmp_path)
    event_file = tmp_path / "drift-events.json"
    assert event_file.exists()


# ---------------------------------------------------------------------------
# handle_deployment_completion (webhook handler)
# ---------------------------------------------------------------------------

def test_handle_deployment_completion_returns_processed_count(tmp_path):
    result = handle_deployment_completion(COMPLETION_PAYLOAD, tmp_path, run_drift_check=False)
    assert result["processed"] == 1


def test_handle_deployment_completion_writes_node(tmp_path):
    handle_deployment_completion(COMPLETION_PAYLOAD, tmp_path, run_drift_check=False)
    nodes = load_deployment_statuses(tmp_path)
    assert len(nodes) == 1


def test_handle_deployment_completion_includes_nodes_key(tmp_path):
    result = handle_deployment_completion(COMPLETION_PAYLOAD, tmp_path, run_drift_check=False)
    assert "nodes" in result
    assert result["nodes"][0]["@type"] == "DeploymentStatus"


def test_handle_deployment_completion_runs_drift_check(tmp_path):
    _build_kg(tmp_path)
    result = handle_deployment_completion(COMPLETION_PAYLOAD, tmp_path, run_drift_check=True)
    assert "drift_results" in result
    assert len(result["drift_results"]) == 1


def test_handle_deployment_completion_no_drift_check_no_key(tmp_path):
    result = handle_deployment_completion(COMPLETION_PAYLOAD, tmp_path, run_drift_check=False)
    assert "drift_results" not in result


# ---------------------------------------------------------------------------
# kg_status includes deployments
# ---------------------------------------------------------------------------

def test_kg_status_has_deployments_key(tmp_path):
    status = kg_status(tmp_path)
    assert "deployments" in status


def test_kg_status_deployments_empty(tmp_path):
    status = kg_status(tmp_path)
    assert status["deployments"]["pending"] == 0
    assert status["deployments"]["completed"] == 0


def test_kg_status_deployments_counts_request(tmp_path):
    node = {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "DeploymentRequest",
        "@id": "deploy-req:fraud-v1:abcd1234",
        "workload_id": "workload:fraud-v1",
        "attestation_sha": "a" * 64,
        "artifact_paths": [],
        "target_branch": None,
        "target_path": "/tmp",
        "requested_at": "2026-05-08T00:00:00+00:00",
        "requested_by": "test",
        "status": "pending",
        "_provenance": {},
    }
    write_deployment_request(node, tmp_path)
    status = kg_status(tmp_path)
    assert status["deployments"]["pending"] == 1
    assert status["deployments"]["requests"] == 1


def test_kg_status_deployments_counts_completed_status(tmp_path):
    completion_node = intake_deployment_completion(COMPLETION_PAYLOAD)[0]
    write_deployment_status(completion_node, tmp_path)
    status = kg_status(tmp_path)
    assert status["deployments"]["completed"] == 1


# ---------------------------------------------------------------------------
# build_fabric_feed includes deployments
# ---------------------------------------------------------------------------

def test_feed_has_deployments_key(tmp_path):
    feed = build_fabric_feed(tmp_path)
    assert "deployments" in feed


def test_feed_deployments_empty_by_default(tmp_path):
    feed = build_fabric_feed(tmp_path)
    assert feed["deployments"] == []


def test_feed_summary_has_deployments_pending(tmp_path):
    feed = build_fabric_feed(tmp_path)
    assert "deployments_pending" in feed["summary"]


def test_feed_deployments_includes_request(tmp_path):
    node = {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "DeploymentRequest",
        "@id": "deploy-req:fraud-v1:abcd1234",
        "workload_id": "workload:fraud-v1",
        "attestation_sha": "a" * 64,
        "artifact_paths": [],
        "target_branch": None,
        "target_path": "/tmp",
        "requested_at": "2026-05-08T00:00:00+00:00",
        "requested_by": "test",
        "status": "pending",
        "_provenance": {},
    }
    write_deployment_request(node, tmp_path)
    feed = build_fabric_feed(tmp_path)
    assert len(feed["deployments"]) == 1
    assert feed["deployments"][0]["workload_id"] == "workload:fraud-v1"
