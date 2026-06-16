"""Tests for kg_inspect — KG status summarisation."""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.intake import (
    intake_acm,
    intake_ansible,
    intake_tfe,
    write_environment_nodes,
    write_placement_nodes,
    write_workload_nodes,
)
from calm_forge.kg_inspect import kg_status

# ---------------------------------------------------------------------------
# Fixtures — reuse from test_intake patterns
# ---------------------------------------------------------------------------

ACM_FIXTURE = {
    "clusters": [
        {"name": "prod-east", "region": "us-east-1", "status": "ready",
         "substrate": "x86", "labels": {"environment": "prod"},
         "capabilities": ["http_read", "vault_dynamic_creds"]},
        {"name": "prod-eu", "region": "eu-west-1", "status": "degraded",
         "substrate": "x86", "labels": {"environment": "prod"},
         "capabilities": ["http_read"]},
    ]
}

AAP_FIXTURE = {
    "jobs": [
        {"id": "j1", "workload_name": "payments", "target_cluster": "prod-east",
         "namespace": "payments", "region": "us-east-1", "finished": "2026-05-01T00:00:00Z",
         "observed_capabilities": ["http_read"]},
    ]
}

TFE_FIXTURE = {
    "workspaces": [
        {"name": "payments-prod", "terraform_version": "1.7.4", "tags": ["pci"],
         "vcs_repo": {}, "working_directory": "", "created_at": "2026-01-01T00:00:00Z",
         "updated_at": "2026-04-01T00:00:00Z", "variables": [], "resources": []},
    ]
}


def _build_kg(tmp_path) -> Path:
    """Build a fully populated KG directory."""
    env_nodes = intake_acm(ACM_FIXTURE)
    write_environment_nodes(env_nodes, tmp_path)
    placement_nodes = intake_ansible(AAP_FIXTURE, env_nodes)
    write_placement_nodes(placement_nodes, tmp_path)
    workload_nodes = intake_tfe(TFE_FIXTURE)
    write_workload_nodes(workload_nodes, tmp_path)
    return tmp_path


# ---------------------------------------------------------------------------
# kg_status — unit tests
# ---------------------------------------------------------------------------

def test_status_empty_dir(tmp_path):
    s = kg_status(tmp_path)
    assert s["environments"]["count"] == 0
    assert s["placements"]["count"] == 0
    assert s["workloads"]["count"] == 0
    assert s["drift_events"]["count"] == 0


def test_status_environment_count(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    write_environment_nodes(env_nodes, tmp_path)
    s = kg_status(tmp_path)
    assert s["environments"]["count"] == 2


def test_status_environment_by_status(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    write_environment_nodes(env_nodes, tmp_path)
    s = kg_status(tmp_path)
    assert s["environments"]["by_status"]["ready"] == 1
    assert s["environments"]["by_status"]["degraded"] == 1


def test_status_placement_count(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    nodes = intake_ansible(AAP_FIXTURE, env_nodes)
    write_placement_nodes(nodes, tmp_path)
    s = kg_status(tmp_path)
    assert s["placements"]["count"] == 1


def test_status_placement_pending_before_drift(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    nodes = intake_ansible(AAP_FIXTURE, env_nodes)
    write_placement_nodes(nodes, tmp_path)
    s = kg_status(tmp_path)
    assert s["placements"]["by_drift_status"].get("pending_first_evaluation", 0) == 1


def test_status_workload_count(tmp_path):
    nodes = intake_tfe(TFE_FIXTURE)
    write_workload_nodes(nodes, tmp_path)
    s = kg_status(tmp_path)
    assert s["workloads"]["count"] == 1


def test_status_workload_reconstructed(tmp_path):
    nodes = intake_tfe(TFE_FIXTURE)
    write_workload_nodes(nodes, tmp_path)
    s = kg_status(tmp_path)
    assert s["workloads"]["reconstructed"] == 1
    assert s["workloads"]["review_required"] == 1


def test_status_overall_unevaluated(tmp_path):
    _build_kg(tmp_path)
    s = kg_status(tmp_path)
    assert s["overall_status"] == "UNEVALUATED"


def test_status_overall_clean_after_drift(tmp_path):
    _build_kg(tmp_path)
    # Manually write drift_state ok onto the placement node
    for path in (tmp_path / "placements").glob("*.json"):
        node = json.loads(path.read_text())
        node["drift_state"] = {
            "last_evaluated": "2026-05-03T12:00:00Z",
            "status": "ok",
            "deviation_hours": None,
            "findings": [],
        }
        path.write_text(json.dumps(node))
    s = kg_status(tmp_path)
    assert s["overall_status"] == "CLEAN"


def test_status_overall_violation(tmp_path):
    _build_kg(tmp_path)
    for path in (tmp_path / "placements").glob("*.json"):
        node = json.loads(path.read_text())
        node["drift_state"] = {
            "last_evaluated": "2026-05-03T12:00:00Z",
            "status": "violation",
            "deviation_hours": None,
            "findings": [{"severity": "violation", "message": "bad region"}],
        }
        path.write_text(json.dumps(node))
    s = kg_status(tmp_path)
    assert s["overall_status"] == "VIOLATION"


def test_status_no_placements_status(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    write_environment_nodes(env_nodes, tmp_path)
    s = kg_status(tmp_path)
    assert s["overall_status"] == "NO_PLACEMENTS"


def test_status_last_evaluated(tmp_path):
    _build_kg(tmp_path)
    for path in (tmp_path / "placements").glob("*.json"):
        node = json.loads(path.read_text())
        node["drift_state"]["last_evaluated"] = "2026-05-03T15:00:00Z"
        node["drift_state"]["status"] = "ok"
        path.write_text(json.dumps(node))
    s = kg_status(tmp_path)
    assert s["placements"]["last_evaluated"] == "2026-05-03T15:00:00Z"


def test_status_placement_manifests_as_edges(tmp_path):
    env_nodes = intake_acm(ACM_FIXTURE)
    nodes = intake_ansible(AAP_FIXTURE, env_nodes)
    write_placement_nodes(nodes, tmp_path)
    s = kg_status(tmp_path)
    assert s["placements"]["manifests_as_edges"] == 1


def test_status_workload_requires_capability_edges(tmp_path):
    _build_kg(tmp_path)
    s = kg_status(tmp_path)
    # TFE-reconstructed Workload nodes have no edges
    assert s["workloads"]["requires_capability_edges"] == 0


def test_status_drift_events(tmp_path):
    event_file = tmp_path / "drift-events.json"
    event_file.write_text(
        '{"event_type":"calm.drift.evaluated","timestamp":"2026-05-03T12:00:00Z","status":"ok"}\n'
        '{"event_type":"calm.drift.evaluated","timestamp":"2026-05-03T13:00:00Z","status":"ok"}\n'
    )
    s = kg_status(tmp_path)
    assert s["drift_events"]["count"] == 2
    assert s["drift_events"]["last_timestamp"] == "2026-05-03T13:00:00Z"


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------

def test_cli_kg_status_output(tmp_path):
    _build_kg(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["kg", "status", "--kg-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "ExecutionEnvironment" in result.output
    assert "Placement" in result.output
    assert "Workload" in result.output


def test_cli_kg_status_json(tmp_path):
    _build_kg(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["kg", "status", "--kg-dir", str(tmp_path), "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "environments" in data
    assert "placements" in data
    assert "workloads" in data
    assert "overall_status" in data


def test_cli_kg_status_empty(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["kg", "status", "--kg-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "NO_PLACEMENTS" in result.output
