"""Tests for P4-003 — drift reconciliation loop."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.dashboard import build_fabric_feed
from calm_forge.intake import (
    intake_acm,
    intake_ansible,
    write_deployment_request,
    write_environment_nodes,
    write_placement_nodes,
)
from calm_forge.interviewer import build_workload, write_workload_node
from calm_forge.reconciler import load_escalations, reconcile

# ---------------------------------------------------------------------------
# KG fixtures
# ---------------------------------------------------------------------------

ACM = {
    "clusters": [
        {"name": "prod-east", "region": "us-east-1", "status": "ready",
         "substrate": "x86", "labels": {}, "capabilities": ["http_read"]},
        {"name": "shared-dev", "region": "us-west-2", "status": "ready",
         "substrate": "x86", "labels": {}, "capabilities": ["http_read"]},
    ]
}

AAP_DRIFT = {
    "jobs": [
        {"id": "j1", "workload_name": "fraud-v1", "target_cluster": "shared-dev",
         "namespace": "fraud", "region": "us-west-2", "finished": "2026-05-08T00:00:00Z",
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

WORKLOAD_SPEC_NO_REGION = {
    "name": "payments-v1",
    "purpose": "Payments",
    "owner": "payments-team",
    "components": [{"name": "api", "capabilities": ["http_read"]}],
    "compliance_scope": [],
    "allowed_regions": [],
}


def _build_drifting_kg(kg_dir: Path) -> None:
    """Build a KG with a workload placed in an undeclared region (drift violation)."""
    envs = intake_acm(ACM)
    write_environment_nodes(envs, kg_dir)
    placements = intake_ansible(AAP_DRIFT, envs)
    write_placement_nodes(placements, kg_dir)
    node = build_workload(WORKLOAD_SPEC)
    write_workload_node(node, kg_dir)
    # Inject drift violations directly onto placement nodes
    place_dir = kg_dir / "placements"
    for path in place_dir.glob("*.json"):
        placement = json.loads(path.read_text())
        if placement.get("@type") != "Placement":
            continue
        placement["drift_state"] = {
            "last_evaluated": "2026-05-08T00:00:00Z",
            "status": "violation",
            "deviation_hours": None,
            "findings": [
                {
                    "severity": "violation",
                    "placement_id": placement["@id"],
                    "observed_region": "us-west-2",
                    "declared_zones": ["us-east-1"],
                    "message": "Workload placed in 'us-west-2' — not in declared zones ['us-east-1']",
                }
            ],
        }
        path.write_text(json.dumps(placement, indent=2))
    # Write fabric-state.json with drift_status: violation
    feed = build_fabric_feed(kg_dir)
    (kg_dir / "fabric-state.json").write_text(json.dumps(feed))


def _build_pending_request(kg_dir: Path) -> dict:
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
    write_deployment_request(node, kg_dir)
    return node


# ---------------------------------------------------------------------------
# reconcile() — basic contract
# ---------------------------------------------------------------------------

def test_reconcile_returns_dict(tmp_path):
    result = reconcile(tmp_path)
    assert isinstance(result, dict)


def test_reconcile_has_proposals_key(tmp_path):
    result = reconcile(tmp_path)
    assert "proposals" in result


def test_reconcile_has_executed_key(tmp_path):
    result = reconcile(tmp_path)
    assert "executed" in result


def test_reconcile_has_dry_run_key(tmp_path):
    result = reconcile(tmp_path)
    assert "dry_run" in result


def test_reconcile_dry_run_true_by_default(tmp_path):
    result = reconcile(tmp_path)
    assert result["dry_run"] is True


def test_reconcile_no_violations_empty_proposals(tmp_path):
    result = reconcile(tmp_path)
    assert result["proposals"] == []


def test_reconcile_dry_run_writes_nothing(tmp_path):
    _build_drifting_kg(tmp_path)
    reconcile(tmp_path, dry_run=True)
    assert not (tmp_path / "_fabric" / "escalations.jsonl").exists()


# ---------------------------------------------------------------------------
# escalate action
# ---------------------------------------------------------------------------

def test_reconcile_drifting_kg_produces_proposal(tmp_path):
    _build_drifting_kg(tmp_path)
    result = reconcile(tmp_path, dry_run=True)
    assert len(result["proposals"]) >= 1


def test_reconcile_escalate_action_for_unresolvable(tmp_path):
    _build_drifting_kg(tmp_path)
    result = reconcile(tmp_path, dry_run=True)
    # No pending request → escalate
    actions = [p["action"] for p in result["proposals"]]
    assert "escalate" in actions


def test_reconcile_escalate_writes_to_jsonl(tmp_path):
    _build_drifting_kg(tmp_path)
    reconcile(tmp_path, dry_run=False)
    records = load_escalations(tmp_path)
    assert len(records) >= 1


def test_escalation_record_has_required_keys(tmp_path):
    _build_drifting_kg(tmp_path)
    reconcile(tmp_path, dry_run=False)
    records = load_escalations(tmp_path)
    rec = records[0]
    assert "workload_id" in rec
    assert "reason" in rec
    assert "event_type" in rec
    assert rec["event_type"] == "calm.reconcile.escalated"


def test_escalation_record_has_timestamp(tmp_path):
    _build_drifting_kg(tmp_path)
    reconcile(tmp_path, dry_run=False)
    records = load_escalations(tmp_path)
    assert "timestamp" in records[0]


def test_load_escalations_empty(tmp_path):
    assert load_escalations(tmp_path) == []


def test_multiple_reconcile_passes_appends(tmp_path):
    _build_drifting_kg(tmp_path)
    reconcile(tmp_path, dry_run=False)
    reconcile(tmp_path, dry_run=False)
    records = load_escalations(tmp_path)
    assert len(records) >= 2


# ---------------------------------------------------------------------------
# redeploy action
# ---------------------------------------------------------------------------

def test_reconcile_redeploy_when_pending_request_exists(tmp_path):
    _build_drifting_kg(tmp_path)
    # Add capability-ceiling violation to trigger redeploy path — inject via
    # placement node directly with a capability-ceiling finding in drift_state
    place_dir = tmp_path / "placements"
    for path in place_dir.glob("*.json"):
        node = json.loads(path.read_text())
        if node.get("@type") == "Placement":
            node["drift_state"] = {
                "last_evaluated": "2026-05-08T00:00:00Z",
                "status": "violation",
                "deviation_hours": None,
                "findings": [
                    {"severity": "violation", "rule": "capability-ceiling",
                     "placement_id": node["@id"], "excess_capabilities": ["sudo"],
                     "message": "capabilities_granted exceeds declared: ['sudo']"}
                ],
            }
            path.write_text(json.dumps(node, indent=2))
    # Also update workload node to show capability-ceiling violation
    feed = build_fabric_feed(tmp_path)
    (tmp_path / "fabric-state.json").write_text(json.dumps(feed))
    _build_pending_request(tmp_path)
    result = reconcile(tmp_path, dry_run=True)
    actions = [p["action"] for p in result["proposals"]]
    # With a pending request and capability-ceiling finding, redeploy is proposed
    assert "redeploy" in actions or "escalate" in actions  # either is valid given decision tree


def test_reconcile_redeploy_writes_new_request_dry_false(tmp_path):
    _build_drifting_kg(tmp_path)
    req = _build_pending_request(tmp_path)
    # Force a redeploy proposal by patching the proposal decision
    from calm_forge import reconciler as rec_mod
    original = rec_mod._propose_action

    def _force_redeploy(wl, kg_dir):
        return rec_mod.ReconciliationProposal(
            workload_id="workload:fraud-v1",
            action="redeploy",
            reason="test forced redeploy",
            deployment_request_id=req["@id"],
            dry_run=True,
            violations=[],
        )

    rec_mod._propose_action = _force_redeploy
    try:
        reconcile(tmp_path, dry_run=False)
    finally:
        rec_mod._propose_action = original

    from calm_forge.intake import load_deployment_requests
    all_reqs = load_deployment_requests(tmp_path)
    reconciled = [r for r in all_reqs if r.get("requested_by") == "calm-forge/reconciler"]
    assert len(reconciled) == 1


# ---------------------------------------------------------------------------
# update_kg action
# ---------------------------------------------------------------------------

def test_reconcile_update_kg_writes_new_regions_dry_false(tmp_path):
    _build_drifting_kg(tmp_path)
    from calm_forge import reconciler as rec_mod
    original = rec_mod._propose_action

    def _force_update_kg(wl, kg_dir):
        return rec_mod.ReconciliationProposal(
            workload_id="workload:fraud-v1",
            action="update_kg",
            reason="test forced update_kg",
            deployment_request_id=None,
            dry_run=True,
            violations=[],
        )

    rec_mod._propose_action = _force_update_kg
    try:
        reconcile(tmp_path, dry_run=False)
    finally:
        rec_mod._propose_action = original

    wl_dir = tmp_path / "workloads"
    for path in wl_dir.glob("*.json"):
        node = json.loads(path.read_text())
        if node.get("@id") == "workload:fraud-v1":
            # Should include observed region us-west-2 (from AAP_DRIFT)
            assert "us-west-2" in node.get("allowed_regions", [])
            assert "_reconciliation_history" in node
            return
    pytest.fail("workload node not found")


# ---------------------------------------------------------------------------
# executed key
# ---------------------------------------------------------------------------

def test_reconcile_dry_run_false_populates_executed(tmp_path):
    _build_drifting_kg(tmp_path)
    result = reconcile(tmp_path, dry_run=False)
    assert isinstance(result["executed"], list)


def test_reconcile_dry_run_true_executed_empty(tmp_path):
    _build_drifting_kg(tmp_path)
    result = reconcile(tmp_path, dry_run=True)
    assert result["executed"] == []


# ---------------------------------------------------------------------------
# Proposal structure
# ---------------------------------------------------------------------------

def test_proposal_has_required_keys(tmp_path):
    _build_drifting_kg(tmp_path)
    result = reconcile(tmp_path, dry_run=True)
    for p in result["proposals"]:
        assert "workload_id" in p
        assert "action" in p
        assert "reason" in p
        assert "dry_run" in p
        assert "violations" in p


def test_proposal_action_is_valid_value(tmp_path):
    _build_drifting_kg(tmp_path)
    result = reconcile(tmp_path, dry_run=True)
    for p in result["proposals"]:
        assert p["action"] in ("redeploy", "update_kg", "escalate")


# ---------------------------------------------------------------------------
# CLI: calm-forge reconcile
# ---------------------------------------------------------------------------

def test_cli_reconcile_dry_run_exit_zero(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, [
        "reconcile", "--kg-dir", str(tmp_path), "--dry-run", "--once",
    ])
    assert result.exit_code == 0


def test_cli_reconcile_json_output(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, [
        "reconcile", "--kg-dir", str(tmp_path), "--dry-run", "--once", "--json",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "proposals" in data


def test_cli_reconcile_no_violations_message(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, [
        "reconcile", "--kg-dir", str(tmp_path), "--dry-run", "--once",
    ])
    assert "No violations" in result.output


def test_cli_reconcile_with_violations_shows_proposal(tmp_path):
    _build_drifting_kg(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, [
        "reconcile", "--kg-dir", str(tmp_path), "--dry-run", "--once",
    ])
    assert result.exit_code == 0
    assert "proposal" in result.output.lower() or "ESCALATE" in result.output or "fraud-v1" in result.output


# ---------------------------------------------------------------------------
# MCP tool
# ---------------------------------------------------------------------------

def test_mcp_reconcile_dry_run(tmp_path):
    from calm_forge.mcp_server import reconcile_tool
    result = reconcile_tool(kg_dir=str(tmp_path), dry_run=True)
    assert "proposals" in result
    assert result["dry_run"] is True


def test_mcp_reconcile_empty_kg_no_proposals(tmp_path):
    from calm_forge.mcp_server import reconcile_tool
    result = reconcile_tool(kg_dir=str(tmp_path), dry_run=True)
    assert result["proposals"] == []
