"""Tests for P5-004 — Reconciliation feedback → RemediationProposal."""
from __future__ import annotations

import json
from pathlib import Path

from calm_forge.reconciler import (
    propose_remediation,
    reconcile,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_kg(tmp_path: Path) -> Path:
    kg = tmp_path / "kg"
    (kg / "_fabric").mkdir(parents=True)
    (kg / "placements").mkdir(parents=True)
    (kg / "workloads").mkdir(parents=True)
    return kg


def _write_escalation(kg: Path, workload_id: str, violations: list) -> dict:
    record = {
        "event_type": "calm.reconcile.escalated",
        "timestamp": "2026-05-09T00:00:00Z",
        "workload_id": workload_id,
        "reason": "unresolvable drift",
        "action": "escalate",
        "violations": violations,
        "deployment_request_id": None,
    }
    esc_file = kg / "_fabric" / "escalations.jsonl"
    with esc_file.open("a") as fh:
        fh.write(json.dumps(record) + "\n")
    return record


def _make_workload_node(kg: Path, workload_id: str, **fields) -> Path:
    slug = workload_id.replace("workload:", "")
    node = {"@type": "Workload", "@id": workload_id, **fields}
    path = kg / "workloads" / f"{slug}.json"
    path.write_text(json.dumps(node))
    return path


def _make_violation(rule: str) -> dict:
    return {"rule": rule, "severity": "violation", "message": f"{rule} violated"}


# ---------------------------------------------------------------------------
# RemediationProposal structure
# ---------------------------------------------------------------------------

def test_remediation_proposal_has_required_fields(tmp_path):
    kg = _make_kg(tmp_path)
    esc = _write_escalation(kg, "workload:fraud-v1", [_make_violation("capability-ceiling")])
    proposal = propose_remediation(esc, kg)
    assert "workload_id" in proposal
    assert "proposed_changes" in proposal
    assert "rationale" in proposal
    assert "confidence" in proposal


def test_remediation_proposal_workload_id_matches(tmp_path):
    kg = _make_kg(tmp_path)
    esc = _write_escalation(kg, "workload:fraud-v1", [_make_violation("capability-ceiling")])
    proposal = propose_remediation(esc, kg)
    assert proposal["workload_id"] == "workload:fraud-v1"


def test_remediation_proposal_proposed_changes_nonempty(tmp_path):
    kg = _make_kg(tmp_path)
    esc = _write_escalation(kg, "workload:fraud-v1", [_make_violation("capability-ceiling")])
    proposal = propose_remediation(esc, kg)
    assert len(proposal["proposed_changes"]) >= 1


def test_remediation_proposal_change_has_field_and_description(tmp_path):
    kg = _make_kg(tmp_path)
    esc = _write_escalation(kg, "workload:fraud-v1", [_make_violation("capability-ceiling")])
    proposal = propose_remediation(esc, kg)
    change = proposal["proposed_changes"][0]
    assert "field" in change
    assert "description" in change


# ---------------------------------------------------------------------------
# Known rule → specific field mapping
# ---------------------------------------------------------------------------

def test_region_violation_proposes_allowed_regions(tmp_path):
    kg = _make_kg(tmp_path)
    esc = _write_escalation(
        kg, "workload:fraud-v1",
        [_make_violation("compliance-requires-region-constraint")]
    )
    proposal = propose_remediation(esc, kg)
    fields = [c["field"] for c in proposal["proposed_changes"]]
    assert "allowed_regions" in fields


def test_region_violation_suggests_observed_regions(tmp_path):
    kg = _make_kg(tmp_path)
    # Write a placement with a known region
    placement = {
        "@type": "Placement",
        "workload_id": "workload:fraud-v1",
        "region": "us-east-1",
    }
    (kg / "placements" / "fraud-placement.json").write_text(json.dumps(placement))
    esc = _write_escalation(
        kg, "workload:fraud-v1",
        [_make_violation("compliance-requires-region-constraint")]
    )
    proposal = propose_remediation(esc, kg)
    region_change = next(c for c in proposal["proposed_changes"] if c["field"] == "allowed_regions")
    assert "us-east-1" in region_change["suggested_value"]


def test_region_violation_includes_current_value(tmp_path):
    kg = _make_kg(tmp_path)
    _make_workload_node(kg, "workload:fraud-v1", allowed_regions=["eu-west-1"])
    esc = _write_escalation(
        kg, "workload:fraud-v1",
        [_make_violation("compliance-requires-region-constraint")]
    )
    proposal = propose_remediation(esc, kg)
    region_change = next(c for c in proposal["proposed_changes"] if c["field"] == "allowed_regions")
    assert "current_value" in region_change


def test_pii_violation_proposes_compliance_scope(tmp_path):
    kg = _make_kg(tmp_path)
    esc = _write_escalation(
        kg, "workload:fraud-v1",
        [_make_violation("pii-requires-compliance-scope")]
    )
    proposal = propose_remediation(esc, kg)
    fields = [c["field"] for c in proposal["proposed_changes"]]
    assert "compliance_scope" in fields


def test_capability_ceiling_proposes_declared_capabilities(tmp_path):
    kg = _make_kg(tmp_path)
    esc = _write_escalation(
        kg, "workload:fraud-v1",
        [_make_violation("capability-ceiling")]
    )
    proposal = propose_remediation(esc, kg)
    fields = [c["field"] for c in proposal["proposed_changes"]]
    assert "declared_capabilities" in fields


# ---------------------------------------------------------------------------
# Confidence levels
# ---------------------------------------------------------------------------

def test_high_confidence_for_known_rule(tmp_path):
    kg = _make_kg(tmp_path)
    esc = _write_escalation(kg, "workload:fraud-v1", [_make_violation("capability-ceiling")])
    proposal = propose_remediation(esc, kg)
    assert proposal["confidence"] == "high"


def test_low_confidence_for_unknown_rule(tmp_path):
    kg = _make_kg(tmp_path)
    esc = _write_escalation(kg, "workload:fraud-v1", [_make_violation("some-unknown-rule")])
    proposal = propose_remediation(esc, kg)
    assert proposal["confidence"] == "low"


def test_no_violations_produces_low_confidence(tmp_path):
    kg = _make_kg(tmp_path)
    esc = {"workload_id": "workload:fraud-v1", "violations": []}
    proposal = propose_remediation(esc, kg)
    assert proposal["confidence"] == "low"


# ---------------------------------------------------------------------------
# reconcile(propose=True) integration
# ---------------------------------------------------------------------------

def _make_drifting_kg(tmp_path: Path) -> Path:
    """Build a minimal KG with a drifting workload ready for reconciliation."""
    kg = tmp_path / "kg"
    (kg / "_fabric").mkdir(parents=True)
    (kg / "placements").mkdir(parents=True)
    (kg / "workloads").mkdir(parents=True)

    placement = {
        "@type": "Placement",
        "workload_id": "workload:fraud-v1",
        "region": "us-east-1",
        "drift_state": {
            "drift_status": "violation",
            "findings": [_make_violation("compliance-requires-region-constraint")],
        },
    }
    (kg / "placements" / "fraud-placement.json").write_text(json.dumps(placement))

    fabric_state = {
        "workloads": [{
            "id": "workload:fraud-v1",
            "drift_status": "violation",
            "placements": [{"region": "us-east-1"}],
        }]
    }
    (kg / "fabric-state.json").write_text(json.dumps(fabric_state))
    return kg


def test_reconcile_propose_true_attaches_proposal(tmp_path):
    kg = _make_drifting_kg(tmp_path)
    result = reconcile(kg, dry_run=True, propose=True)
    escalations = [p for p in result["proposals"] if p["action"] == "escalate"]
    assert all("remediation_proposal" in p for p in escalations)


def test_reconcile_propose_false_no_proposal_attached(tmp_path):
    kg = _make_drifting_kg(tmp_path)
    result = reconcile(kg, dry_run=True, propose=False)
    for p in result["proposals"]:
        assert "remediation_proposal" not in p


def test_reconcile_propose_true_proposal_has_changes(tmp_path):
    kg = _make_drifting_kg(tmp_path)
    result = reconcile(kg, dry_run=True, propose=True)
    for p in result["proposals"]:
        if p.get("remediation_proposal"):
            assert len(p["remediation_proposal"]["proposed_changes"]) >= 1


def test_reconcile_propose_true_proposal_has_rationale(tmp_path):
    kg = _make_drifting_kg(tmp_path)
    result = reconcile(kg, dry_run=True, propose=True)
    for p in result["proposals"]:
        if p.get("remediation_proposal"):
            assert p["remediation_proposal"]["rationale"]
