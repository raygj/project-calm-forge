"""Tests for P6-001 — interview_from_proposal + build_workload prefill."""
from __future__ import annotations

import json
from pathlib import Path

from calm_forge.interviewer import (
    _apply_proposal_patches,
    _workload_node_to_spec,
    build_workload,
    interview_from_proposal,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_kg(tmp_path: Path) -> Path:
    kg = tmp_path / "kg"
    (kg / "workloads").mkdir(parents=True)
    (kg / "_fabric").mkdir(parents=True)
    return kg


def _workload_node(
    workload_id: str = "workload:payments-v2",
    **fields,
) -> dict:
    return {
        "@type": "Workload",
        "@id": workload_id,
        "name": fields.pop("name", "payments-v2"),
        **fields,
    }


def _proposal(
    workload_id: str = "workload:payments-v2",
    changes: list | None = None,
    confidence: str = "high",
) -> dict:
    return {
        "workload_id": workload_id,
        "proposed_changes": changes or [],
        "rationale": "Drift detected",
        "confidence": confidence,
    }


def _region_change(suggested: list[str] | None = None, current: list[str] | None = None) -> dict:
    change = {"field": "allowed_regions", "description": "Region constraint needed", "rule": "compliance-requires-region-constraint"}
    if suggested is not None:
        change["suggested_value"] = suggested
    if current is not None:
        change["current_value"] = current
    return change


def _compliance_change(suggested: list[str] | None = None) -> dict:
    change = {"field": "compliance_scope", "description": "Add compliance scope", "rule": "pii-requires-compliance-scope"}
    if suggested is not None:
        change["suggested_value"] = suggested
    return change


def _capability_change(suggested: list[str] | None = None) -> dict:
    change = {"field": "declared_capabilities", "description": "Update declared capabilities", "rule": "capability-ceiling"}
    if suggested is not None:
        change["suggested_value"] = suggested
    return change


# ---------------------------------------------------------------------------
# _workload_node_to_spec
# ---------------------------------------------------------------------------

def test_node_to_spec_round_trips_name():
    node = _workload_node(name="fraud-detection")
    spec = _workload_node_to_spec(node)
    assert spec["name"] == "fraud-detection"


def test_node_to_spec_round_trips_compliance_scope():
    node = _workload_node(compliance_scope=["PCI-DSS-v4:req-3", "HIPAA:164.312"])
    spec = _workload_node_to_spec(node)
    assert spec["compliance_scope"] == ["PCI-DSS-v4:req-3", "HIPAA:164.312"]


def test_node_to_spec_round_trips_declared_capabilities():
    node = _workload_node(declared_capabilities=["pii_read", "vault_dynamic_creds"])
    spec = _workload_node_to_spec(node)
    assert spec["declared_capabilities"] == ["pii_read", "vault_dynamic_creds"]


def test_node_to_spec_round_trips_allowed_regions_direct():
    node = _workload_node(allowed_regions=["us-east-1", "eu-west-1"])
    spec = _workload_node_to_spec(node)
    assert spec["allowed_regions"] == ["us-east-1", "eu-west-1"]


def test_node_to_spec_extracts_allowed_regions_from_policy():
    node = _workload_node()
    node["policies"] = [
        {
            "@type": "Policy",
            "predicate_type": "compliance_boundary",
            "allowed_regions": ["ap-southeast-1"],
        }
    ]
    spec = _workload_node_to_spec(node)
    assert spec["allowed_regions"] == ["ap-southeast-1"]


def test_node_to_spec_with_minimal_node_does_not_raise():
    node = {"@id": "workload:minimal"}
    spec = _workload_node_to_spec(node)
    assert spec["name"] == "minimal"
    assert spec["compliance_scope"] == []
    assert spec["allowed_regions"] == []
    assert spec["components"] == []


def test_node_to_spec_maps_nodes_to_components():
    node = _workload_node()
    node["nodes"] = [
        {
            "@type": "WorkloadComponent",
            "@id": "workload:payments-v2:api",
            "name": "api",
            "declared_capabilities": ["http_read"],
        }
    ]
    spec = _workload_node_to_spec(node)
    assert len(spec["components"]) == 1
    assert spec["components"][0]["name"] == "api"
    assert spec["components"][0]["capabilities"] == ["http_read"]


# ---------------------------------------------------------------------------
# _apply_proposal_patches
# ---------------------------------------------------------------------------

def test_patch_allowed_regions_with_suggested_value():
    spec = {"name": "w", "allowed_regions": ["eu-west-1"]}
    patched, fields = _apply_proposal_patches(spec, [_region_change(suggested=["us-east-1"])])
    assert patched["allowed_regions"] == ["us-east-1"]
    assert "allowed_regions" in fields


def test_patch_compliance_scope_with_suggested_value():
    spec = {"name": "w", "compliance_scope": []}
    patched, fields = _apply_proposal_patches(spec, [_compliance_change(suggested=["PCI-DSS-v4:req-3"])])
    assert patched["compliance_scope"] == ["PCI-DSS-v4:req-3"]
    assert "compliance_scope" in fields


def test_patch_declared_capabilities_with_suggested_value():
    spec = {"name": "w", "declared_capabilities": []}
    patched, fields = _apply_proposal_patches(spec, [_capability_change(suggested=["pii_read"])])
    assert patched["declared_capabilities"] == ["pii_read"]
    assert "declared_capabilities" in fields


def test_patch_without_suggested_value_does_not_modify_spec():
    spec = {"name": "w", "allowed_regions": ["eu-west-1"]}
    patched, fields = _apply_proposal_patches(spec, [_region_change()])
    assert patched["allowed_regions"] == ["eu-west-1"]
    assert "allowed_regions" not in fields


def test_patch_returns_prefilled_field_names():
    spec = {"name": "w"}
    _, fields = _apply_proposal_patches(
        spec,
        [_region_change(suggested=["us-east-1"]), _compliance_change(suggested=["PCI-DSS-v4:req-3"])],
    )
    assert "allowed_regions" in fields
    assert "compliance_scope" in fields


def test_patch_components_field_added_to_prefilled_advisory():
    spec = {"name": "w"}
    _, fields = _apply_proposal_patches(
        spec, [{"field": "components", "description": "structural", "rule": "x", "suggested_value": []}]
    )
    assert "components" in fields


def test_patch_unknown_field_is_skipped():
    spec = {"name": "w"}
    patched, fields = _apply_proposal_patches(
        spec, [{"field": "unknown_field", "description": "d", "rule": "r", "suggested_value": "x"}]
    )
    assert "unknown_field" not in patched
    assert fields == []


def test_patch_does_not_mutate_original_spec():
    spec = {"name": "w", "allowed_regions": ["eu-west-1"]}
    _apply_proposal_patches(spec, [_region_change(suggested=["us-east-1"])])
    assert spec["allowed_regions"] == ["eu-west-1"]


# ---------------------------------------------------------------------------
# interview_from_proposal
# ---------------------------------------------------------------------------

def test_interview_from_proposal_prepopulates_allowed_regions(tmp_path):
    kg = _make_kg(tmp_path)
    node = _workload_node(allowed_regions=["eu-west-1"])
    (kg / "workloads" / "payments-v2.json").write_text(json.dumps(node))

    proposal = _proposal(changes=[_region_change(suggested=["us-east-1"])])
    result = interview_from_proposal(proposal, kg)

    wl = result["workload"]
    region_policy = next(
        (p for p in wl.get("policies", []) if p.get("predicate_type") == "compliance_boundary"),
        None,
    )
    assert region_policy is not None
    assert "us-east-1" in region_policy["allowed_regions"]


def test_interview_from_proposal_with_no_workload_kg_node_does_not_raise(tmp_path):
    kg = _make_kg(tmp_path)
    proposal = _proposal(changes=[_region_change(suggested=["us-east-1"])])
    result = interview_from_proposal(proposal, kg)
    assert "workload" in result


def test_interview_from_proposal_returns_prefilled_fields(tmp_path):
    kg = _make_kg(tmp_path)
    proposal = _proposal(changes=[_region_change(suggested=["us-east-1"])])
    result = interview_from_proposal(proposal, kg)
    assert "prefilled_fields" in result
    assert "allowed_regions" in result["prefilled_fields"]


def test_interview_from_proposal_returns_proposal_confidence(tmp_path):
    kg = _make_kg(tmp_path)
    proposal = _proposal(confidence="medium", changes=[])
    result = interview_from_proposal(proposal, kg)
    assert result["proposal_confidence"] == "medium"


def test_interview_from_proposal_returns_workload_id(tmp_path):
    kg = _make_kg(tmp_path)
    proposal = _proposal(workload_id="workload:payments-v2", changes=[])
    result = interview_from_proposal(proposal, kg)
    assert result["workload_id"] == "workload:payments-v2"


def test_interview_from_proposal_low_confidence_default(tmp_path):
    kg = _make_kg(tmp_path)
    proposal = {"workload_id": "workload:x", "proposed_changes": [], "rationale": "r"}
    result = interview_from_proposal(proposal, kg)
    assert result["proposal_confidence"] == "low"


# ---------------------------------------------------------------------------
# build_workload with prefill
# ---------------------------------------------------------------------------

def test_build_workload_prefill_patches_allowed_regions():
    spec = {"name": "fraud-v1", "allowed_regions": ["eu-west-1"]}
    proposal = _proposal(changes=[_region_change(suggested=["us-east-1"])])
    node = build_workload(spec, prefill=proposal)
    region_policy = next(
        (p for p in node.get("policies", []) if p.get("predicate_type") == "compliance_boundary"),
        None,
    )
    assert region_policy is not None
    assert "us-east-1" in region_policy["allowed_regions"]


def test_build_workload_prefill_none_behaves_same_as_before():
    spec = {
        "name": "fraud-v1",
        "allowed_regions": ["eu-west-1"],
        "compliance_scope": ["PCI-DSS-v4:req-3"],
    }
    node_no_prefill = build_workload(spec)
    node_with_none = build_workload(spec, prefill=None)
    assert node_no_prefill["@id"] == node_with_none["@id"]
    assert node_no_prefill["compliance_scope"] == node_with_none["compliance_scope"]


def test_build_workload_prefill_patches_compliance_scope():
    spec = {"name": "fraud-v1", "compliance_scope": []}
    proposal = _proposal(changes=[_compliance_change(suggested=["HIPAA:164.312"])])
    node = build_workload(spec, prefill=proposal)
    assert node.get("compliance_scope") == ["HIPAA:164.312"]


def test_build_workload_original_spec_not_mutated_by_prefill():
    spec = {"name": "fraud-v1", "allowed_regions": ["eu-west-1"]}
    proposal = _proposal(changes=[_region_change(suggested=["us-east-1"])])
    build_workload(spec, prefill=proposal)
    assert spec["allowed_regions"] == ["eu-west-1"]
