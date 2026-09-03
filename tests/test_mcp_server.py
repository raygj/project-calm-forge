"""Tests for MCP server tool implementations.

Tests call the underlying helper functions directly — no stdio transport needed.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from calm_forge.mcp_server import (
    _catalog,
    _diff,
    _generate,
    _intake_acm,
    _interview,
    _kg_query,
    _kg_status,
    _patterns,
    _validate,
    _validate_intent,
    fabric_state_tool,
    intake_concert_tool,
    kg_bootstrap_tool,
    kg_export_tool,
    kg_federate_query_tool,
    kg_federate_status_tool,
    kg_import_tool,
    reconcile_tool,
)

EXAMPLES_DIR = Path(__file__).parent.parent / "examples" / "fsi-3tier"


# ---------------------------------------------------------------------------
# Helpers: load fsi-3tier example inputs
# ---------------------------------------------------------------------------

def _load(name: str) -> dict:
    return json.loads((EXAMPLES_DIR / name).read_text())


def _fsi_inputs():
    return _load("instantiation.json"), _load("decorator.json"), _load("catalog.json")


# ---------------------------------------------------------------------------
# _generate tests
# ---------------------------------------------------------------------------

def test_generate_fsi3tier_returns_core_files():
    calm, decorator, catalog = _fsi_inputs()
    result = _generate(calm, decorator, catalog)
    assert "files" in result
    assert "components.tfstack.hcl" in result["files"]
    assert "variables.tfstack.hcl" in result["files"]
    assert "deployments.tfdeploy.hcl" in result["files"]


def test_generate_attestation_sha_is_64_char_hex():
    calm, decorator, catalog = _fsi_inputs()
    result = _generate(calm, decorator, catalog)
    sha = result["attestation_sha"]
    assert len(sha) == 64
    assert all(c in "0123456789abcdef" for c in sha)


def test_generate_file_count_three_default():
    calm, decorator, catalog = _fsi_inputs()
    result = _generate(calm, decorator, catalog)
    assert result["file_count"] == 3


def test_generate_full_true_returns_8_files():
    calm, decorator, catalog = _fsi_inputs()
    result = _generate(calm, decorator, catalog, full=True)
    # 3 HCL + 2 vault + 1 sentinel + 2 ansible + 1 dcm = 9 files
    assert result["file_count"] == 9


def test_generate_hcl_errors_empty_for_valid_output():
    calm, decorator, catalog = _fsi_inputs()
    result = _generate(calm, decorator, catalog)
    assert result["hcl_errors"] == []


def test_generate_invalid_calm_raises_value_error():
    """An invalid CALM dict (missing nodes) should raise ValueError."""
    bad_calm = {"metadata": {"application-name": "bad"}, "relationships": []}
    decorator = _load("decorator.json")
    catalog = _load("catalog.json")
    with pytest.raises(ValueError):
        _generate(bad_calm, decorator, catalog)


def test_generate_attestation_sha_deterministic():
    """Same inputs produce the same SHA."""
    calm, decorator, catalog = _fsi_inputs()
    r1 = _generate(calm, decorator, catalog)
    r2 = _generate(calm, decorator, catalog)
    assert r1["attestation_sha"] == r2["attestation_sha"]


# ---------------------------------------------------------------------------
# _validate tests
# ---------------------------------------------------------------------------

def test_validate_valid_fsi3tier():
    calm = _load("instantiation.json")
    result = _validate(calm)
    assert result["valid"] is True
    assert result["errors"] == []


def test_validate_missing_nodes():
    bad = {"relationships": [], "metadata": {"application-name": "x"}}
    result = _validate(bad)
    assert result["valid"] is False
    assert any("nodes" in e for e in result["errors"])


def test_validate_empty_nodes_array():
    bad = {"nodes": [], "relationships": [], "metadata": {"application-name": "x"}}
    result = _validate(bad)
    assert result["valid"] is False


def test_validate_missing_metadata():
    bad = {
        "nodes": [{"unique-id": "n1", "node-type": "service"}],
        "relationships": [],
    }
    result = _validate(bad)
    assert result["valid"] is False
    assert any("metadata" in e for e in result["errors"])


# ---------------------------------------------------------------------------
# _validate_intent tests
# ---------------------------------------------------------------------------

def test_validate_intent_valid_input():
    calm, decorator, _ = _fsi_inputs()
    result = _validate_intent(calm, decorator)
    # Valid FSI inputs produce no error-severity violations whether OPA is
    # present (CI installs it) or absent (graceful degradation) — both => valid=True.
    assert result["valid"] is True
    assert "violations" in result
    assert "opa_available" in result


def test_validate_intent_has_opa_available_key():
    calm, decorator, _ = _fsi_inputs()
    result = _validate_intent(calm, decorator)
    assert "opa_available" in result


def test_validate_intent_no_decorator():
    calm, _, _ = _fsi_inputs()
    result = _validate_intent(calm)
    assert result["valid"] is True
    assert "violations" in result


def test_validate_intent_opa_not_available_has_warning():
    calm, decorator, _ = _fsi_inputs()
    result = _validate_intent(calm, decorator)
    if not result["opa_available"]:
        assert result.get("warning") is not None


# ---------------------------------------------------------------------------
# _diff tests
# ---------------------------------------------------------------------------

def test_diff_identical_specs_impact_none():
    calm = _load("instantiation.json")
    result = _diff(calm, calm)
    assert result["impact"] == "none"


def test_diff_add_node_impact_additive():
    calm = _load("instantiation.json")
    after = json.loads(json.dumps(calm))  # deep copy
    after["nodes"].append({
        "unique-id": "new-svc",
        "node-type": "service",
        "name": "New Service",
    })
    result = _diff(calm, after)
    assert result["impact"] == "additive"
    assert result["estimated_terraform"]["creates"] == 1


def test_diff_remove_node_impact_breaking():
    calm = _load("instantiation.json")
    after = json.loads(json.dumps(calm))
    after["nodes"] = [n for n in after["nodes"] if n["unique-id"] != "database"]
    result = _diff(calm, after)
    assert result["impact"] == "breaking"
    assert result["estimated_terraform"]["destroys"] == 1


def test_diff_returns_summary_string():
    calm = _load("instantiation.json")
    result = _diff(calm, calm)
    assert isinstance(result["summary"], str)
    assert "NONE" in result["summary"]


# ---------------------------------------------------------------------------
# _catalog tests
# ---------------------------------------------------------------------------

def test_catalog_none_returns_schema_info():
    result = _catalog(None)
    assert "schema" in result
    assert "note" in result


def test_catalog_with_fsi3tier_returns_node_types():
    catalog = _load("catalog.json")
    result = _catalog(catalog)
    assert "node_types" in result
    assert "service" in result["node_types"]


def test_catalog_with_fsi3tier_total_positive():
    catalog = _load("catalog.json")
    result = _catalog(catalog)
    assert result["total"] > 0


def test_catalog_modules_summary_has_service():
    catalog = _load("catalog.json")
    result = _catalog(catalog)
    service_mod = next((m for m in result["modules"] if m["node_type"] == "service"), None)
    assert service_mod is not None


# ---------------------------------------------------------------------------
# _patterns tests
# ---------------------------------------------------------------------------

def test_patterns_no_filter_returns_workload_patterns():
    result = _patterns()
    # Only Workload @type patterns are loaded — old ArchitecturePattern files are skipped
    assert result["total"] >= 3
    names = [p["name"] for p in result["patterns"]]
    assert "3-tier-pci" in names
    assert "fraud-detection-pipeline" in names
    assert "legacy-payment-processor" in names


def test_patterns_filter_pci_matches_multiple():
    # "pci" matches 3-tier-pci (name) and fraud-detection-pipeline (PCI compliance scope)
    result = _patterns("pci")
    assert result["total"] >= 1
    names = [p["name"] for p in result["patterns"]]
    assert "3-tier-pci" in names


def test_patterns_filter_fraud_returns_one():
    result = _patterns("fraud")
    assert result["total"] == 1
    assert result["patterns"][0]["name"] == "fraud-detection-pipeline"


def test_patterns_filter_no_match_returns_empty():
    result = _patterns("nonexistent-xyz-pattern")
    assert result["total"] == 0
    assert result["patterns"] == []


def test_patterns_all_have_required_summary_fields():
    result = _patterns()
    for p in result["patterns"]:
        assert "name" in p
        assert "id" in p
        assert "purpose" in p
        assert "policy_count" in p
        assert "predicate_types" in p
        assert "capabilities_required" in p


def test_patterns_filter_brownfield():
    result = _patterns("brownfield")
    assert result["total"] >= 1
    names = [p["name"] for p in result["patterns"]]
    assert "legacy-payment-processor" in names


# ---------------------------------------------------------------------------
# Intake / interview / KG tools — the write-through and no-write branches
#
# These wrap intake and interviewer internals that are tested elsewhere; what
# is untested is the MCP layer's own behaviour: shaping the response, and the
# split between "just compute" and "compute and persist to output_dir".
# ---------------------------------------------------------------------------

_ACM = {
    "clusters": [
        {"name": "prod-east", "region": "us-east-1", "status": "ready",
         "substrate": "x86", "labels": {"environment": "prod"},
         "capabilities": ["http_read"]},
        {"name": "prod-eu", "region": "eu-west-1", "status": "ready",
         "substrate": "x86", "labels": {"environment": "prod"},
         "capabilities": ["http_read"]},
    ]
}


def test_intake_acm_without_output_dir_computes_but_does_not_write(tmp_path):
    result = _intake_acm(_ACM, "")
    assert result["count"] == 2
    assert result["written"] == []
    assert not (tmp_path / "environments").exists()


def test_intake_acm_with_output_dir_persists_nodes(tmp_path):
    result = _intake_acm(_ACM, str(tmp_path / "kg"))
    assert result["count"] == 2
    assert len(result["written"]) == 2
    assert (tmp_path / "kg" / "environments").exists()


def test_interview_from_spec_returns_node_and_summary(tmp_path):
    spec = {"name": "payments", "components": [{"name": "api", "capabilities": ["http_read"]}]}
    result = _interview(spec=spec, output_dir=str(tmp_path / "kg"))

    assert result["node"]["@type"] == "Workload"
    assert result["node"]["@id"] == "workload:payments"
    assert result["summary"]["id"] == "workload:payments"
    assert result["written"] is not None
    assert (tmp_path / "kg" / "workloads").exists()


def test_kg_status_and_query_round_trip(tmp_path):
    kg = str(tmp_path / "kg")
    _intake_acm(_ACM, kg)

    status = _kg_status(kg)
    assert status["environments"]["count"] == 2

    queried = _kg_query(kg, "ExecutionEnvironment")
    assert queried["count"] == 2


# ---------------------------------------------------------------------------
# Federated KG tools — error containment and the dict-`where` contract
# ---------------------------------------------------------------------------


def test_federate_status_contains_a_bad_root_error_in_the_payload(tmp_path):
    """A missing root must surface as data, not an exception — the caller is an
    LLM that needs a structured answer, not a stack trace."""
    result = kg_federate_status_tool([str(tmp_path / "does-not-exist")])
    assert "error" in result


def test_federate_query_contains_a_bad_root_error_in_the_list(tmp_path):
    result = kg_federate_query_tool([str(tmp_path / "does-not-exist")], node_type="Workload")
    assert isinstance(result, list)
    assert result and "error" in result[0]


def test_federate_query_dict_where_filters_instead_of_raising(tmp_path):
    """Regression: `where` is documented as a dict, but the federated query
    passed it through `list(dict)`, which yields bare keys and made kg_query
    reject every non-empty filter as malformed. A dict must filter by value."""
    kg = str(tmp_path / "kg")
    _intake_acm(_ACM, kg)

    filtered = kg_federate_query_tool(
        [kg], node_type="ExecutionEnvironment", where={"region": "eu-west-1"}
    )
    ids = [e["node"]["@id"] for e in filtered if "node" in e]
    assert ids == ["env:acm:prod-eu"]


def test_federate_query_empty_and_absent_where_return_everything(tmp_path):
    kg = str(tmp_path / "kg")
    _intake_acm(_ACM, kg)

    both = [
        kg_federate_query_tool([kg], node_type="ExecutionEnvironment", where={}),
        kg_federate_query_tool([kg], node_type="ExecutionEnvironment"),
    ]
    for result in both:
        assert len([e for e in result if "node" in e]) == 2


# ---------------------------------------------------------------------------
# Bootstrap / bundle / reconcile / fabric-state MCP tools
# ---------------------------------------------------------------------------


def test_kg_bootstrap_runs_named_sources(tmp_path):
    acm = tmp_path / "acm.json"
    acm.write_text(json.dumps(_ACM))
    result = kg_bootstrap_tool(str(tmp_path / "kg"), sources=["acm"], acm_fixture_path=str(acm))
    assert result["sources_run"] == ["acm"]
    assert result["total_nodes"] == 2


def test_kg_bootstrap_unknown_source_surfaces_in_errors(tmp_path):
    """The MCP tool must relay the same unknown-source error — an LLM caller
    that mistypes a source name needs to see it, not a clean empty result."""
    result = kg_bootstrap_tool(str(tmp_path / "kg"), sources=["ansible-tower"])
    assert "ansible-tower" in result["errors"]
    assert result["total_nodes"] == 0


def test_kg_export_import_roundtrip_via_mcp(tmp_path):
    kg = str(tmp_path / "kg")
    _intake_acm(_ACM, kg)
    bundle = str(tmp_path / "bundle.zip")

    exported = kg_export_tool(kg, bundle)
    assert Path(exported["bundle_path"]).exists()

    imported = kg_import_tool(bundle, str(tmp_path / "restored"))
    assert imported["imported"] >= 1
    assert imported["conflicts"] == []


def test_reconcile_dry_run_on_clean_kg_proposes_nothing(tmp_path):
    kg = str(tmp_path / "kg")
    _intake_acm(_ACM, kg)
    result = reconcile_tool(kg, dry_run=True)
    assert result["dry_run"] is True
    assert result["proposals"] == []
    assert result["executed"] == []


def test_fabric_state_returns_a_summary_snapshot(tmp_path):
    kg = str(tmp_path / "kg")
    _intake_acm(_ACM, kg)
    result = fabric_state_tool(kg)
    assert "summary" in result
    assert result["summary"]["environments"] == 2


# ---------------------------------------------------------------------------
# interview from a remediation proposal
#
# The other interview mode: instead of a hand-written spec, pre-populate from a
# RemediationProposal so a reconcile finding flows straight into an authored fix.
# ---------------------------------------------------------------------------


def test_interview_from_proposal_prefills_from_the_existing_workload(tmp_path):
    kg = str(tmp_path / "kg")
    _interview(spec={"name": "payments", "allowed_regions": ["us-east-1"]}, output_dir=kg)

    proposal = {
        "workload_id": "workload:payments",
        "confidence": "high",
        "proposed_changes": [
            {"field": "allowed_regions", "suggested_value": ["us-east-1", "eu-west-1"]},
        ],
    }
    result = _interview(proposal=proposal, kg_dir=kg, output_dir=str(tmp_path / "out"))

    assert result["proposal_confidence"] == "high"
    assert "allowed_regions" in result["prefilled_fields"]
    assert result["written"] is not None


def test_interview_from_proposal_for_unknown_workload_falls_back_to_slug(tmp_path):
    """A proposal referencing a workload with no node yet must still author one,
    seeded from the id slug rather than crashing on the missing file."""
    proposal = {"workload_id": "workload:brand-new", "confidence": "low", "proposed_changes": []}
    result = _interview(proposal=proposal, kg_dir=str(tmp_path / "kg"))

    assert result["node"]["@id"] == "workload:brand-new"
    assert result["node"]["name"] == "brand-new"


# ---------------------------------------------------------------------------
# intake-concert — the compliance-blocking governance path
# ---------------------------------------------------------------------------


def test_intake_concert_separates_blocking_from_clean_apps(tmp_path):
    """A blocked_environments list is what turns a risk assessment into a
    placement constraint. The `blocking` count and per-policy constraint must
    reflect exactly which apps carry a block."""
    fixture = {
        "applications": [
            {"name": "payments", "risk_score": 0.9, "risk_level": "high",
             "blocked_environments": ["env:acm:prod-eu"],
             "evaluated_at": "2026-05-01T00:00:00Z"},
            {"name": "catalog", "risk_score": 0.1, "risk_level": "low",
             "blocked_environments": [], "evaluated_at": "2026-05-01T00:00:00Z"},
        ]
    }
    result = intake_concert_tool(fixture=fixture, output_dir=str(tmp_path / "kg"))

    assert result["count"] == 2
    assert result["blocking"] == 1

    by_id = {p["id"]: p for p in result["policies"]}
    assert by_id["policy:concert:payments"]["constraint"] == "placement_requires_isolation"
    assert by_id["policy:concert:payments"]["blocked_environments"] == ["env:acm:prod-eu"]
    assert by_id["policy:concert:catalog"]["constraint"] == "no_constraint"
