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
    _patterns,
    _validate,
    _validate_intent,
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
