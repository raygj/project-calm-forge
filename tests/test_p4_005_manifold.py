"""Tests for P4-005 — ManifoldEngine, _graph_to_sheaf, _holonomy_validate."""
from __future__ import annotations

import json
from pathlib import Path

from calm_forge.intent_validator import (
    InvariantEngine,
    ManifoldEngine,
    OPAEngine,
    _graph_to_sheaf,
    _holonomy_result_to_findings,
    _holonomy_validate,
    _sections_compatible,
    validate_architecture_intent,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_CLEAN_GRAPH = {
    "workload_id": "workload:fraud-v1",
    "declared_capabilities": ["http_read", "confidential_compute"],
    "components": [
        {"id": "scorer", "name": "scorer", "capabilities": ["http_read"]},
        {"id": "vault", "name": "vault", "capabilities": ["confidential_compute"]},
    ],
    "edges": [
        {"@type": "requires_capability", "from": "scorer", "to": "capability:http_read"},
        {"@type": "requires_capability", "from": "vault", "to": "capability:confidential_compute"},
    ],
    "compliance_scope": ["PCI-DSS-v4:req-3"],
    "allowed_regions": ["us-east-1"],
    "policies": [{"predicate_type": "capability_ceiling"}],
}

_MINIMAL_GRAPH = {
    "workload_id": "workload:minimal",
    "declared_capabilities": [],
    "components": [],
    "edges": [],
    "compliance_scope": [],
    "allowed_regions": [],
    "policies": [],
}

_EXCESS_CAP_GRAPH = {
    **_CLEAN_GRAPH,
    # scorer claims pii_read which is NOT in declared_capabilities
    "components": [
        {"id": "scorer", "name": "scorer", "capabilities": ["http_read", "pii_read"]},
        {"id": "vault", "name": "vault", "capabilities": ["confidential_compute"]},
    ],
}

_PCI_NO_REGION_GRAPH = {
    **_CLEAN_GRAPH,
    "allowed_regions": [],  # PCI scope but no region → compliance drift
}

_PII_NO_COMPLIANCE_GRAPH = {
    "workload_id": "workload:pii-test",
    "declared_capabilities": ["pii_read"],
    "components": [{"id": "reader", "name": "reader", "capabilities": ["pii_read"]}],
    "edges": [{"@type": "requires_capability", "from": "reader", "to": "capability:pii_read"}],
    "compliance_scope": [],
    "allowed_regions": [],
    "policies": [],
}

_BROKEN_GLUING_GRAPH = {
    "workload_id": "workload:broken",
    "declared_capabilities": ["http_read"],
    "components": [
        # scorer section does NOT list confidential_compute, but edge says it requires it
        {"id": "scorer", "name": "scorer", "capabilities": ["http_read"]},
    ],
    "edges": [
        {"@type": "requires_capability", "from": "scorer", "to": "capability:confidential_compute"},
    ],
    "compliance_scope": [],
    "allowed_regions": [],
    "policies": [],
}

KG_DIR = Path(__file__).parent.parent / "src/calm_forge/knowledge_graph"


# ---------------------------------------------------------------------------
# _graph_to_sheaf
# ---------------------------------------------------------------------------

def test_graph_to_sheaf_returns_dict():
    assert isinstance(_graph_to_sheaf(_MINIMAL_GRAPH), dict)


def test_graph_to_sheaf_has_three_keys():
    sheaf = _graph_to_sheaf(_CLEAN_GRAPH)
    assert {"sections", "gluing_conditions", "global_section"} <= sheaf.keys()


def test_graph_to_sheaf_section_count():
    sheaf = _graph_to_sheaf(_CLEAN_GRAPH)
    assert len(sheaf["sections"]) == 2


def test_graph_to_sheaf_gluing_count():
    sheaf = _graph_to_sheaf(_CLEAN_GRAPH)
    assert len(sheaf["gluing_conditions"]) == 2


def test_graph_to_sheaf_section_id():
    sheaf = _graph_to_sheaf(_CLEAN_GRAPH)
    ids = [s["id"] for s in sheaf["sections"]]
    assert "scorer" in ids and "vault" in ids


def test_graph_to_sheaf_section_capabilities():
    sheaf = _graph_to_sheaf(_CLEAN_GRAPH)
    scorer = next(s for s in sheaf["sections"] if s["id"] == "scorer")
    assert "http_read" in scorer["capabilities"]


def test_graph_to_sheaf_global_section_declared_capabilities():
    sheaf = _graph_to_sheaf(_CLEAN_GRAPH)
    assert set(sheaf["global_section"]["declared_capabilities"]) == {"http_read", "confidential_compute"}


def test_graph_to_sheaf_global_section_compliance():
    sheaf = _graph_to_sheaf(_CLEAN_GRAPH)
    assert "PCI-DSS-v4:req-3" in sheaf["global_section"]["compliance_scope"]


def test_graph_to_sheaf_gluing_edge_type():
    sheaf = _graph_to_sheaf(_CLEAN_GRAPH)
    assert sheaf["gluing_conditions"][0]["edge_type"] == "requires_capability"


def test_graph_to_sheaf_empty_graph():
    sheaf = _graph_to_sheaf(_MINIMAL_GRAPH)
    assert sheaf["sections"] == []
    assert sheaf["gluing_conditions"] == []


# ---------------------------------------------------------------------------
# _sections_compatible
# ---------------------------------------------------------------------------

def test_sections_compatible_known_cap():
    section_map = {"scorer": {"id": "scorer", "capabilities": ["http_read"]}}
    condition = {"from": "scorer", "to": "capability:http_read", "edge_type": "requires_capability"}
    assert _sections_compatible(condition, section_map) is True


def test_sections_compatible_missing_cap():
    section_map = {"scorer": {"id": "scorer", "capabilities": ["http_read"]}}
    condition = {"from": "scorer", "to": "capability:pii_read", "edge_type": "requires_capability"}
    assert _sections_compatible(condition, section_map) is False


def test_sections_compatible_unknown_edge_type():
    condition = {"from": "a", "to": "b", "edge_type": "manifests_as"}
    assert _sections_compatible(condition, {}) is True


def test_sections_compatible_missing_source_section():
    condition = {"from": "ghost", "to": "capability:x", "edge_type": "requires_capability"}
    assert _sections_compatible(condition, {}) is True


# ---------------------------------------------------------------------------
# _holonomy_validate — clean graph
# ---------------------------------------------------------------------------

def test_holonomy_validate_clean_graph_curvature_zero():
    sheaf = _graph_to_sheaf(_CLEAN_GRAPH)
    result = _holonomy_validate(_CLEAN_GRAPH, sheaf)
    assert result["curvature"] == 0.0


def test_holonomy_validate_clean_graph_valid_true():
    sheaf = _graph_to_sheaf(_CLEAN_GRAPH)
    result = _holonomy_validate(_CLEAN_GRAPH, sheaf)
    assert result["valid"] is True


def test_holonomy_validate_clean_graph_explanation_coherent():
    sheaf = _graph_to_sheaf(_CLEAN_GRAPH)
    result = _holonomy_validate(_CLEAN_GRAPH, sheaf)
    assert result["explanation"] == "coherent"


def test_holonomy_validate_minimal_graph_zero_curvature():
    sheaf = _graph_to_sheaf(_MINIMAL_GRAPH)
    result = _holonomy_validate(_MINIMAL_GRAPH, sheaf)
    assert result["curvature"] == 0.0


# ---------------------------------------------------------------------------
# _holonomy_validate — section excess
# ---------------------------------------------------------------------------

def test_holonomy_validate_excess_cap_nonzero_curvature():
    sheaf = _graph_to_sheaf(_EXCESS_CAP_GRAPH)
    result = _holonomy_validate(_EXCESS_CAP_GRAPH, sheaf)
    assert result["curvature"] > 0.0


def test_holonomy_validate_excess_cap_explanation_mentions_component():
    sheaf = _graph_to_sheaf(_EXCESS_CAP_GRAPH)
    result = _holonomy_validate(_EXCESS_CAP_GRAPH, sheaf)
    assert "scorer" in result["explanation"]


def test_holonomy_validate_excess_cap_explanation_mentions_capability():
    sheaf = _graph_to_sheaf(_EXCESS_CAP_GRAPH)
    result = _holonomy_validate(_EXCESS_CAP_GRAPH, sheaf)
    assert "pii_read" in result["explanation"]


# ---------------------------------------------------------------------------
# _holonomy_validate — gluing violations
# ---------------------------------------------------------------------------

def test_holonomy_validate_broken_gluing_nonzero_curvature():
    sheaf = _graph_to_sheaf(_BROKEN_GLUING_GRAPH)
    result = _holonomy_validate(_BROKEN_GLUING_GRAPH, sheaf)
    assert result["curvature"] > 0.0


def test_holonomy_validate_broken_gluing_explanation():
    sheaf = _graph_to_sheaf(_BROKEN_GLUING_GRAPH)
    result = _holonomy_validate(_BROKEN_GLUING_GRAPH, sheaf)
    assert "Gluing violation" in result["explanation"]


# ---------------------------------------------------------------------------
# _holonomy_validate — compliance drift
# ---------------------------------------------------------------------------

def test_holonomy_validate_pci_no_region_nonzero():
    sheaf = _graph_to_sheaf(_PCI_NO_REGION_GRAPH)
    result = _holonomy_validate(_PCI_NO_REGION_GRAPH, sheaf)
    assert result["curvature"] > 0.0


def test_holonomy_validate_pci_no_region_explanation():
    sheaf = _graph_to_sheaf(_PCI_NO_REGION_GRAPH)
    result = _holonomy_validate(_PCI_NO_REGION_GRAPH, sheaf)
    assert "region" in result["explanation"]


def test_holonomy_validate_pii_no_compliance_nonzero():
    sheaf = _graph_to_sheaf(_PII_NO_COMPLIANCE_GRAPH)
    result = _holonomy_validate(_PII_NO_COMPLIANCE_GRAPH, sheaf)
    assert result["curvature"] > 0.0


def test_holonomy_validate_pii_no_compliance_explanation():
    sheaf = _graph_to_sheaf(_PII_NO_COMPLIANCE_GRAPH)
    result = _holonomy_validate(_PII_NO_COMPLIANCE_GRAPH, sheaf)
    assert "compliance" in result["explanation"].lower()


# ---------------------------------------------------------------------------
# _holonomy_result_to_findings
# ---------------------------------------------------------------------------

def test_holonomy_findings_zero_curvature_empty():
    assert _holonomy_result_to_findings({"curvature": 0.0, "explanation": ""}) == []


def test_holonomy_findings_below_threshold_warning():
    findings = _holonomy_result_to_findings({"curvature": 0.005, "explanation": "x"}, curvature_threshold=0.01)
    assert findings[0]["severity"] == "warning"
    assert findings[0]["rule"] == "holonomy-curvature-nonzero"


def test_holonomy_findings_at_threshold_error():
    findings = _holonomy_result_to_findings({"curvature": 0.01, "explanation": "x"}, curvature_threshold=0.01)
    assert findings[0]["severity"] == "error"
    assert findings[0]["rule"] == "holonomy-ceiling-violated"


def test_holonomy_findings_above_threshold_error():
    findings = _holonomy_result_to_findings({"curvature": 0.5, "explanation": "excess"}, curvature_threshold=0.01)
    assert findings[0]["severity"] == "error"


def test_holonomy_findings_message_includes_curvature():
    findings = _holonomy_result_to_findings({"curvature": 0.5, "explanation": ""}, curvature_threshold=0.01)
    assert "0.5000" in findings[0]["message"]


# ---------------------------------------------------------------------------
# ManifoldEngine — live (no mocks needed)
# ---------------------------------------------------------------------------

def test_manifold_engine_satisfies_protocol():
    assert isinstance(ManifoldEngine(), InvariantEngine)


def test_manifold_engine_clean_graph_returns_empty():
    findings = ManifoldEngine().validate(_CLEAN_GRAPH)
    assert findings == []


def test_manifold_engine_minimal_graph_returns_empty():
    findings = ManifoldEngine().validate(_MINIMAL_GRAPH)
    assert findings == []


def test_manifold_engine_pci_no_region_returns_finding():
    findings = ManifoldEngine().validate(_PCI_NO_REGION_GRAPH)
    assert len(findings) >= 1


def test_manifold_engine_excess_cap_returns_finding():
    findings = ManifoldEngine().validate(_EXCESS_CAP_GRAPH)
    assert len(findings) >= 1


def test_manifold_engine_broken_gluing_returns_finding():
    findings = ManifoldEngine().validate(_BROKEN_GLUING_GRAPH)
    assert len(findings) >= 1


def test_manifold_engine_curvature_threshold_configurable():
    # With a very high threshold, warning-level curvature is suppressed
    engine = ManifoldEngine(curvature_threshold=99.0)
    findings = engine.validate(_EXCESS_CAP_GRAPH)
    # curvature > 0 but below 99 → warning, not error
    assert all(f["severity"] == "warning" for f in findings) or findings == []


def test_manifold_engine_default_threshold():
    engine = ManifoldEngine()
    assert engine.curvature_threshold == 0.01


# ---------------------------------------------------------------------------
# validate_architecture_intent with ManifoldEngine
# ---------------------------------------------------------------------------

def test_validate_with_manifold_clean_pci_pattern():
    arch = json.loads((KG_DIR / "3-tier-pci.json").read_text())
    result = validate_architecture_intent(arch, engine=ManifoldEngine(), run_opa=False)
    assert "valid" in result
    assert "violations" in result


def test_validate_with_manifold_does_not_raise():
    arch = json.loads((KG_DIR / "fraud-detection-pipeline.json").read_text())
    result = validate_architecture_intent(arch, engine=ManifoldEngine(), run_opa=False)
    assert result is not None


def test_opaengine_unaffected_by_manifold_changes():
    arch = json.loads((KG_DIR / "fraud-detection-pipeline.json").read_text())
    result = validate_architecture_intent(arch, engine=OPAEngine(), run_opa=False)
    assert result["valid"] is True
