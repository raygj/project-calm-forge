"""Tests for intent_validator — semantic graph compilation and invariant checks."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.intent_validator import (
    InvariantEngine,
    ManifoldEngine,
    OPAEngine,
    check_graph_invariants,
    compile_to_graph,
    to_sarif,
    validate_architecture_intent,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

WORKLOAD_NODE = {
    "@context": "https://calmforge.io/kg/v1/context.jsonld",
    "@type": "Workload",
    "@id": "workload:payments-v2",
    "version": "1.0.0",
    "name": "payments-v2",
    "declared_capabilities": ["http_read", "vault_dynamic_creds", "pii_read"],
    "compliance_scope": ["PCI-DSS-v4:req-3"],
    "nodes": [
        {"@type": "WorkloadComponent", "@id": "workload:payments-v2:api",
         "name": "api", "declared_capabilities": ["http_read", "vault_dynamic_creds"]},
        {"@type": "WorkloadComponent", "@id": "workload:payments-v2:processor",
         "name": "processor", "declared_capabilities": ["pii_read"]},
    ],
    "policies": [
        {"@type": "Policy", "predicate_type": "compliance_boundary",
         "allowed_regions": ["us-east-1", "eu-west-1"]},
        {"@type": "Policy", "predicate_type": "capability_ceiling",
         "enforcement_mode": "enforce"},
    ],
    "edges": [
        {"@type": "requires_capability", "from": "workload:payments-v2:api", "to": "capability:http_read"},
        {"@type": "authored_in", "from": "workload:payments-v2", "to": "compliance:PCI-DSS-v4:req-3"},
    ],
    "_provenance": {"authored_by": "calm-forge/interview", "provenance": "authored"},
    "review_required": False,
}

CALM_INSTANTIATION = {
    "metadata": {
        "name": "pci-payments",
        "data": {
            "compliance": "pci",
            "data-residency": ["us-east-1", "eu-west-1"],
        },
    },
    "nodes": [
        {"unique-id": "web", "node-type": "service",
         "required-capabilities": ["http_read", "http_write"]},
        {"unique-id": "db", "node-type": "database",
         "required-capabilities": ["encryption_at_rest", "vault_dynamic_creds"]},
    ],
    "relationships": [],
}


# ---------------------------------------------------------------------------
# compile_to_graph — Workload KG node format
# ---------------------------------------------------------------------------

def test_compile_workload_node_type():
    graph = compile_to_graph(WORKLOAD_NODE)
    assert graph["workload_id"] == "workload:payments-v2"


def test_compile_workload_declared_capabilities():
    graph = compile_to_graph(WORKLOAD_NODE)
    assert "pii_read" in graph["declared_capabilities"]
    assert "http_read" in graph["declared_capabilities"]


def test_compile_workload_components():
    graph = compile_to_graph(WORKLOAD_NODE)
    assert len(graph["components"]) == 2
    names = {c["name"] for c in graph["components"]}
    assert names == {"api", "processor"}


def test_compile_workload_compliance_scope():
    graph = compile_to_graph(WORKLOAD_NODE)
    assert "PCI-DSS-v4:req-3" in graph["compliance_scope"]


def test_compile_workload_allowed_regions_from_policy():
    graph = compile_to_graph(WORKLOAD_NODE)
    assert "us-east-1" in graph["allowed_regions"]


def test_compile_workload_edges_preserved():
    graph = compile_to_graph(WORKLOAD_NODE)
    req_caps = [e for e in graph["edges"] if e["@type"] == "requires_capability"]
    assert len(req_caps) == 1


def test_compile_workload_policies_preserved():
    graph = compile_to_graph(WORKLOAD_NODE)
    assert len(graph["policies"]) == 2


# ---------------------------------------------------------------------------
# compile_to_graph — CALM instantiation format
# ---------------------------------------------------------------------------

def test_compile_calm_workload_id():
    graph = compile_to_graph(CALM_INSTANTIATION)
    assert graph["workload_id"] == "workload:pci-payments"


def test_compile_calm_components():
    graph = compile_to_graph(CALM_INSTANTIATION)
    assert len(graph["components"]) == 2


def test_compile_calm_capabilities_extracted():
    graph = compile_to_graph(CALM_INSTANTIATION)
    caps = graph["declared_capabilities"]
    assert "http_read" in caps
    assert "encryption_at_rest" in caps


def test_compile_calm_edges_created():
    graph = compile_to_graph(CALM_INSTANTIATION)
    req_caps = [e for e in graph["edges"] if e["@type"] == "requires_capability"]
    assert len(req_caps) == 4  # 2 per node


def test_compile_calm_compliance_scope():
    graph = compile_to_graph(CALM_INSTANTIATION)
    assert "pci" in graph["compliance_scope"]


def test_compile_calm_allowed_regions():
    graph = compile_to_graph(CALM_INSTANTIATION)
    assert "us-east-1" in graph["allowed_regions"]


def test_compile_calm_no_regions_defaults_empty():
    calm = {**CALM_INSTANTIATION,
            "metadata": {"name": "test", "data": {"compliance": "pci"}}}
    graph = compile_to_graph(calm)
    assert graph["allowed_regions"] == []


# ---------------------------------------------------------------------------
# check_graph_invariants
# ---------------------------------------------------------------------------

def _clean_graph() -> dict:
    return {
        "workload_id": "workload:test",
        "declared_capabilities": ["http_read"],
        "components": [{"id": "workload:test:svc", "name": "svc", "capabilities": ["http_read"]}],
        "edges": [],
        "compliance_scope": [],
        "allowed_regions": [],
        "policies": [{"predicate_type": "capability_ceiling"}],
    }


def test_invariants_clean_graph_no_violations():
    findings = check_graph_invariants(_clean_graph())
    assert findings == []


def test_invariants_pci_without_regions():
    graph = {**_clean_graph(), "compliance_scope": ["PCI-DSS-v4:req-3"], "allowed_regions": []}
    findings = check_graph_invariants(graph)
    rules = {f["rule"] for f in findings}
    assert "compliance-requires-region-constraint" in rules


def test_invariants_hipaa_without_regions():
    graph = {**_clean_graph(), "compliance_scope": ["HIPAA:164.312.a.1"], "allowed_regions": []}
    findings = check_graph_invariants(graph)
    rules = {f["rule"] for f in findings}
    assert "compliance-requires-region-constraint" in rules


def test_invariants_gdpr_without_regions():
    graph = {**_clean_graph(), "compliance_scope": ["GDPR:art-25"], "allowed_regions": []}
    findings = check_graph_invariants(graph)
    rules = {f["rule"] for f in findings}
    assert "compliance-requires-region-constraint" in rules


def test_invariants_pci_with_regions_clean():
    graph = {**_clean_graph(),
             "compliance_scope": ["PCI-DSS-v4:req-3"], "allowed_regions": ["us-east-1"]}
    findings = check_graph_invariants(graph)
    rules = {f["rule"] for f in findings}
    assert "compliance-requires-region-constraint" not in rules


def test_invariants_pii_without_compliance():
    graph = {**_clean_graph(),
             "components": [{"id": "svc", "name": "svc", "capabilities": ["pii_read"]}],
             "compliance_scope": []}
    findings = check_graph_invariants(graph)
    rules = {f["rule"] for f in findings}
    assert "pii-requires-compliance-scope" in rules


def test_invariants_pii_with_compliance_clean():
    graph = {**_clean_graph(),
             "components": [{"id": "svc", "name": "svc", "capabilities": ["pii_read"]}],
             "compliance_scope": ["HIPAA:164.312.a.1"],
             "allowed_regions": ["us-east-1"]}
    findings = check_graph_invariants(graph)
    rules = {f["rule"] for f in findings}
    assert "pii-requires-compliance-scope" not in rules


def test_invariants_no_ceiling_policy_is_warning():
    graph = {**_clean_graph(), "policies": []}
    findings = check_graph_invariants(graph)
    ceiling = [f for f in findings if f["rule"] == "capability-ceiling-policy-required"]
    assert len(ceiling) == 1
    assert ceiling[0]["severity"] == "warning"


def test_invariants_with_ceiling_policy_clean():
    graph = _clean_graph()  # already has ceiling policy
    findings = check_graph_invariants(graph)
    ceiling = [f for f in findings if f["rule"] == "capability-ceiling-policy-required"]
    assert ceiling == []


def test_invariants_no_capabilities_no_ceiling_required():
    graph = {**_clean_graph(), "declared_capabilities": [], "components": [], "policies": []}
    findings = check_graph_invariants(graph)
    ceiling = [f for f in findings if f["rule"] == "capability-ceiling-policy-required"]
    assert ceiling == []


def test_invariants_violation_severity_is_error():
    graph = {**_clean_graph(), "compliance_scope": ["PCI-DSS-v4:req-3"], "allowed_regions": []}
    findings = check_graph_invariants(graph)
    errors = [f for f in findings if f["severity"] == "error"]
    assert len(errors) >= 1


# ---------------------------------------------------------------------------
# validate_architecture_intent
# ---------------------------------------------------------------------------

def test_validate_intent_clean_workload_node():
    result = validate_architecture_intent(WORKLOAD_NODE, run_opa=False)
    assert result["valid"] is True
    assert "graph" in result
    assert "violations" in result


def test_validate_intent_violation_on_pci_no_region(tmp_path):
    arch = {
        "@type": "Workload",
        "@id": "workload:bad",
        "declared_capabilities": ["http_read"],
        "compliance_scope": ["PCI-DSS-v4:req-3"],
        "nodes": [],
        "edges": [],
        "policies": [{"predicate_type": "capability_ceiling"}],
        "_provenance": {"provenance": "authored"},
    }
    result = validate_architecture_intent(arch, run_opa=False)
    assert result["valid"] is False
    rules = {v["rule"] for v in result["violations"]}
    assert "compliance-requires-region-constraint" in rules


def test_validate_intent_calm_instantiation():
    result = validate_architecture_intent(CALM_INSTANTIATION, run_opa=False)
    # pci compliance with regions present → should be clean (no errors)
    errors = [v for v in result["violations"] if v["severity"] == "error"]
    assert errors == []


def test_validate_intent_returns_graph():
    result = validate_architecture_intent(WORKLOAD_NODE, run_opa=False)
    assert result["graph"]["workload_id"] == "workload:payments-v2"


# ---------------------------------------------------------------------------
# to_sarif
# ---------------------------------------------------------------------------

def test_sarif_schema_field():
    result = {"valid": True, "violations": []}
    sarif = to_sarif(result)
    assert "sarif-schema" in sarif["$schema"]


def test_sarif_version():
    sarif = to_sarif({"valid": True, "violations": []})
    assert sarif["version"] == "2.1.0"


def test_sarif_tool_name():
    sarif = to_sarif({"valid": True, "violations": []})
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "calm-forge"


def test_sarif_result_for_violation():
    result = {
        "valid": False,
        "violations": [{"rule": "pci-requires-region", "severity": "error",
                        "message": "PCI needs regions"}],
    }
    sarif = to_sarif(result, architecture_uri="instantiation.json")
    runs = sarif["runs"][0]["results"]
    assert len(runs) == 1
    assert runs[0]["ruleId"] == "pci-requires-region"
    assert runs[0]["level"] == "error"
    assert runs[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "instantiation.json"


def test_sarif_warning_level():
    result = {
        "valid": True,
        "violations": [{"rule": "cap-ceiling", "severity": "warning", "message": "add policy"}],
    }
    sarif = to_sarif(result)
    assert sarif["runs"][0]["results"][0]["level"] == "warning"


def test_sarif_empty_violations():
    sarif = to_sarif({"valid": True, "violations": []})
    assert sarif["runs"][0]["results"] == []


def test_sarif_invocation_success():
    sarif = to_sarif({"valid": True, "violations": []})
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is True


def test_sarif_invocation_failure():
    sarif = to_sarif({"valid": False, "violations": [
        {"rule": "r", "severity": "error", "message": "m"}]})
    assert sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False


# ---------------------------------------------------------------------------
# CLI — validate-intent command
# ---------------------------------------------------------------------------

def test_cli_validate_intent_clean(tmp_path):
    arch_file = tmp_path / "workload.json"
    arch_file.write_text(json.dumps(WORKLOAD_NODE))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "validate-intent", "--architecture", str(arch_file), "--no-opa",
    ])
    assert result.exit_code == 0
    assert "CLEAN" in result.output


def test_cli_validate_intent_violation_exit_1(tmp_path):
    bad_arch = {
        "@type": "Workload", "@id": "workload:bad",
        "declared_capabilities": ["http_read"],
        "compliance_scope": ["PCI-DSS-v4:req-3"],
        "nodes": [], "edges": [], "policies": [{"predicate_type": "capability_ceiling"}],
        "_provenance": {"provenance": "authored"},
    }
    arch_file = tmp_path / "bad.json"
    arch_file.write_text(json.dumps(bad_arch))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "validate-intent", "--architecture", str(arch_file), "--no-opa",
    ])
    assert result.exit_code == 1
    assert "ERROR" in result.output


def test_cli_validate_intent_sarif_output(tmp_path):
    arch_file = tmp_path / "workload.json"
    arch_file.write_text(json.dumps(WORKLOAD_NODE))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "validate-intent", "--architecture", str(arch_file),
        "--no-opa", "--sarif",
    ])
    assert result.exit_code == 0
    sarif = json.loads(result.output)
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif


def test_cli_validate_intent_sarif_to_file(tmp_path):
    arch_file = tmp_path / "workload.json"
    arch_file.write_text(json.dumps(WORKLOAD_NODE))
    out_file = tmp_path / "results.sarif.json"
    runner = CliRunner()
    result = runner.invoke(cli, [
        "validate-intent", "--architecture", str(arch_file),
        "--no-opa", "--sarif", "--output", str(out_file),
    ])
    assert result.exit_code == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["version"] == "2.1.0"


def test_cli_validate_intent_calm_instantiation(tmp_path):
    arch_file = tmp_path / "instantiation.json"
    arch_file.write_text(json.dumps(CALM_INSTANTIATION))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "validate-intent", "--architecture", str(arch_file), "--no-opa",
    ])
    assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Reference patterns pass validate-intent
# ---------------------------------------------------------------------------

KG_DIR = Path(__file__).parent.parent / "src/calm_forge/knowledge_graph"


@pytest.mark.parametrize("pattern_name", [
    "3-tier-pci.json",
    "fraud-detection-pipeline.json",
    "healthcare-hl7-pipeline.json",
    "supply-chain-analytics.json",
    "identity-verification-kyc.json",
])
def test_reference_pattern_passes_validate_intent(pattern_name):
    arch = json.loads((KG_DIR / pattern_name).read_text())
    result = validate_architecture_intent(arch, run_opa=False)
    errors = [v for v in result["violations"] if v["severity"] == "error"]
    assert errors == [], f"{pattern_name} has errors: {errors}"


# ---------------------------------------------------------------------------
# P3-005 — InvariantEngine protocol (ADR-0025)
# ---------------------------------------------------------------------------

_MINIMAL_GRAPH: dict = {
    "workload_id": "workload:test",
    "declared_capabilities": [],
    "components": [],
    "edges": [],
    "compliance_scope": [],
    "allowed_regions": [],
    "policies": [],
}

_PCI_GRAPH: dict = {
    "workload_id": "workload:pci-test",
    "declared_capabilities": ["pii_read"],
    "components": [{"id": "comp-a", "name": "comp-a", "capabilities": ["pii_read"]}],
    "edges": [],
    "compliance_scope": ["PCI-DSS-v4:req-3"],
    "allowed_regions": ["us-east-1"],
    "policies": [{"predicate_type": "capability_ceiling"}],
}


def test_opaengine_satisfies_invariant_engine_protocol():
    assert isinstance(OPAEngine(), InvariantEngine)


def test_manifoldengine_satisfies_invariant_engine_protocol():
    assert isinstance(ManifoldEngine(), InvariantEngine)


def test_opaengine_validate_returns_list():
    result = OPAEngine().validate(_MINIMAL_GRAPH)
    assert isinstance(result, list)


def test_opaengine_validate_clean_graph_no_violations():
    result = OPAEngine().validate(_PCI_GRAPH)
    assert result == []


def test_opaengine_validate_detects_violation():
    graph = {**_PCI_GRAPH, "allowed_regions": []}
    findings = OPAEngine().validate(graph)
    rules = [f["rule"] for f in findings]
    assert "compliance-requires-region-constraint" in rules


def test_opaengine_accepts_placement_policies():
    policy = {
        "predicate_type": "placement_policy",
        "blocked_environments": ["env:acm:dev"],
        "risk_score": 0.9,
        "risk_level": "critical",
    }
    findings = OPAEngine(placement_policies=[policy]).validate(_MINIMAL_GRAPH)
    assert any(f["rule"] == "concert-risk-placement-block" for f in findings)


def test_manifoldengine_validate_returns_list():
    # ManifoldEngine is now a live implementation — no longer raises
    result = ManifoldEngine().validate(_MINIMAL_GRAPH)
    assert isinstance(result, list)


def test_manifoldengine_clean_graph_no_violations():
    result = ManifoldEngine().validate(_PCI_GRAPH)
    assert result == []


def test_validate_architecture_intent_default_engine_backward_compat():
    arch = json.loads((KG_DIR / "3-tier-pci.json").read_text())
    result = validate_architecture_intent(arch, run_opa=False)
    assert "valid" in result
    assert "violations" in result
    assert "graph" in result
    assert "opa_result" in result


def test_validate_architecture_intent_explicit_opaengine():
    arch = json.loads((KG_DIR / "3-tier-pci.json").read_text())
    result = validate_architecture_intent(arch, engine=OPAEngine(), run_opa=False)
    assert result["valid"] is True


def test_validate_architecture_intent_manifold_engine_runs():
    arch = json.loads((KG_DIR / "3-tier-pci.json").read_text())
    result = validate_architecture_intent(arch, engine=ManifoldEngine(), run_opa=False)
    assert "valid" in result
    assert "violations" in result


def test_validate_architecture_intent_run_opa_false_no_opa_result():
    arch = json.loads((KG_DIR / "3-tier-pci.json").read_text())
    result = validate_architecture_intent(arch, run_opa=False)
    assert result["opa_result"] is None


def test_validate_architecture_intent_graph_key_present():
    arch = json.loads((KG_DIR / "fraud-detection-pipeline.json").read_text())
    result = validate_architecture_intent(arch, run_opa=False)
    assert "workload_id" in result["graph"]


def test_opaengine_finding_has_required_keys():
    graph = {**_MINIMAL_GRAPH, "compliance_scope": ["PCI-DSS-v4:req-3"], "allowed_regions": []}
    findings = OPAEngine().validate(graph)
    assert findings
    for f in findings:
        assert "rule" in f
        assert "severity" in f
        assert "message" in f
