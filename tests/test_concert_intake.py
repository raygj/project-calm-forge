"""Tests for Concert risk intake and placement policy enforcement (P3-003)."""
from __future__ import annotations

import json

from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.intake import (
    intake_concert,
    load_placement_policies,
    write_policy_nodes,
)
from calm_forge.intent_validator import (
    check_graph_invariants,
    validate_architecture_intent,
)
from calm_forge.kg_inspect import kg_status

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

CONCERT_FIXTURE = {
    "applications": [
        {
            "name": "fraud-detection-pipeline",
            "risk_score": 0.87,
            "risk_level": "critical",
            "blocked_environments": ["env:acm:shared-dev-01"],
            "allowed_environments": [],
            "evaluated_at": "2026-05-08T10:00:00Z",
        },
        {
            "name": "inventory-service",
            "risk_score": 0.25,
            "risk_level": "low",
            "blocked_environments": [],
            "allowed_environments": [],
            "evaluated_at": "2026-05-08T10:00:00Z",
        },
    ]
}

CONCERT_CLEAN = {
    "applications": [
        {
            "name": "analytics-dashboard",
            "risk_score": 0.15,
            "risk_level": "low",
            "blocked_environments": [],
            "allowed_environments": [],
            "evaluated_at": "2026-05-08T10:00:00Z",
        }
    ]
}

WORKLOAD_GRAPH = {
    "workload_id": "workload:fraud-detection-pipeline",
    "declared_capabilities": ["http_read", "confidential_compute"],
    "components": [],
    "edges": [],
    "compliance_scope": ["PCI-DSS-v4:req-3"],
    "allowed_regions": ["us-east-1"],
    "policies": [{"predicate_type": "capability_ceiling"}],
}

WORKLOAD_NODE = {
    "@context": "https://calmforge.io/kg/v1/context.jsonld",
    "@type": "Workload",
    "@id": "workload:fraud-detection-pipeline",
    "name": "fraud-detection-pipeline",
    "owner": "financial-crimes",
    "declared_capabilities": ["http_read", "confidential_compute"],
    "compliance_scope": ["PCI-DSS-v4:req-3"],
    "policies": [
        {
            "predicate_type": "compliance_boundary",
            "allowed_regions": ["us-east-1"],
        },
        {"predicate_type": "capability_ceiling"},
    ],
    "_provenance": {"provenance": "authored"},
}


# ---------------------------------------------------------------------------
# intake_concert — node structure
# ---------------------------------------------------------------------------

def test_intake_concert_node_type():
    nodes = intake_concert(CONCERT_FIXTURE)
    assert all(n["@type"] == "PlacementPolicy" for n in nodes)


def test_intake_concert_count():
    nodes = intake_concert(CONCERT_FIXTURE)
    assert len(nodes) == 2


def test_intake_concert_node_id():
    nodes = intake_concert(CONCERT_FIXTURE)
    ids = {n["@id"] for n in nodes}
    assert "policy:concert:fraud-detection-pipeline" in ids


def test_intake_concert_workload_id():
    nodes = intake_concert(CONCERT_FIXTURE)
    fraud = next(n for n in nodes if "fraud" in n["@id"])
    assert fraud["workload_id"] == "workload:fraud-detection-pipeline"


def test_intake_concert_risk_score():
    nodes = intake_concert(CONCERT_FIXTURE)
    fraud = next(n for n in nodes if "fraud" in n["@id"])
    assert fraud["risk_score"] == 0.87


def test_intake_concert_risk_level():
    nodes = intake_concert(CONCERT_FIXTURE)
    fraud = next(n for n in nodes if "fraud" in n["@id"])
    assert fraud["risk_level"] == "critical"


def test_intake_concert_blocked_environments():
    nodes = intake_concert(CONCERT_FIXTURE)
    fraud = next(n for n in nodes if "fraud" in n["@id"])
    assert "env:acm:shared-dev-01" in fraud["blocked_environments"]


def test_intake_concert_constraint_set_when_blocked():
    nodes = intake_concert(CONCERT_FIXTURE)
    fraud = next(n for n in nodes if "fraud" in n["@id"])
    assert fraud["constraint"] == "placement_requires_isolation"


def test_intake_concert_no_constraint_when_clean():
    nodes = intake_concert(CONCERT_FIXTURE)
    inv = next(n for n in nodes if "inventory" in n["@id"])
    assert inv["constraint"] == "no_constraint"


def test_intake_concert_source():
    nodes = intake_concert(CONCERT_FIXTURE)
    assert all(n["source"] == "concert" for n in nodes)


def test_intake_concert_provenance():
    nodes = intake_concert(CONCERT_FIXTURE)
    assert all(n["_provenance"]["authored_by"] == "calm-forge/intake-concert" for n in nodes)


def test_intake_concert_empty_applications():
    assert intake_concert({"applications": []}) == []


# ---------------------------------------------------------------------------
# write_policy_nodes / load_placement_policies
# ---------------------------------------------------------------------------

def test_write_policy_nodes_creates_dir(tmp_path):
    nodes = intake_concert(CONCERT_FIXTURE)
    write_policy_nodes(nodes, tmp_path)
    assert (tmp_path / "policies").is_dir()


def test_write_policy_nodes_count(tmp_path):
    nodes = intake_concert(CONCERT_FIXTURE)
    paths = write_policy_nodes(nodes, tmp_path)
    assert len(paths) == 2


def test_write_policy_nodes_valid_json(tmp_path):
    nodes = intake_concert(CONCERT_FIXTURE)
    write_policy_nodes(nodes, tmp_path)
    for path in (tmp_path / "policies").glob("*.json"):
        data = json.loads(path.read_text())
        assert data["@type"] == "PlacementPolicy"


def test_load_placement_policies_all(tmp_path):
    nodes = intake_concert(CONCERT_FIXTURE)
    write_policy_nodes(nodes, tmp_path)
    loaded = load_placement_policies(tmp_path)
    assert len(loaded) == 2


def test_load_placement_policies_filtered_by_workload_id(tmp_path):
    nodes = intake_concert(CONCERT_FIXTURE)
    write_policy_nodes(nodes, tmp_path)
    loaded = load_placement_policies(tmp_path, "workload:fraud-detection-pipeline")
    assert len(loaded) == 1
    assert loaded[0]["workload_id"] == "workload:fraud-detection-pipeline"


def test_load_placement_policies_empty_when_no_dir(tmp_path):
    result = load_placement_policies(tmp_path)
    assert result == []


# ---------------------------------------------------------------------------
# check_graph_invariants with placement_policies
# ---------------------------------------------------------------------------

def test_concert_risk_rule_fires_when_blocked(tmp_path):
    nodes = intake_concert(CONCERT_FIXTURE)
    write_policy_nodes(nodes, tmp_path)
    policies = load_placement_policies(tmp_path, "workload:fraud-detection-pipeline")
    findings = check_graph_invariants(WORKLOAD_GRAPH, placement_policies=policies)
    rules = [f["rule"] for f in findings]
    assert "concert-risk-placement-block" in rules


def test_concert_risk_rule_severity_error(tmp_path):
    nodes = intake_concert(CONCERT_FIXTURE)
    write_policy_nodes(nodes, tmp_path)
    policies = load_placement_policies(tmp_path, "workload:fraud-detection-pipeline")
    findings = check_graph_invariants(WORKLOAD_GRAPH, placement_policies=policies)
    concert_findings = [f for f in findings if f["rule"] == "concert-risk-placement-block"]
    assert all(f["severity"] == "error" for f in concert_findings)


def test_concert_risk_rule_message_has_blocked_env(tmp_path):
    nodes = intake_concert(CONCERT_FIXTURE)
    write_policy_nodes(nodes, tmp_path)
    policies = load_placement_policies(tmp_path, "workload:fraud-detection-pipeline")
    findings = check_graph_invariants(WORKLOAD_GRAPH, placement_policies=policies)
    concert = next(f for f in findings if f["rule"] == "concert-risk-placement-block")
    assert "shared-dev-01" in concert["message"]


def test_no_concert_rule_when_no_policies():
    findings = check_graph_invariants(WORKLOAD_GRAPH)
    rules = [f["rule"] for f in findings]
    assert "concert-risk-placement-block" not in rules


def test_no_concert_rule_when_policy_has_no_blocked_envs():
    clean_policies = intake_concert(CONCERT_CLEAN)
    findings = check_graph_invariants(WORKLOAD_GRAPH, placement_policies=clean_policies)
    rules = [f["rule"] for f in findings]
    assert "concert-risk-placement-block" not in rules


# ---------------------------------------------------------------------------
# validate_architecture_intent with kg_dir
# ---------------------------------------------------------------------------

def test_validate_intent_blocked_by_concert_risk(tmp_path):
    nodes = intake_concert(CONCERT_FIXTURE)
    write_policy_nodes(nodes, tmp_path)
    result = validate_architecture_intent(WORKLOAD_NODE, run_opa=False, kg_dir=tmp_path)
    assert not result["valid"]
    rules = [v["rule"] for v in result["violations"]]
    assert "concert-risk-placement-block" in rules


def test_validate_intent_clean_without_kg_dir():
    result = validate_architecture_intent(WORKLOAD_NODE, run_opa=False)
    assert result["valid"]


def test_validate_intent_clean_concert_low_risk(tmp_path):
    nodes = intake_concert(CONCERT_CLEAN)
    write_policy_nodes(nodes, tmp_path)
    node = {**WORKLOAD_NODE, "@id": "workload:analytics-dashboard", "name": "analytics-dashboard"}
    result = validate_architecture_intent(node, run_opa=False, kg_dir=tmp_path)
    rules = [v["rule"] for v in result["violations"]]
    assert "concert-risk-placement-block" not in rules


# ---------------------------------------------------------------------------
# kg_status shows policy count
# ---------------------------------------------------------------------------

def test_kg_status_policy_count(tmp_path):
    nodes = intake_concert(CONCERT_FIXTURE)
    write_policy_nodes(nodes, tmp_path)
    status = kg_status(tmp_path)
    assert status["policies"]["count"] == 2


def test_kg_status_policy_blocking(tmp_path):
    nodes = intake_concert(CONCERT_FIXTURE)
    write_policy_nodes(nodes, tmp_path)
    status = kg_status(tmp_path)
    assert status["policies"]["blocking"] == 1  # only fraud has blocked envs


def test_kg_status_no_policies(tmp_path):
    status = kg_status(tmp_path)
    assert status["policies"]["count"] == 0


# ---------------------------------------------------------------------------
# CLI: calm-forge intake-concert
# ---------------------------------------------------------------------------

def test_cli_intake_concert(tmp_path):
    fixture_file = tmp_path / "concert.json"
    fixture_file.write_text(json.dumps(CONCERT_FIXTURE))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "intake-concert",
        "--fixture", str(fixture_file),
        "--output-dir", str(tmp_path),
    ])
    assert result.exit_code == 0
    assert (tmp_path / "policies").exists()


def test_cli_intake_concert_reports_blocked(tmp_path):
    fixture_file = tmp_path / "concert.json"
    fixture_file.write_text(json.dumps(CONCERT_FIXTURE))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "intake-concert",
        "--fixture", str(fixture_file),
        "--output-dir", str(tmp_path),
    ])
    assert "shared-dev-01" in result.output


def test_cli_validate_intent_with_kg_dir_blocks(tmp_path):
    nodes = intake_concert(CONCERT_FIXTURE)
    write_policy_nodes(nodes, tmp_path)
    arch_file = tmp_path / "workload.json"
    arch_file.write_text(json.dumps(WORKLOAD_NODE))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "validate-intent",
        "--architecture", str(arch_file),
        "--no-opa",
        "--kg-dir", str(tmp_path),
    ])
    assert result.exit_code == 1
    assert "concert-risk-placement-block" in result.output


# ---------------------------------------------------------------------------
# MCP tool
# ---------------------------------------------------------------------------

def test_mcp_intake_concert(tmp_path):
    from calm_forge.mcp_server import intake_concert_tool
    result = intake_concert_tool(
        fixture=CONCERT_FIXTURE,
        output_dir=str(tmp_path),
    )
    assert result["count"] == 2
    assert result["blocking"] == 1


def test_mcp_intake_concert_without_output_dir():
    from calm_forge.mcp_server import intake_concert_tool
    result = intake_concert_tool(fixture=CONCERT_FIXTURE)
    assert result["count"] == 2
    assert result["written"] == []
