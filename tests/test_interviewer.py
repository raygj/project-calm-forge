"""Tests for the interview skill — Workload authoring."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.interviewer import build_workload, write_workload_node

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SIMPLE_SPEC = {
    "name": "payments-v2",
    "purpose": "Real-time payment processing",
    "owner": "platform-engineering",
    "components": [
        {"name": "api-gateway", "capabilities": ["http_read", "http_write"]},
        {"name": "processor", "capabilities": ["vault_dynamic_creds", "pii_read"]},
    ],
    "compliance_scope": ["PCI-DSS-v4:req-3"],
    "allowed_regions": ["us-east-1", "eu-west-1"],
}

MINIMAL_SPEC = {
    "name": "hello-world",
    "components": [],
}


# ---------------------------------------------------------------------------
# build_workload — node structure
# ---------------------------------------------------------------------------

def test_build_node_type():
    node = build_workload(SIMPLE_SPEC)
    assert node["@type"] == "Workload"


def test_build_node_id_slug():
    node = build_workload(SIMPLE_SPEC)
    assert node["@id"] == "workload:payments-v2"


def test_build_node_id_slugifies_spaces():
    node = build_workload({"name": "My Service Name", "components": []})
    assert node["@id"] == "workload:my-service-name"


def test_build_name_preserved():
    node = build_workload(SIMPLE_SPEC)
    assert node["name"] == "payments-v2"


def test_build_purpose_and_owner():
    node = build_workload(SIMPLE_SPEC)
    assert node["purpose"] == "Real-time payment processing"
    assert node["owner"] == "platform-engineering"


def test_build_compliance_scope():
    node = build_workload(SIMPLE_SPEC)
    assert node["compliance_scope"] == ["PCI-DSS-v4:req-3"]


def test_build_provenance_authored():
    node = build_workload(SIMPLE_SPEC)
    assert node["_provenance"]["provenance"] == "authored"
    assert node["_provenance"]["authored_by"] == "calm-forge/interview"


def test_build_review_required_false():
    node = build_workload(SIMPLE_SPEC)
    assert node["review_required"] is False


def test_build_version():
    node = build_workload(SIMPLE_SPEC)
    assert node["version"] == "1.0.0"


def test_build_context():
    node = build_workload(SIMPLE_SPEC)
    assert "calmforge.io/kg" in node["@context"]


# ---------------------------------------------------------------------------
# build_workload — components
# ---------------------------------------------------------------------------

def test_build_components_count():
    node = build_workload(SIMPLE_SPEC)
    assert len(node["nodes"]) == 2


def test_build_component_type():
    node = build_workload(SIMPLE_SPEC)
    assert all(c["@type"] == "WorkloadComponent" for c in node["nodes"])


def test_build_component_id_format():
    node = build_workload(SIMPLE_SPEC)
    ids = {c["@id"] for c in node["nodes"]}
    assert "workload:payments-v2:api-gateway" in ids
    assert "workload:payments-v2:processor" in ids


def test_build_component_capabilities():
    node = build_workload(SIMPLE_SPEC)
    gw = next(c for c in node["nodes"] if c["name"] == "api-gateway")
    assert set(gw["declared_capabilities"]) == {"http_read", "http_write"}


def test_build_component_role_optional():
    spec = {**SIMPLE_SPEC, "components": [
        {"name": "svc", "role": "api-gateway", "capabilities": []},
    ]}
    node = build_workload(spec)
    assert node["nodes"][0]["role"] == "api-gateway"


def test_build_no_components():
    node = build_workload(MINIMAL_SPEC)
    assert node.get("nodes", []) == []


# ---------------------------------------------------------------------------
# build_workload — declared_capabilities (flat union)
# ---------------------------------------------------------------------------

def test_build_declared_capabilities_union():
    node = build_workload(SIMPLE_SPEC)
    caps = set(node["declared_capabilities"])
    assert caps == {"http_read", "http_write", "vault_dynamic_creds", "pii_read"}


def test_build_declared_capabilities_deduplicated():
    spec = {
        "name": "dedup",
        "components": [
            {"name": "a", "capabilities": ["http_read", "vault_dynamic_creds"]},
            {"name": "b", "capabilities": ["http_read"]},
        ],
    }
    node = build_workload(spec)
    assert node["declared_capabilities"].count("http_read") == 1


def test_build_declared_capabilities_sorted():
    node = build_workload(SIMPLE_SPEC)
    assert node["declared_capabilities"] == sorted(node["declared_capabilities"])


def test_build_declared_capabilities_empty_when_no_components():
    node = build_workload(MINIMAL_SPEC)
    assert node["declared_capabilities"] == []


# ---------------------------------------------------------------------------
# build_workload — edges
# ---------------------------------------------------------------------------

def test_build_requires_capability_edges_present():
    node = build_workload(SIMPLE_SPEC)
    req_cap = [e for e in node["edges"] if e["@type"] == "requires_capability"]
    assert len(req_cap) == 4  # 2 + 2


def test_build_requires_capability_edge_shape():
    node = build_workload(SIMPLE_SPEC)
    req_cap = [e for e in node["edges"] if e["@type"] == "requires_capability"]
    for e in req_cap:
        assert e["from"].startswith("workload:payments-v2:")
        assert e["to"].startswith("capability:")


def test_build_authored_in_edges():
    node = build_workload(SIMPLE_SPEC)
    auth_in = [e for e in node["edges"] if e["@type"] == "authored_in"]
    assert len(auth_in) == 1
    assert auth_in[0]["to"] == "compliance:PCI-DSS-v4:req-3"


def test_build_no_edges_when_no_components_no_compliance():
    node = build_workload(MINIMAL_SPEC)
    assert node.get("edges", []) == []


# ---------------------------------------------------------------------------
# build_workload — policies
# ---------------------------------------------------------------------------

def test_build_region_policy_present():
    node = build_workload(SIMPLE_SPEC)
    data_res = next(
        (p for p in node["policies"] if p.get("predicate_type") == "compliance_boundary"),
        None,
    )
    assert data_res is not None
    assert data_res["allowed_regions"] == ["us-east-1", "eu-west-1"]


def test_build_capability_ceiling_policy_always_present():
    node = build_workload(SIMPLE_SPEC)
    ceiling = next(
        (p for p in node["policies"] if p.get("predicate_type") == "capability_ceiling"),
        None,
    )
    assert ceiling is not None
    assert ceiling["enforcement_mode"] == "enforce"


def test_build_no_region_policy_when_no_regions():
    node = build_workload({**SIMPLE_SPEC, "allowed_regions": []})
    data_res = [p for p in node.get("policies", []) if p.get("predicate_type") == "compliance_boundary"]
    assert data_res == []


# ---------------------------------------------------------------------------
# write_workload_node
# ---------------------------------------------------------------------------

def test_write_creates_file(tmp_path):
    node = build_workload(SIMPLE_SPEC)
    path = write_workload_node(node, tmp_path)
    assert path.exists()
    assert path.suffix == ".json"


def test_write_creates_workloads_subdir(tmp_path):
    node = build_workload(SIMPLE_SPEC)
    write_workload_node(node, tmp_path)
    assert (tmp_path / "workloads").is_dir()


def test_write_roundtrip(tmp_path):
    node = build_workload(SIMPLE_SPEC)
    path = write_workload_node(node, tmp_path)
    loaded = json.loads(path.read_text())
    assert loaded["@id"] == node["@id"]
    assert loaded["declared_capabilities"] == node["declared_capabilities"]


# ---------------------------------------------------------------------------
# Reference patterns — validate 3 authored patterns exist and are well-formed
# ---------------------------------------------------------------------------


def _load_kg_pattern(name: str) -> dict:
    pkg_dir = Path(__file__).parent.parent / "src/calm_forge/knowledge_graph"
    return json.loads((pkg_dir / f"{name}.json").read_text())


@pytest.mark.parametrize("pattern_name", [
    "healthcare-hl7-pipeline",
    "supply-chain-analytics",
    "identity-verification-kyc",
])
def test_reference_pattern_exists(pattern_name):
    node = _load_kg_pattern(pattern_name)
    assert node["@type"] == "Workload"


@pytest.mark.parametrize("pattern_name", [
    "healthcare-hl7-pipeline",
    "supply-chain-analytics",
    "identity-verification-kyc",
])
def test_reference_pattern_authored_provenance(pattern_name):
    node = _load_kg_pattern(pattern_name)
    assert node["_provenance"]["provenance"] == "authored"
    assert node["review_required"] is False


@pytest.mark.parametrize("pattern_name", [
    "healthcare-hl7-pipeline",
    "supply-chain-analytics",
    "identity-verification-kyc",
])
def test_reference_pattern_has_requires_capability_edges(pattern_name):
    node = _load_kg_pattern(pattern_name)
    req_caps = [e for e in node.get("edges", []) if e["@type"] == "requires_capability"]
    assert len(req_caps) >= 4  # at least 4 capabilities declared


@pytest.mark.parametrize("pattern_name", [
    "healthcare-hl7-pipeline",
    "supply-chain-analytics",
    "identity-verification-kyc",
])
def test_reference_pattern_capability_ceiling_policy(pattern_name):
    node = _load_kg_pattern(pattern_name)
    ceiling = next(
        (p for p in node.get("policies", []) if p.get("predicate_type") == "capability_ceiling"),
        None,
    )
    assert ceiling is not None


# ---------------------------------------------------------------------------
# CLI — interview command (non-interactive via --spec)
# ---------------------------------------------------------------------------

def test_cli_interview_spec_json_output(tmp_path):
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SIMPLE_SPEC))
    runner = CliRunner()
    result = runner.invoke(cli, ["interview", "--spec", str(spec_file), "--json"])
    assert result.exit_code == 0
    node = json.loads(result.output)
    assert node["@type"] == "Workload"
    assert node["@id"] == "workload:payments-v2"


def test_cli_interview_spec_writes_to_dir(tmp_path):
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SIMPLE_SPEC))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "interview", "--spec", str(spec_file), "--output-dir", str(tmp_path),
    ])
    assert result.exit_code == 0
    assert (tmp_path / "workloads" / "payments-v2.json").exists()


def test_cli_interview_spec_summary_output(tmp_path):
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SIMPLE_SPEC))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "interview", "--spec", str(spec_file), "--output-dir", str(tmp_path),
    ])
    assert result.exit_code == 0
    assert "workload:payments-v2" in result.output
    assert "requires_capability" in result.output


def test_cli_interview_interactive(tmp_path):
    runner = CliRunner()
    user_input = "\n".join([
        "simple-service",       # name
        "A simple service",     # purpose
        "my-team",              # owner
        "web,db",               # components
        "http_read,http_write", # capabilities for web
        "encryption_at_rest",   # capabilities for db
        "",                     # no compliance
        "us-east-1",            # regions
    ]) + "\n"
    result = runner.invoke(cli, ["interview", "--json"], input=user_input)
    assert result.exit_code == 0
    # Find the JSON in output (may have prompt text before it)
    lines = result.output.strip().splitlines()
    json_start = next(i for i, line in enumerate(lines) if line.strip().startswith("{"))
    node = json.loads("\n".join(lines[json_start:]))
    assert node["@id"] == "workload:simple-service"
    assert "http_read" in node["declared_capabilities"]
    assert "encryption_at_rest" in node["declared_capabilities"]
