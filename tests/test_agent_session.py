"""Tests for the agent autonomy session (P3-001)."""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from calm_forge.agent_session import run_agent_session
from calm_forge.cli import cli
from calm_forge.intake import (
    intake_acm,
    intake_ansible,
    write_environment_nodes,
    write_placement_nodes,
)
from calm_forge.interviewer import build_workload, write_workload_node

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SPEC = {
    "name": "fraud-detection-v3",
    "purpose": "Real-time fraud detection",
    "owner": "financial-crimes",
    "components": [
        {"name": "scorer", "capabilities": ["http_read", "confidential_compute"]},
        {"name": "store",  "capabilities": ["vault_dynamic_creds", "pii_read"]},
    ],
    "compliance_scope": ["PCI-DSS-v4:req-3", "PCI-DSS-v4:req-10"],
    "allowed_regions": ["us-east-1", "eu-west-1"],
}

# A spec that will trigger a validate-intent error (PCI without allowed_regions)
BAD_SPEC = {
    "name": "bad-workload",
    "purpose": "Test",
    "owner": "test-team",
    "components": [
        {"name": "svc", "capabilities": ["pii_read"]},
    ],
    "compliance_scope": ["PCI-DSS-v4:req-3"],
    "allowed_regions": [],   # missing → compliance-requires-region-constraint fires
}

ACM_FIXTURE = {
    "clusters": [
        {"name": "prod-east-ocp-01", "region": "us-east-1", "status": "ready",
         "substrate": "x86", "labels": {"compliance": "pci"},
         "capabilities": ["confidential_compute", "http_read", "vault_dynamic_creds"]},
    ]
}

AAP_FIXTURE = {
    "jobs": [
        {"id": "j1", "workload_name": "fraud-detection-v3",
         "target_cluster": "prod-east-ocp-01", "namespace": "fraud",
         "region": "us-east-1", "finished": "2026-05-01T00:00:00Z",
         "observed_capabilities": ["http_read", "confidential_compute"]},
    ]
}


def _populate_kg(tmp_path: Path) -> Path:
    env_nodes = intake_acm(ACM_FIXTURE)
    write_environment_nodes(env_nodes, tmp_path)
    placement_nodes = intake_ansible(AAP_FIXTURE, env_nodes)
    write_placement_nodes(placement_nodes, tmp_path)
    return tmp_path


# ---------------------------------------------------------------------------
# run_agent_session — happy path (spec only)
# ---------------------------------------------------------------------------

def test_session_status_success(tmp_path):
    result = run_agent_session({"spec": SPEC}, tmp_path)
    assert result["status"] == "success"


def test_session_workload_id_set(tmp_path):
    result = run_agent_session({"spec": SPEC}, tmp_path)
    assert result["workload_id"] == "workload:fraud-detection-v3"


def test_session_workload_authored_true(tmp_path):
    result = run_agent_session({"spec": SPEC}, tmp_path)
    assert result["workload_authored"] is True


def test_session_workload_node_written_to_kg(tmp_path):
    run_agent_session({"spec": SPEC}, tmp_path)
    workload_files = list((tmp_path / "workloads").glob("*.json"))
    assert len(workload_files) == 1


def test_session_no_violations_on_clean_spec(tmp_path):
    result = run_agent_session({"spec": SPEC}, tmp_path)
    errors = [v for v in result["violations"] if v.get("severity") == "error"]
    assert errors == []


def test_session_catalog_entities_returned(tmp_path):
    _populate_kg(tmp_path)
    result = run_agent_session({"spec": SPEC}, tmp_path)
    assert isinstance(result["catalog_entities"], list)


def test_session_artifacts_none_without_calm(tmp_path):
    result = run_agent_session({"spec": SPEC}, tmp_path)
    assert result["artifacts"] is None


# ---------------------------------------------------------------------------
# Six steps are logged
# ---------------------------------------------------------------------------

def test_session_step_count(tmp_path):
    result = run_agent_session({"spec": SPEC}, tmp_path)
    step_names = [s["step"] for s in result["steps"]]
    assert set(step_names) == {"kg-status", "kg-query", "interview", "validate-intent", "generate", "deploy", "backstage"}


def test_session_steps_ordered(tmp_path):
    result = run_agent_session({"spec": SPEC}, tmp_path)
    names = [s["step"] for s in result["steps"]]
    expected = ["kg-status", "kg-query", "interview", "validate-intent", "generate", "deploy", "backstage"]
    assert names == expected


def test_session_kg_status_step_has_overall_status(tmp_path):
    result = run_agent_session({"spec": SPEC}, tmp_path)
    kg_step = next(s for s in result["steps"] if s["step"] == "kg-status")
    assert "overall_status" in kg_step["result"]


def test_session_interview_step_has_workload_id(tmp_path):
    result = run_agent_session({"spec": SPEC}, tmp_path)
    iv_step = next(s for s in result["steps"] if s["step"] == "interview")
    assert iv_step["result"].get("workload_id") == "workload:fraud-detection-v3"


def test_session_generate_step_skipped_when_no_calm(tmp_path):
    result = run_agent_session({"spec": SPEC}, tmp_path)
    gen_step = next(s for s in result["steps"] if s["step"] == "generate")
    assert gen_step["result"].get("skipped") is True


# ---------------------------------------------------------------------------
# Idempotency — existing Workload is found and reused
# ---------------------------------------------------------------------------

def test_session_skips_interview_when_workload_exists(tmp_path):
    node = build_workload(SPEC)
    write_workload_node(node, tmp_path)
    result = run_agent_session({"spec": SPEC}, tmp_path)
    assert result["workload_authored"] is False


def test_session_workload_id_correct_when_existing(tmp_path):
    node = build_workload(SPEC)
    write_workload_node(node, tmp_path)
    result = run_agent_session({"spec": SPEC}, tmp_path)
    assert result["workload_id"] == "workload:fraud-detection-v3"


def test_session_kg_query_step_found_existing(tmp_path):
    node = build_workload(SPEC)
    write_workload_node(node, tmp_path)
    result = run_agent_session({"spec": SPEC}, tmp_path)
    kq = next(s for s in result["steps"] if s["step"] == "kg-query")
    assert kq["result"]["found_existing"] is True


def test_session_workload_count_not_duplicated(tmp_path):
    node = build_workload(SPEC)
    write_workload_node(node, tmp_path)
    run_agent_session({"spec": SPEC}, tmp_path)
    assert len(list((tmp_path / "workloads").glob("*.json"))) == 1


# ---------------------------------------------------------------------------
# Blocking — error-severity violations stop the pipeline
# ---------------------------------------------------------------------------

def test_session_blocked_on_error_violation(tmp_path):
    result = run_agent_session({"spec": BAD_SPEC}, tmp_path)
    assert result["status"] == "blocked"


def test_session_blocked_message_contains_rule(tmp_path):
    result = run_agent_session({"spec": BAD_SPEC}, tmp_path)
    assert "compliance-requires-region-constraint" in result["message"]


def test_session_blocked_violations_present(tmp_path):
    result = run_agent_session({"spec": BAD_SPEC}, tmp_path)
    assert any(v["severity"] == "error" for v in result.get("violations", []))


def test_session_blocked_no_generate_step(tmp_path):
    result = run_agent_session({"spec": BAD_SPEC}, tmp_path)
    step_names = [s["step"] for s in result["steps"]]
    assert "generate" not in step_names


def test_session_blocked_no_backstage_step(tmp_path):
    result = run_agent_session({"spec": BAD_SPEC}, tmp_path)
    step_names = [s["step"] for s in result["steps"]]
    assert "backstage" not in step_names


def test_session_warnings_not_blocking(tmp_path):
    # Spec with capabilities but no capability_ceiling policy → warning, not error
    spec = {
        "name": "warn-only",
        "purpose": "Test",
        "owner": "team",
        "components": [{"name": "svc", "capabilities": ["http_read"]}],
        "compliance_scope": [],
        "allowed_regions": ["us-east-1"],
    }
    result = run_agent_session({"spec": spec}, tmp_path)
    assert result["status"] == "success"


# ---------------------------------------------------------------------------
# No spec provided
# ---------------------------------------------------------------------------

def test_session_error_when_no_spec_and_no_calm(tmp_path):
    result = run_agent_session({}, tmp_path)
    assert result["status"] == "error"


def test_session_interview_skipped_when_no_spec(tmp_path):
    result = run_agent_session({}, tmp_path)
    step_names = [s["step"] for s in result["steps"]]
    assert "kg-status" in step_names  # ran before hitting error


# ---------------------------------------------------------------------------
# Backstage output dir
# ---------------------------------------------------------------------------

def test_session_backstage_writes_catalog(tmp_path):
    _populate_kg(tmp_path)
    catalog_dir = tmp_path / "catalog"
    run_agent_session({"spec": SPEC, "backstage_output_dir": str(catalog_dir)}, tmp_path)
    assert (catalog_dir / "catalog-info.yaml").exists()


def test_session_backstage_step_written_path_set(tmp_path):
    _populate_kg(tmp_path)
    catalog_dir = tmp_path / "catalog"
    result = run_agent_session({"spec": SPEC, "backstage_output_dir": str(catalog_dir)}, tmp_path)
    bs_step = next(s for s in result["steps"] if s["step"] == "backstage")
    assert bs_step["result"]["written"] is not None


# ---------------------------------------------------------------------------
# CLI: calm-forge agent-run
# ---------------------------------------------------------------------------

def test_cli_agent_run_spec_file(tmp_path):
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SPEC))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "agent-run",
        "--kg-dir", str(tmp_path),
        "--spec", str(spec_file),
    ])
    assert result.exit_code == 0
    assert "success" in result.output.lower()


def test_cli_agent_run_json_output(tmp_path):
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SPEC))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "agent-run",
        "--kg-dir", str(tmp_path),
        "--spec", str(spec_file),
        "--json",
    ])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["status"] == "success"
    assert data["workload_id"] == "workload:fraud-detection-v3"


def test_cli_agent_run_blocked_exits_1(tmp_path):
    spec_file = tmp_path / "bad.json"
    spec_file.write_text(json.dumps(BAD_SPEC))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "agent-run",
        "--kg-dir", str(tmp_path),
        "--spec", str(spec_file),
    ])
    assert result.exit_code == 1
    assert "blocked" in result.output.lower()


def test_cli_agent_run_no_spec_exits_1(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, [
        "agent-run",
        "--kg-dir", str(tmp_path),
    ])
    assert result.exit_code == 1


def test_cli_agent_run_shows_step_summary(tmp_path):
    spec_file = tmp_path / "spec.json"
    spec_file.write_text(json.dumps(SPEC))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "agent-run",
        "--kg-dir", str(tmp_path),
        "--spec", str(spec_file),
    ])
    assert "kg-status" in result.output
    assert "interview" in result.output
    assert "validate-intent" in result.output
    assert "backstage" in result.output


# ---------------------------------------------------------------------------
# MCP tool
# ---------------------------------------------------------------------------

def test_mcp_agent_run_returns_success(tmp_path):
    from calm_forge.mcp_server import agent_run_tool
    result = agent_run_tool(
        kg_dir=str(tmp_path),
        spec=SPEC,
    )
    assert result["status"] == "success"
    assert result["workload_id"] == "workload:fraud-detection-v3"


def test_mcp_agent_run_blocked_on_bad_spec(tmp_path):
    from calm_forge.mcp_server import agent_run_tool
    result = agent_run_tool(
        kg_dir=str(tmp_path),
        spec=BAD_SPEC,
    )
    assert result["status"] == "blocked"


def test_mcp_agent_run_no_spec_no_calm_error(tmp_path):
    from calm_forge.mcp_server import agent_run_tool
    result = agent_run_tool(kg_dir=str(tmp_path))
    assert result["status"] == "error"
