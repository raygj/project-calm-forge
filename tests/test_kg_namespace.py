"""Tests for multi-tenant KG namespace support (P3-002)."""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.intake import (
    intake_acm,
    intake_ansible,
    write_environment_nodes,
    write_placement_nodes,
)
from calm_forge.kg_inspect import kg_status
from calm_forge.kg_namespace import list_namespaces, resolve_kg_dir
from calm_forge.kg_query import kg_query

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ACM_A = {
    "clusters": [
        {"name": "cluster-a", "region": "us-east-1", "status": "ready",
         "substrate": "x86", "labels": {"team": "payments"},
         "capabilities": ["http_read", "vault_dynamic_creds"]},
    ]
}

AAP_A = {
    "jobs": [
        {"id": "j1", "workload_name": "payments-v2", "target_cluster": "cluster-a",
         "namespace": "payments", "region": "us-east-1", "finished": "2026-05-01T00:00:00Z",
         "observed_capabilities": ["http_read"]},
    ]
}

ACM_B = {
    "clusters": [
        {"name": "cluster-b", "region": "eu-west-1", "status": "ready",
         "substrate": "x86", "labels": {"team": "fraud"},
         "capabilities": ["confidential_compute"]},
    ]
}

AAP_B = {
    "jobs": [
        {"id": "j2", "workload_name": "fraud-v1", "target_cluster": "cluster-b",
         "namespace": "fraud", "region": "eu-west-1", "finished": "2026-05-02T00:00:00Z",
         "observed_capabilities": ["confidential_compute"]},
    ]
}

SPEC_A = {
    "name": "payments-v2",
    "purpose": "Payment processing",
    "owner": "payments-team",
    "components": [{"name": "api", "capabilities": ["http_read"]}],
    "compliance_scope": ["PCI-DSS-v4:req-3"],
    "allowed_regions": ["us-east-1"],
}

SPEC_B = {
    "name": "fraud-v1",
    "purpose": "Fraud detection",
    "owner": "fraud-team",
    "components": [{"name": "scorer", "capabilities": ["confidential_compute"]}],
    "compliance_scope": [],
    "allowed_regions": ["eu-west-1"],
}


def _build_ns(kg_root: Path, name: str, acm: dict, aap: dict) -> Path:
    ns_dir = kg_root / name
    envs = intake_acm(acm)
    write_environment_nodes(envs, ns_dir)
    placements = intake_ansible(aap, envs)
    write_placement_nodes(placements, ns_dir)
    return ns_dir


# ---------------------------------------------------------------------------
# resolve_kg_dir
# ---------------------------------------------------------------------------

def test_resolve_no_namespace_returns_root(tmp_path):
    assert resolve_kg_dir(tmp_path, None) == tmp_path


def test_resolve_empty_string_returns_root(tmp_path):
    assert resolve_kg_dir(tmp_path, "") == tmp_path


def test_resolve_namespace_returns_subdir(tmp_path):
    assert resolve_kg_dir(tmp_path, "payments-team") == tmp_path / "payments-team"


def test_resolve_nested_namespace(tmp_path):
    result = resolve_kg_dir(tmp_path, "org-a")
    assert result == tmp_path / "org-a"


# ---------------------------------------------------------------------------
# list_namespaces
# ---------------------------------------------------------------------------

def test_list_namespaces_empty_kg(tmp_path):
    result = list_namespaces(tmp_path)
    assert result == [("", tmp_path)]


def test_list_namespaces_includes_root(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    ns = list_namespaces(tmp_path)
    names = [n for n, _ in ns]
    assert "" in names


def test_list_namespaces_finds_named_namespace(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    ns = list_namespaces(tmp_path)
    names = [n for n, _ in ns]
    assert "payments-team" in names


def test_list_namespaces_finds_multiple(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    _build_ns(tmp_path, "fraud-team", ACM_B, AAP_B)
    ns = list_namespaces(tmp_path)
    names = [n for n, _ in ns]
    assert "payments-team" in names
    assert "fraud-team" in names


def test_list_namespaces_excludes_kg_subdirs(tmp_path):
    # environments/ is a standard KG subdir, not a namespace
    envs = intake_acm(ACM_A)
    write_environment_nodes(envs, tmp_path)
    ns = list_namespaces(tmp_path)
    names = [n for n, _ in ns]
    assert "environments" not in names


def test_list_namespaces_excludes_underscore_dirs(tmp_path):
    (_tmp_path := tmp_path / "_fabric").mkdir()
    ns = list_namespaces(tmp_path)
    names = [n for n, _ in ns]
    assert "_fabric" not in names


def test_list_namespaces_nonexistent_root():
    result = list_namespaces(Path("/nonexistent/kg"))
    assert result == [("", Path("/nonexistent/kg"))]


# ---------------------------------------------------------------------------
# kg_status with namespace
# ---------------------------------------------------------------------------

def test_kg_status_root_namespace(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    # Root namespace has no nodes
    status = kg_status(tmp_path, namespace=None)
    assert status["namespace"] == ""


def test_kg_status_named_namespace(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    status = kg_status(tmp_path, namespace="payments-team")
    assert status["environments"]["count"] == 1
    assert status["placements"]["count"] == 1


def test_kg_status_namespace_isolation(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    _build_ns(tmp_path, "fraud-team", ACM_B, AAP_B)
    payments = kg_status(tmp_path, namespace="payments-team")
    fraud = kg_status(tmp_path, namespace="fraud-team")
    assert payments["environments"]["count"] == 1
    assert fraud["environments"]["count"] == 1


def test_kg_status_all_namespaces_aggregates(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    _build_ns(tmp_path, "fraud-team", ACM_B, AAP_B)
    status = kg_status(tmp_path, namespace="*")
    assert status["namespace"] == "*"
    assert status["environments"]["count"] == 2
    assert status["placements"]["count"] == 2


def test_kg_status_all_namespaces_has_per_ns_breakdown(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    _build_ns(tmp_path, "fraud-team", ACM_B, AAP_B)
    status = kg_status(tmp_path, namespace="*")
    ns_names = [ns["namespace"] for ns in status["namespaces"]]
    assert "payments-team" in ns_names
    assert "fraud-team" in ns_names


# ---------------------------------------------------------------------------
# kg_query with namespace
# ---------------------------------------------------------------------------

def test_kg_query_named_namespace(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    _build_ns(tmp_path, "fraud-team", ACM_B, AAP_B)
    results = kg_query(tmp_path, "Placement", [], namespace="payments-team")
    ids = [r["node"]["@id"] for r in results]
    assert all("payments" in i for i in ids)


def test_kg_query_namespace_isolation(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    _build_ns(tmp_path, "fraud-team", ACM_B, AAP_B)
    results = kg_query(tmp_path, "Placement", [], namespace="payments-team")
    assert len(results) == 1


def test_kg_query_all_namespaces_merges(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    _build_ns(tmp_path, "fraud-team", ACM_B, AAP_B)
    results = kg_query(tmp_path, "Placement", [], namespace="*")
    assert len(results) == 2


def test_kg_query_result_has_namespace_tag(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    results = kg_query(tmp_path, "Placement", [], namespace="payments-team")
    assert results[0]["namespace"] == "payments-team"


def test_kg_query_all_namespaces_namespace_tags(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    _build_ns(tmp_path, "fraud-team", ACM_B, AAP_B)
    results = kg_query(tmp_path, "Placement", [], namespace="*")
    ns_tags = {r["namespace"] for r in results}
    assert "payments-team" in ns_tags
    assert "fraud-team" in ns_tags


def test_kg_query_no_namespace_backward_compat(tmp_path):
    # Root-level KG still works without namespace param
    envs = intake_acm(ACM_A)
    write_environment_nodes(envs, tmp_path)
    placements = intake_ansible(AAP_A, envs)
    write_placement_nodes(placements, tmp_path)
    results = kg_query(tmp_path, "Placement", [])
    assert len(results) == 1


# ---------------------------------------------------------------------------
# CLI — --namespace flag
# ---------------------------------------------------------------------------

def test_cli_kg_status_namespace(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    runner = CliRunner()
    result = runner.invoke(cli, [
        "kg", "status",
        "--kg-dir", str(tmp_path),
        "--namespace", "payments-team",
    ])
    assert result.exit_code == 0
    assert "ExecutionEnvironment" in result.output


def test_cli_kg_status_all_namespaces(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    _build_ns(tmp_path, "fraud-team", ACM_B, AAP_B)
    runner = CliRunner()
    result = runner.invoke(cli, [
        "kg", "status",
        "--kg-dir", str(tmp_path),
        "--namespace", "*",
        "--json",
    ])
    assert result.exit_code == 0
    import json as _json
    data = _json.loads(result.output)
    assert data["namespace"] == "*"
    assert data["environments"]["count"] == 2


def test_cli_kg_query_namespace(tmp_path):
    _build_ns(tmp_path, "payments-team", ACM_A, AAP_A)
    runner = CliRunner()
    result = runner.invoke(cli, [
        "kg", "query",
        "--kg-dir", str(tmp_path),
        "--type", "Placement",
        "--namespace", "payments-team",
        "--json",
    ])
    assert result.exit_code == 0
    import json as _json
    data = _json.loads(result.output)
    assert len(data) == 1


def test_cli_intake_acm_namespace(tmp_path):
    import json as _json
    fixture_file = tmp_path / "acm.json"
    fixture_file.write_text(_json.dumps(ACM_A))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "intake-acm",
        "--fixture", str(fixture_file),
        "--output-dir", str(tmp_path),
        "--namespace", "payments-team",
    ])
    assert result.exit_code == 0
    assert (tmp_path / "payments-team" / "environments").exists()
    assert not (tmp_path / "environments").exists()


def test_cli_intake_tfe_namespace(tmp_path):
    import json as _json
    fixture = {"workspaces": [
        {"name": "pay-prod", "terraform_version": "1.7.4", "tags": ["pci"],
         "vcs_repo": {}, "working_directory": "", "created_at": "2026-01-01T00:00:00Z",
         "updated_at": "2026-04-01T00:00:00Z", "variables": [], "resources": []},
    ]}
    fixture_file = tmp_path / "tfe.json"
    fixture_file.write_text(_json.dumps(fixture))
    runner = CliRunner()
    result = runner.invoke(cli, [
        "intake-tfe",
        "--fixture", str(fixture_file),
        "--output-dir", str(tmp_path),
        "--namespace", "payments-team",
    ])
    assert result.exit_code == 0
    assert (tmp_path / "payments-team" / "workloads").exists()
