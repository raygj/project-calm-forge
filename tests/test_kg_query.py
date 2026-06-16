"""Tests for kg_query — KG predicate filtering and edge traversal."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.intake import (
    intake_acm,
    intake_ansible,
    intake_tfe,
    write_environment_nodes,
    write_placement_nodes,
    write_workload_nodes,
)
from calm_forge.kg_query import kg_query

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

ACM_FIXTURE = {
    "clusters": [
        {"name": "prod-east", "region": "us-east-1", "status": "ready",
         "substrate": "x86", "labels": {"environment": "prod"},
         "capabilities": ["http_read", "vault_dynamic_creds", "confidential_compute"]},
        {"name": "prod-eu", "region": "eu-west-1", "status": "degraded",
         "substrate": "x86", "labels": {"environment": "prod"},
         "capabilities": ["http_read"]},
    ]
}

AAP_FIXTURE = {
    "jobs": [
        {"id": "j1", "workload_name": "payments", "target_cluster": "prod-east",
         "namespace": "payments", "region": "us-east-1", "finished": "2026-05-01T00:00:00Z",
         "observed_capabilities": ["http_read", "vault_dynamic_creds"]},
        {"id": "j2", "workload_name": "payments", "target_cluster": "prod-eu",
         "namespace": "payments", "region": "eu-west-1", "finished": "2026-05-01T00:00:00Z",
         "observed_capabilities": ["http_read"]},
    ]
}

TFE_FIXTURE = {
    "workspaces": [
        {"name": "payments-prod", "terraform_version": "1.7.4", "tags": ["pci"],
         "vcs_repo": {}, "working_directory": "", "created_at": "2026-01-01T00:00:00Z",
         "updated_at": "2026-04-01T00:00:00Z", "variables": [], "resources": []},
    ]
}


def _build_kg(tmp_path) -> Path:
    env_nodes = intake_acm(ACM_FIXTURE)
    write_environment_nodes(env_nodes, tmp_path)
    placement_nodes = intake_ansible(AAP_FIXTURE, env_nodes)
    write_placement_nodes(placement_nodes, tmp_path)
    workload_nodes = intake_tfe(TFE_FIXTURE)
    write_workload_nodes(workload_nodes, tmp_path)
    return tmp_path


def _set_drift_status(tmp_path, status: str):
    for path in (tmp_path / "placements").glob("*.json"):
        node = json.loads(path.read_text())
        node["drift_state"]["status"] = status
        node["drift_state"]["last_evaluated"] = "2026-05-03T12:00:00Z"
        path.write_text(json.dumps(node))


# ---------------------------------------------------------------------------
# Type resolution
# ---------------------------------------------------------------------------

def test_query_type_alias_env(tmp_path):
    _build_kg(tmp_path)
    results = kg_query(tmp_path, "env", [], None)
    assert all(r["node"]["@type"] == "ExecutionEnvironment" for r in results)


def test_query_type_alias_placement(tmp_path):
    _build_kg(tmp_path)
    results = kg_query(tmp_path, "placement", [], None)
    assert all(r["node"]["@type"] == "Placement" for r in results)


def test_query_unknown_type_raises(tmp_path):
    with pytest.raises(ValueError, match="Unknown node type"):
        kg_query(tmp_path, "FooBar", [], None)


# ---------------------------------------------------------------------------
# No filter — returns all of a type
# ---------------------------------------------------------------------------

def test_query_all_environments(tmp_path):
    _build_kg(tmp_path)
    results = kg_query(tmp_path, "ExecutionEnvironment", [], None)
    assert len(results) == 2


def test_query_all_placements(tmp_path):
    _build_kg(tmp_path)
    results = kg_query(tmp_path, "Placement", [], None)
    assert len(results) == 2


def test_query_empty_kg_returns_empty(tmp_path):
    results = kg_query(tmp_path, "Placement", [], None)
    assert results == []


# ---------------------------------------------------------------------------
# --where predicate filtering
# ---------------------------------------------------------------------------

def test_query_where_top_level_field(tmp_path):
    _build_kg(tmp_path)
    results = kg_query(tmp_path, "ExecutionEnvironment", ["region=us-east-1"], None)
    assert len(results) == 1
    assert results[0]["node"]["region"] == "us-east-1"


def test_query_where_nested_field(tmp_path):
    _build_kg(tmp_path)
    _set_drift_status(tmp_path, "ok")
    # one placement to violation
    for i, path in enumerate(sorted((tmp_path / "placements").glob("*.json"))):
        if i == 0:
            node = json.loads(path.read_text())
            node["drift_state"]["status"] = "violation"
            path.write_text(json.dumps(node))
    results = kg_query(tmp_path, "Placement", ["drift_state.status=violation"], None)
    assert len(results) == 1
    assert results[0]["node"]["drift_state"]["status"] == "violation"


def test_query_where_array_containment(tmp_path):
    _build_kg(tmp_path)
    results = kg_query(tmp_path, "ExecutionEnvironment",
                       ["advertised_capabilities=confidential_compute"], None)
    assert len(results) == 1
    assert "confidential_compute" in results[0]["node"]["advertised_capabilities"]


def test_query_where_multiple_predicates(tmp_path):
    _build_kg(tmp_path)
    results = kg_query(tmp_path, "ExecutionEnvironment",
                       ["region=us-east-1", "status=ready"], None)
    assert len(results) == 1


def test_query_where_no_match_returns_empty(tmp_path):
    _build_kg(tmp_path)
    results = kg_query(tmp_path, "Placement", ["region=ap-southeast-1"], None)
    assert results == []


def test_query_where_missing_field_no_match(tmp_path):
    _build_kg(tmp_path)
    results = kg_query(tmp_path, "Placement", ["nonexistent_field=x"], None)
    assert results == []


def test_query_where_invalid_expr_raises():
    with pytest.raises(ValueError, match="expected 'path=value'"):
        from calm_forge.kg_query import _parse_predicate
        _parse_predicate("no-equals-sign")


# ---------------------------------------------------------------------------
# --follow manifests_as
# ---------------------------------------------------------------------------

def test_query_follow_manifests_as_from_placement(tmp_path):
    _build_kg(tmp_path)
    results = kg_query(tmp_path, "Placement", [], "manifests_as")
    assert all(len(r["related"]) >= 1 for r in results)
    for r in results:
        rel = r["related"][0]
        assert rel["edge_type"] == "manifests_as"
        assert rel["direction"] == "from"


def test_query_follow_manifests_as_capabilities_granted(tmp_path):
    _build_kg(tmp_path)
    results = kg_query(tmp_path, "Placement", ["region=us-east-1"], "manifests_as")
    assert len(results) == 1
    caps = results[0]["related"][0]["edge_data"]["capabilities_granted"]
    assert "http_read" in caps
    assert "vault_dynamic_creds" in caps


def test_query_follow_manifests_as_unresolved_when_no_workload(tmp_path):
    # Only write placements, no workloads dir
    env_nodes = intake_acm(ACM_FIXTURE)
    placements = intake_ansible(AAP_FIXTURE, env_nodes)
    write_placement_nodes(placements, tmp_path)
    results = kg_query(tmp_path, "Placement", [], "manifests_as")
    for r in results:
        assert r["related"][0]["node"].get("_unresolved") is True


def test_query_follow_manifests_as_from_workload(tmp_path):
    _build_kg(tmp_path)
    # Write an authored workload that matches the AAP fixture's workload name
    authored_wl = {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "Workload",
        "@id": "workload:payments",
        "name": "payments",
        "declared_capabilities": ["http_read", "vault_dynamic_creds"],
        "_provenance": {"authored_by": "test", "authored_at": "2026-05-01T00:00:00Z"},
    }
    (tmp_path / "workloads" / "payments.json").write_text(json.dumps(authored_wl))
    results = kg_query(tmp_path, "Workload", [], "manifests_as")
    # The authored workload should resolve to 2 placements
    authored = next((r for r in results if r["node"]["@id"] == "workload:payments"), None)
    assert authored is not None
    assert len(authored["related"]) == 2
    assert all(r["direction"] == "to" for r in authored["related"])


def test_query_follow_unknown_edge_returns_empty_related(tmp_path):
    _build_kg(tmp_path)
    results = kg_query(tmp_path, "Placement", [], "unknown_edge_type")
    assert all(r["related"] == [] for r in results)


def test_query_result_shape(tmp_path):
    _build_kg(tmp_path)
    results = kg_query(tmp_path, "Placement", [], None)
    for r in results:
        assert "node" in r
        assert "related" in r
        assert isinstance(r["related"], list)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_cli_kg_query_basic(tmp_path):
    _build_kg(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["kg", "query", "--kg-dir", str(tmp_path),
                                  "--type", "Placement"])
    assert result.exit_code == 0
    assert "Placement" in result.output


def test_cli_kg_query_where(tmp_path):
    _build_kg(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["kg", "query", "--kg-dir", str(tmp_path),
                                  "--type", "ExecutionEnvironment",
                                  "--where", "status=ready"])
    assert result.exit_code == 0
    assert "ExecutionEnvironment" in result.output


def test_cli_kg_query_json(tmp_path):
    _build_kg(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["kg", "query", "--kg-dir", str(tmp_path),
                                  "--type", "Placement", "--json"])
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert isinstance(data, list)
    assert all("node" in r for r in data)


def test_cli_kg_query_no_match(tmp_path):
    _build_kg(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["kg", "query", "--kg-dir", str(tmp_path),
                                  "--type", "Placement",
                                  "--where", "region=ap-southeast-1"])
    assert result.exit_code == 0
    assert "No Placement" in result.output


def test_cli_kg_query_follow(tmp_path):
    _build_kg(tmp_path)
    runner = CliRunner()
    result = runner.invoke(cli, ["kg", "query", "--kg-dir", str(tmp_path),
                                  "--type", "Placement", "--follow", "manifests_as"])
    assert result.exit_code == 0
    assert "manifests_as" in result.output


def test_cli_kg_query_unknown_type_error(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["kg", "query", "--kg-dir", str(tmp_path),
                                  "--type", "BadType"])
    assert result.exit_code != 0
