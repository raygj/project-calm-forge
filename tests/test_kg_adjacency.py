"""Tests for the canonical adjacency predicate — ADR-FORGE-KG-002.

query_adjacent (filesystem evaluation), the /graph/adjacent endpoint, and
graph-tier parity for the in-ADR reference Cypher (when kuzu is installed).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from calm_forge.kg_coherence_api import query_adjacent

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _write_workload(kg_dir: Path, workload_id: str,
                    trust_domains: list[str] | None = None) -> None:
    (kg_dir / "workloads").mkdir(parents=True, exist_ok=True)
    node = {
        "@id": workload_id,
        "@type": "Workload",
        "declared_capabilities": ["http_read"],
        "_provenance": {"provenance": "authored"},
    }
    if trust_domains is not None:
        node["trust_domains"] = trust_domains
    fname = workload_id.replace(":", "_") + ".json"
    (kg_dir / "workloads" / fname).write_text(json.dumps(node))


def _write_placement(kg_dir: Path, workload_id: str, environment_id: str) -> None:
    (kg_dir / "placements").mkdir(parents=True, exist_ok=True)
    pid = f"placement:{workload_id.split(':')[1]}:{environment_id.split(':')[1]}"
    node = {
        "@id": pid,
        "@type": "Placement",
        "workload_id": workload_id,
        "environment_id": environment_id,
        "region": "us-east-1",
    }
    fname = pid.replace(":", "_") + ".json"
    (kg_dir / "placements" / fname).write_text(json.dumps(node))


def _write_environment(kg_dir: Path, env_id: str) -> None:
    (kg_dir / "environments").mkdir(parents=True, exist_ok=True)
    node = {"@id": env_id, "@type": "ExecutionEnvironment", "region": "us-east-1"}
    (kg_dir / "environments" / (env_id.replace(":", "_") + ".json")).write_text(json.dumps(node))


# ---------------------------------------------------------------------------
# shared_trust_domain
# ---------------------------------------------------------------------------

def test_shared_trust_domain_match(tmp_path):
    _write_workload(tmp_path, "workload:a", trust_domains=["trust_domain:prod.fsi"])
    _write_workload(tmp_path, "workload:b", trust_domains=["trust_domain:prod.fsi"])
    result = query_adjacent(tmp_path, "workload:a")
    assert [n["workload_id"] for n in result["neighbors"]] == ["workload:b"]
    assert result["neighbors"][0]["basis"] == ["shared_trust_domain"]
    assert result["neighbors"][0]["shared_trust_domains"] == ["prod.fsi"]


def test_shared_trust_domain_no_overlap(tmp_path):
    _write_workload(tmp_path, "workload:a", trust_domains=["trust_domain:prod.fsi"])
    _write_workload(tmp_path, "workload:b", trust_domains=["trust_domain:dev.fsi"])
    result = query_adjacent(tmp_path, "workload:a")
    assert result["neighbors"] == []


def test_shared_trust_domain_prefix_normalization(tmp_path):
    _write_workload(tmp_path, "workload:a", trust_domains=["prod.fsi"])
    _write_workload(tmp_path, "workload:b", trust_domains=["trust_domain:prod.fsi"])
    result = query_adjacent(tmp_path, "workload:a")
    assert [n["workload_id"] for n in result["neighbors"]] == ["workload:b"]


def test_empty_trust_domains_has_no_neighbors_on_that_basis(tmp_path):
    # Strict per ADR — a workload declaring no trust domains has none.
    _write_workload(tmp_path, "workload:a")
    _write_workload(tmp_path, "workload:b", trust_domains=["prod.fsi"])
    result = query_adjacent(tmp_path, "workload:a", basis="shared_trust_domain")
    assert result["neighbors"] == []


def test_irreflexive(tmp_path):
    _write_workload(tmp_path, "workload:a", trust_domains=["prod.fsi"])
    result = query_adjacent(tmp_path, "workload:a")
    assert all(n["workload_id"] != "workload:a" for n in result["neighbors"])


def test_symmetric(tmp_path):
    _write_workload(tmp_path, "workload:a", trust_domains=["prod.fsi"])
    _write_workload(tmp_path, "workload:b", trust_domains=["prod.fsi"])
    a_side = query_adjacent(tmp_path, "workload:a")["neighbors"]
    b_side = query_adjacent(tmp_path, "workload:b")["neighbors"]
    assert [n["workload_id"] for n in a_side] == ["workload:b"]
    assert [n["workload_id"] for n in b_side] == ["workload:a"]


# ---------------------------------------------------------------------------
# co_located
# ---------------------------------------------------------------------------

def test_co_located_match(tmp_path):
    _write_environment(tmp_path, "env:prod-east")
    _write_placement(tmp_path, "workload:a", "env:prod-east")
    _write_placement(tmp_path, "workload:b", "env:prod-east")
    result = query_adjacent(tmp_path, "workload:a")
    assert [n["workload_id"] for n in result["neighbors"]] == ["workload:b"]
    assert result["neighbors"][0]["basis"] == ["co_located"]
    assert result["neighbors"][0]["shared_environments"] == ["env:prod-east"]


def test_co_located_different_environments(tmp_path):
    _write_placement(tmp_path, "workload:a", "env:prod-east")
    _write_placement(tmp_path, "workload:b", "env:prod-west")
    result = query_adjacent(tmp_path, "workload:a")
    assert result["neighbors"] == []


def test_co_located_includes_reconstructed_without_workload_node(tmp_path):
    # co_located matches on Placement.workload_id — no Workload node needed.
    _write_placement(tmp_path, "workload:a", "env:prod-east")
    _write_placement(tmp_path, "workload:legacy", "env:prod-east")
    result = query_adjacent(tmp_path, "workload:a")
    assert [n["workload_id"] for n in result["neighbors"]] == ["workload:legacy"]


def test_co_located_crosses_trust_domains(tmp_path):
    # Deliberate per ADR: a cluster repave hits every tenant.
    _write_workload(tmp_path, "workload:a", trust_domains=["prod.fsi"])
    _write_workload(tmp_path, "workload:b", trust_domains=["dev.fsi"])
    _write_placement(tmp_path, "workload:a", "env:shared")
    _write_placement(tmp_path, "workload:b", "env:shared")
    result = query_adjacent(tmp_path, "workload:a")
    assert [n["workload_id"] for n in result["neighbors"]] == ["workload:b"]
    assert result["neighbors"][0]["basis"] == ["co_located"]


# ---------------------------------------------------------------------------
# Composite behavior
# ---------------------------------------------------------------------------

def test_both_bases_fire_on_same_neighbor(tmp_path):
    _write_workload(tmp_path, "workload:a", trust_domains=["prod.fsi"])
    _write_workload(tmp_path, "workload:b", trust_domains=["prod.fsi"])
    _write_placement(tmp_path, "workload:a", "env:prod-east")
    _write_placement(tmp_path, "workload:b", "env:prod-east")
    result = query_adjacent(tmp_path, "workload:a")
    assert len(result["neighbors"]) == 1
    assert sorted(result["neighbors"][0]["basis"]) == ["co_located", "shared_trust_domain"]


def test_basis_filter_restricts_evaluation(tmp_path):
    _write_workload(tmp_path, "workload:a", trust_domains=["prod.fsi"])
    _write_workload(tmp_path, "workload:b", trust_domains=["prod.fsi"])
    _write_placement(tmp_path, "workload:a", "env:prod-east")
    _write_placement(tmp_path, "workload:b", "env:prod-east")
    result = query_adjacent(tmp_path, "workload:a", basis="co_located")
    assert result["bases_evaluated"] == ["co_located"]
    assert result["neighbors"][0]["basis"] == ["co_located"]


def test_bases_evaluated_defaults_to_all_enabled(tmp_path):
    result = query_adjacent(tmp_path, "workload:a")
    assert result["bases_evaluated"] == ["shared_trust_domain", "co_located"]


def test_blast_radius_phase_gated(tmp_path):
    with pytest.raises(NotImplementedError, match="ADR-FORGE-KG-002"):
        query_adjacent(tmp_path, "workload:a", basis="blast_radius")


def test_unknown_basis_rejected(tmp_path):
    with pytest.raises(ValueError, match="shared_capability"):
        query_adjacent(tmp_path, "workload:a", basis="shared_capability")


# ---------------------------------------------------------------------------
# HTTP endpoint
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from calm_forge.api import app
    from calm_forge.kg_coherence_api import configure_coherence_kg_dir

    monkeypatch.delenv("CALM_FORGE_COHERENCE_AUTH", raising=False)
    configure_coherence_kg_dir(tmp_path)
    return TestClient(app)


def test_adjacent_endpoint_returns_neighbors(client, tmp_path):
    _write_workload(tmp_path, "workload:a", trust_domains=["prod.fsi"])
    _write_workload(tmp_path, "workload:b", trust_domains=["prod.fsi"])
    resp = client.get("/graph/adjacent", params={"workload_id": "workload:a"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["workload_id"] == "workload:a"
    assert body["neighbors"][0]["workload_id"] == "workload:b"
    assert body["neighbors"][0]["basis"] == ["shared_trust_domain"]


def test_adjacent_endpoint_blast_radius_501(client):
    resp = client.get("/graph/adjacent",
                      params={"workload_id": "workload:a", "basis": "blast_radius"})
    assert resp.status_code == 501


def test_adjacent_endpoint_unknown_basis_400(client):
    resp = client.get("/graph/adjacent",
                      params={"workload_id": "workload:a", "basis": "nonsense"})
    assert resp.status_code == 400


def test_adjacent_endpoint_subject_to_spiffe_auth(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from calm_forge.api import app
    from calm_forge.kg_coherence_api import configure_coherence_kg_dir

    monkeypatch.setenv("CALM_FORGE_COHERENCE_AUTH", "spiffe")
    monkeypatch.setenv("CALM_FORGE_COHERENCE_PEERS", "prod.fsi")
    configure_coherence_kg_dir(tmp_path)
    resp = TestClient(app).get("/graph/adjacent", params={"workload_id": "workload:a"})
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Graph-tier parity — the in-ADR reference Cypher (Kuzu)
# ---------------------------------------------------------------------------

_SHARED_TD_CYPHER = (
    "MATCH (w1:Workload {id: $wid}), (w2:Workload) "
    "WHERE w1.id <> w2.id "
    "  AND any(td IN w1.trust_domains WHERE td IN w2.trust_domains) "
    "RETURN w2.id AS workload_id"
)

_CO_LOCATED_CYPHER = (
    "MATCH (p1:Placement)-[:PLACED_ON]->(e:ExecutionEnvironment)<-[:PLACED_ON]-(p2:Placement) "
    "WHERE p1.workload_id = $wid AND p2.workload_id <> $wid "
    "RETURN DISTINCT p2.workload_id AS workload_id, e.id AS environment"
)


def test_reference_cypher_parity_with_filesystem(tmp_path):
    pytest.importorskip("kuzu")
    from calm_forge.kg_kuzu_backend import KuzuBackend

    _write_workload(tmp_path, "workload:a", trust_domains=["trust_domain:prod.fsi"])
    _write_workload(tmp_path, "workload:b", trust_domains=["trust_domain:prod.fsi"])
    _write_workload(tmp_path, "workload:c", trust_domains=["trust_domain:dev.fsi"])
    _write_environment(tmp_path, "env:prod-east")
    _write_placement(tmp_path, "workload:a", "env:prod-east")
    _write_placement(tmp_path, "workload:c", "env:prod-east")

    backend = KuzuBackend(db_path=tmp_path / "kg.db")
    backend.load(tmp_path)
    td_rows = backend.query(_SHARED_TD_CYPHER, params={"wid": "workload:a"})
    co_rows = backend.query(_CO_LOCATED_CYPHER, params={"wid": "workload:a"})
    backend.close()

    fs = query_adjacent(tmp_path, "workload:a")
    fs_td = {n["workload_id"] for n in fs["neighbors"] if "shared_trust_domain" in n["basis"]}
    fs_co = {n["workload_id"] for n in fs["neighbors"] if "co_located" in n["basis"]}

    assert {r["workload_id"] for r in td_rows} == fs_td == {"workload:b"}
    assert {r["workload_id"] for r in co_rows} == fs_co == {"workload:c"}
