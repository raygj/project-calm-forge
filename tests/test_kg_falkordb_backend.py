"""Tests for FalkorDBBackend — Tier 2 of ADR-FORGE-KG-001.

Uses a FakeGraph (records Cypher + params, simulates result sets) so no
FalkorDB server is required. Live-server integration is exercised the same
way KuzuBackend tests gate on the kuzu package: skipped unless falkordb is
installed AND CALM_FORGE_TEST_FALKORDB_URL is set.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from calm_forge.kg_falkordb_backend import FalkorDBBackend
from calm_forge.kg_kuzu_backend import KGInvariantViolation

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------

class _FakeResult:
    def __init__(self, header=None, result_set=None):
        self.header = header or []
        self.result_set = result_set or []


class FakeGraph:
    """Records every query; optionally returns canned results by substring."""

    def __init__(self):
        self.queries: list[tuple[str, dict]] = []
        self.canned: list[tuple[str, _FakeResult]] = []

    def query(self, cypher, params=None):
        self.queries.append((cypher, params or {}))
        for needle, result in self.canned:
            if needle in cypher:
                return result
        return _FakeResult()


def _backend():
    graph = FakeGraph()
    return FalkorDBBackend(graph=graph), graph


def _merges(graph: FakeGraph, label: str) -> list[tuple[str, dict]]:
    return [(q, p) for q, p in graph.queries if f"MERGE ({label[0].lower()}" in q or f":{label} " in q or f":{label})" in q]


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

def test_requires_url_or_graph():
    with pytest.raises(ValueError):
        FalkorDBBackend()


def test_injected_graph_skips_connection():
    backend, graph = _backend()
    assert backend._graph is graph


def test_creates_id_indexes_on_init():
    _, graph = _backend()
    index_queries = [q for q, _ in graph.queries if q.startswith("CREATE INDEX")]
    assert len(index_queries) == 5
    assert any(":Workload" in q for q in index_queries)
    assert any(":TrustDomain" in q for q in index_queries)


def test_index_errors_tolerated():
    class ErroringGraph(FakeGraph):
        def query(self, cypher, params=None):
            if cypher.startswith("CREATE INDEX"):
                raise RuntimeError("Index already exists")
            return super().query(cypher, params)

    FalkorDBBackend(graph=ErroringGraph())  # no raise


# ---------------------------------------------------------------------------
# Node upserts — Cypher parity with KuzuBackend
# ---------------------------------------------------------------------------

def test_upsert_workload_params(tmp_path):
    backend, graph = _backend()
    backend.upsert_node({
        "@id": "workload:payments",
        "@type": "Workload",
        "declared_capabilities": ["http_read"],
        "trust_domains": ["trust_domain:prod.fsi"],
        "_provenance": {"provenance": "authored"},
    })
    q, p = graph.queries[-1]
    assert "MERGE (w:Workload {id: $id})" in q
    assert p["id"] == "workload:payments"
    assert p["trust_domains"] == ["trust_domain:prod.fsi"]
    assert p["provenance"] == "authored"


def test_upsert_trust_domain_params():
    backend, graph = _backend()
    backend.upsert_node({
        "@id": "trust_domain:prod.fsi",
        "@type": "TrustDomain",
        "spiffe_uri_prefix": "spiffe://prod.fsi",
        "commune": "forge",
        "peer_trust_domains": ["trust_domain:peer.prod"],
    })
    q, p = graph.queries[-1]
    assert "MERGE (t:TrustDomain {id: $id})" in q
    assert p["peer_trust_domains"] == ["trust_domain:peer.prod"]


def test_upsert_environment_flattens_compliance_label():
    backend, graph = _backend()
    backend.upsert_node({
        "@id": "env:prod-east",
        "@type": "ExecutionEnvironment",
        "region": "us-east-1",
        "labels": {"compliance": "pci"},
    })
    _, p = graph.queries[-1]
    assert p["labels_compliance"] == ["pci"]


def test_upsert_placement_writes_drift_state_and_placed_on():
    backend, graph = _backend()
    backend.upsert_node({
        "@id": "placement:payments:prod-east",
        "@type": "Placement",
        "workload_id": "workload:payments",
        "environment_id": "env:prod-east",
        "region": "us-east-1",
        "drift_state": {"status": "ok", "deviation_hours": 1.5},
    })
    placement_q, placement_p = graph.queries[-2]
    assert "MERGE (p:Placement {id: $id})" in placement_q
    assert placement_p["drift_state_status"] == "ok"
    assert placement_p["drift_state_deviation_hours"] == 1.5
    placed_on_q, placed_on_p = graph.queries[-1]
    assert "MERGE (p)-[:PLACED_ON]->(e)" in placed_on_q
    assert placed_on_p["to_id"] == "env:prod-east"


def test_upsert_placement_inline_manifests_as_edge():
    backend, graph = _backend()
    backend.upsert_node({
        "@id": "placement:payments:prod-east",
        "@type": "Placement",
        "workload_id": "workload:payments",
        "edges": [{
            "@type": "manifests_as",
            "from": "workload:payments",
            "capabilities_granted": ["http_read"],
        }],
    })
    edge_queries = [q for q, _ in graph.queries if "MANIFESTS_AS" in q]
    assert len(edge_queries) == 1


def test_upsert_unknown_type_skipped():
    backend, graph = _backend()
    before = len(graph.queries)
    backend.upsert_node({"@id": "x", "@type": "FutureType"})
    assert len(graph.queries) == before


def test_upsert_edge_skips_dangling():
    backend, graph = _backend()
    before = len(graph.queries)
    backend.upsert_edge({"@type": "manifests_as", "from": "", "to": "p:1"})
    assert len(graph.queries) == before


# ---------------------------------------------------------------------------
# query()
# ---------------------------------------------------------------------------

def test_query_builds_dicts_from_header():
    backend, graph = _backend()
    graph.canned.append(("MATCH (p:Placement)", _FakeResult(
        header=[(1, "id"), (1, "status")],
        result_set=[["placement:a", "ok"], ["placement:b", "violation"]],
    )))
    rows = backend.query("MATCH (p:Placement) RETURN p.id AS id, p.drift_state_status AS status")
    assert rows == [
        {"id": "placement:a", "status": "ok"},
        {"id": "placement:b", "status": "violation"},
    ]


def test_query_plain_string_header():
    backend, graph = _backend()
    graph.canned.append(("RETURN 1", _FakeResult(header=["n"], result_set=[[1]])))
    assert backend.query("RETURN 1 AS n") == [{"n": 1}]


def test_query_passes_params():
    backend, graph = _backend()
    backend.query("MATCH (w:Workload {id: $id}) RETURN w.id", params={"id": "workload:x"})
    _, p = graph.queries[-1]
    assert p == {"id": "workload:x"}


# ---------------------------------------------------------------------------
# load() — ordering and invariant
# ---------------------------------------------------------------------------

def _write_node(kg_dir: Path, subdir: str, node: dict) -> None:
    d = kg_dir / subdir
    d.mkdir(parents=True, exist_ok=True)
    fname = node["@id"].replace(":", "_").replace("/", "_") + ".json"
    (d / fname).write_text(json.dumps(node))


def test_load_ingests_all_directories(tmp_path):
    backend, graph = _backend()
    _write_node(tmp_path, "trust_domains", {"@id": "trust_domain:prod.fsi", "@type": "TrustDomain"})
    _write_node(tmp_path, "workloads", {"@id": "workload:payments", "@type": "Workload",
                                        "declared_capabilities": ["http_read"]})
    _write_node(tmp_path, "environments", {"@id": "env:prod-east", "@type": "ExecutionEnvironment"})
    _write_node(tmp_path, "placements", {"@id": "placement:p1", "@type": "Placement",
                                         "workload_id": "workload:payments"})
    _write_node(tmp_path, "policies", {"@id": "policy:p1", "@type": "PlacementPolicy"})

    backend.load(tmp_path)
    merged_labels = [q.split("MERGE (")[1].split(" {")[0] for q, _ in graph.queries
                     if q.startswith("MERGE (")]
    # Ordering: TrustDomain before Workload before Environment before Placement before Policy
    assert merged_labels.index("t:TrustDomain") < merged_labels.index("w:Workload")
    assert merged_labels.index("w:Workload") < merged_labels.index("e:ExecutionEnvironment")
    assert merged_labels.index("p:Placement") < merged_labels.index("pp:PlacementPolicy")


def test_load_enforces_capability_invariant(tmp_path):
    backend, _ = _backend()
    _write_node(tmp_path, "workloads", {
        "@id": "workload:payments", "@type": "Workload",
        "declared_capabilities": ["http_read"],
        "_provenance": {"provenance": "authored"},
    })
    _write_node(tmp_path, "placements", {
        "@id": "placement:p1", "@type": "Placement",
        "workload_id": "workload:payments",
        "edges": [{"@type": "manifests_as", "from": "workload:payments",
                   "capabilities_granted": ["http_read", "secrets_write"]}],
    })
    with pytest.raises(KGInvariantViolation):
        backend.load(tmp_path)


def test_load_skips_invariant_for_reconstructed(tmp_path):
    backend, _ = _backend()
    _write_node(tmp_path, "workloads", {
        "@id": "workload:legacy", "@type": "Workload",
        "declared_capabilities": [],
        "_provenance": {"provenance": "reconstructed"},
    })
    _write_node(tmp_path, "placements", {
        "@id": "placement:p1", "@type": "Placement",
        "workload_id": "workload:legacy",
        "edges": [{"@type": "manifests_as", "from": "workload:legacy",
                   "capabilities_granted": ["anything"]}],
    })
    backend.load(tmp_path)  # no raise


# ---------------------------------------------------------------------------
# _try_get_backend integration
# ---------------------------------------------------------------------------

def test_try_get_backend_falkordb_requires_url(tmp_path, capsys, monkeypatch):
    from calm_forge.drift_evaluator import _try_get_backend
    monkeypatch.setenv("CALM_FORGE_KG_BACKEND", "falkordb")
    monkeypatch.delenv("CALM_FORGE_KG_URL", raising=False)
    assert _try_get_backend(tmp_path) is None
    assert "CALM_FORGE_KG_URL" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Live server (optional)
# ---------------------------------------------------------------------------

def test_live_falkordb_roundtrip(tmp_path):
    url = os.environ.get("CALM_FORGE_TEST_FALKORDB_URL")
    if not url:
        pytest.skip("CALM_FORGE_TEST_FALKORDB_URL not set")
    pytest.importorskip("falkordb")

    backend = FalkorDBBackend(url=url, graph_name="calm_forge_test")
    backend.upsert_node({
        "@id": "workload:live-test", "@type": "Workload",
        "declared_capabilities": ["http_read"],
        "trust_domains": ["trust_domain:prod.fsi"],
    })
    rows = backend.query(
        "MATCH (w:Workload {id: $id}) RETURN w.trust_domains AS tds",
        params={"id": "workload:live-test"},
    )
    backend.close()
    assert rows[0]["tds"] == ["trust_domain:prod.fsi"]
