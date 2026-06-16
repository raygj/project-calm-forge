"""Tests for trust-domain-scoped query_shadow — ADR-FORGE-KG-001 Phase 2
acceptance criterion, match predicate per ADR-0024 (2026-05-30 extension).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from calm_forge.kg_coherence_api import query_shadow

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _write_workload(
    kg_dir: Path,
    workload_id: str,
    provenance: str = "authored",
    trust_domains: list[str] | None = None,
) -> None:
    (kg_dir / "workloads").mkdir(parents=True, exist_ok=True)
    node = {
        "@id": workload_id,
        "@type": "Workload",
        "declared_capabilities": ["http_read"],
        "_provenance": {"provenance": provenance},
    }
    if trust_domains is not None:
        node["trust_domains"] = trust_domains
    fname = workload_id.replace(":", "_").replace("/", "_") + ".json"
    (kg_dir / "workloads" / fname).write_text(json.dumps(node))


def _write_trust_domain(kg_dir: Path, name: str, peers: list[str] | None = None) -> None:
    (kg_dir / "trust_domains").mkdir(parents=True, exist_ok=True)
    node = {
        "@id": f"trust_domain:{name}",
        "@type": "TrustDomain",
        "spiffe_uri_prefix": f"spiffe://{name}",
        "commune": "forge",
        "peer_trust_domains": peers or [],
    }
    fname = name.replace(".", "_") + ".json"
    (kg_dir / "trust_domains" / fname).write_text(json.dumps(node))


# ---------------------------------------------------------------------------
# Scoped match predicate (ADR-0024)
# ---------------------------------------------------------------------------

def test_scoped_agent_in_declared_trust_domain_matches(tmp_path):
    _write_workload(tmp_path, "workload:payments", trust_domains=["trust_domain:prod.fsi"])
    result = query_shadow(tmp_path, agents=[
        {"workload_id": "workload:payments", "trust_domain": "prod.fsi"},
    ])
    assert result["shadow_agents"] == []
    assert "workload:payments" not in result["unmatched_authored"]


def test_scoped_trust_domain_mismatch_is_shadow(tmp_path):
    _write_workload(tmp_path, "workload:payments", trust_domains=["trust_domain:prod.fsi"])
    result = query_shadow(tmp_path, agents=[
        {"workload_id": "workload:payments", "trust_domain": "dev.fsi"},
    ])
    assert result["shadow_agents"] == ["workload:payments"]


def test_scoped_mismatch_reported_in_diagnostic_bucket(tmp_path):
    _write_workload(tmp_path, "workload:payments", trust_domains=["trust_domain:prod.fsi"])
    result = query_shadow(tmp_path, agents=[
        {"workload_id": "workload:payments", "trust_domain": "dev.fsi"},
    ])
    assert len(result["trust_domain_mismatches"]) == 1
    mismatch = result["trust_domain_mismatches"][0]
    assert mismatch["agent_workload_id"] == "workload:payments"
    assert mismatch["agent_trust_domain"] == "dev.fsi"
    assert mismatch["workload_trust_domains"] == ["prod.fsi"]


def test_scoped_unknown_key_is_shadow_without_mismatch_entry(tmp_path):
    _write_workload(tmp_path, "workload:payments", trust_domains=["trust_domain:prod.fsi"])
    result = query_shadow(tmp_path, agents=[
        {"workload_id": "workload:rogue", "trust_domain": "prod.fsi"},
    ])
    assert result["shadow_agents"] == ["workload:rogue"]
    assert result["trust_domain_mismatches"] == []


def test_scoped_workload_without_trust_domains_never_matches(tmp_path):
    # ADR-0024 predicate is strict: agent.trust_domain ∈ workload.trust_domains.
    # A workload declaring no trust domains cannot manifest anywhere.
    _write_workload(tmp_path, "workload:payments")  # no trust_domains
    result = query_shadow(tmp_path, agents=[
        {"workload_id": "workload:payments", "trust_domain": "prod.fsi"},
    ])
    assert result["shadow_agents"] == ["workload:payments"]
    assert result["trust_domain_mismatches"][0]["workload_trust_domains"] == []


def test_scoped_prefix_normalization_is_symmetric(tmp_path):
    # "prod.fsi" on the workload, "trust_domain:prod.fsi" from the agent — equivalent.
    _write_workload(tmp_path, "workload:payments", trust_domains=["prod.fsi"])
    result = query_shadow(tmp_path, agents=[
        {"workload_id": "workload:payments", "trust_domain": "trust_domain:prod.fsi"},
    ])
    assert result["shadow_agents"] == []


def test_scoped_multi_trust_domain_disambiguation(tmp_path):
    # Same path under different trust domains: prod matches, dev does not (ADR-0024).
    _write_workload(tmp_path, "workload:payments", trust_domains=["trust_domain:prod.fsi"])
    result = query_shadow(tmp_path, agents=[
        {"workload_id": "workload:payments", "trust_domain": "prod.fsi"},
        {"workload_id": "workload:payments", "trust_domain": "dev.fsi"},
    ])
    assert result["shadow_agents"] == ["workload:payments"]
    assert len(result["trust_domain_mismatches"]) == 1


def test_scoped_matched_workload_not_in_unmatched(tmp_path):
    _write_workload(tmp_path, "workload:payments", trust_domains=["prod.fsi"])
    _write_workload(tmp_path, "workload:fraud", trust_domains=["prod.fsi"])
    result = query_shadow(tmp_path, agents=[
        {"workload_id": "workload:payments", "trust_domain": "prod.fsi"},
    ])
    assert result["unmatched_authored"] == ["workload:fraud"]


def test_scoped_reconstructed_bucket_preserved(tmp_path):
    _write_workload(tmp_path, "workload:legacy", provenance="reconstructed",
                    trust_domains=["prod.fsi"])
    result = query_shadow(tmp_path, agents=[
        {"workload_id": "workload:other", "trust_domain": "prod.fsi"},
    ])
    assert result["unmatched_reconstructed"] == ["workload:legacy"]


def test_scoped_response_flag_set(tmp_path):
    _write_workload(tmp_path, "workload:payments", trust_domains=["prod.fsi"])
    result = query_shadow(tmp_path, agents=[
        {"workload_id": "workload:payments", "trust_domain": "prod.fsi"},
    ])
    assert result["scoped"] is True


# ---------------------------------------------------------------------------
# Legacy mode unchanged
# ---------------------------------------------------------------------------

def test_legacy_flat_diff_unchanged(tmp_path):
    _write_workload(tmp_path, "workload:payments")
    result = query_shadow(tmp_path, agent_workload_ids=["workload:payments", "workload:rogue"])
    assert result["shadow_agents"] == ["workload:rogue"]
    assert result["scoped"] is False
    assert result["trust_domain_mismatches"] == []


def test_legacy_ignores_trust_domains_on_workloads(tmp_path):
    # Flat diff matches on key alone even when trust_domains are declared.
    _write_workload(tmp_path, "workload:payments", trust_domains=["prod.fsi"])
    result = query_shadow(tmp_path, agent_workload_ids=["workload:payments"])
    assert result["shadow_agents"] == []


def test_scoped_mode_takes_precedence_over_legacy(tmp_path):
    _write_workload(tmp_path, "workload:payments", trust_domains=["prod.fsi"])
    result = query_shadow(
        tmp_path,
        agent_workload_ids=["workload:ignored"],
        agents=[{"workload_id": "workload:payments", "trust_domain": "prod.fsi"}],
    )
    assert result["scoped"] is True
    assert "workload:ignored" not in result["shadow_agents"]


# ---------------------------------------------------------------------------
# HTTP endpoint
# ---------------------------------------------------------------------------

def test_shadow_endpoint_scoped_request(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from calm_forge.api import app
    from calm_forge.kg_coherence_api import configure_coherence_kg_dir

    monkeypatch.delenv("CALM_FORGE_COHERENCE_AUTH", raising=False)
    _write_workload(tmp_path, "workload:payments", trust_domains=["prod.fsi"])
    configure_coherence_kg_dir(tmp_path)

    client = TestClient(app)
    resp = client.post("/graph/shadow", json={
        "agents": [
            {"workload_id": "workload:payments", "trust_domain": "prod.fsi"},
            {"workload_id": "workload:rogue", "trust_domain": "dev.fsi"},
        ],
    })
    assert resp.status_code == 200
    body = resp.json()
    assert body["scoped"] is True
    assert body["shadow_agents"] == ["workload:rogue"]


def test_shadow_endpoint_legacy_request_still_works(tmp_path, monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from calm_forge.api import app
    from calm_forge.kg_coherence_api import configure_coherence_kg_dir

    monkeypatch.delenv("CALM_FORGE_COHERENCE_AUTH", raising=False)
    _write_workload(tmp_path, "workload:payments")
    configure_coherence_kg_dir(tmp_path)

    client = TestClient(app)
    resp = client.post("/graph/shadow", json={"agent_workload_ids": ["workload:rogue"]})
    assert resp.status_code == 200
    body = resp.json()
    assert body["scoped"] is False
    assert body["shadow_agents"] == ["workload:rogue"]


# ---------------------------------------------------------------------------
# Kuzu — TrustDomain nodes and Workload.trust_domains
# ---------------------------------------------------------------------------

def test_kuzu_workload_trust_domains_roundtrip(tmp_path):
    pytest.importorskip("kuzu")
    from calm_forge.kg_kuzu_backend import KuzuBackend

    backend = KuzuBackend(db_path=tmp_path / "kg.db")
    backend.upsert_node({
        "@id": "workload:payments",
        "@type": "Workload",
        "declared_capabilities": ["http_read"],
        "trust_domains": ["trust_domain:prod.fsi", "trust_domain:dr.fsi"],
    })
    rows = backend.query(
        "MATCH (w:Workload {id: $id}) RETURN w.trust_domains AS tds",
        params={"id": "workload:payments"},
    )
    backend.close()
    assert rows[0]["tds"] == ["trust_domain:prod.fsi", "trust_domain:dr.fsi"]


def test_kuzu_trust_domain_node_roundtrip(tmp_path):
    pytest.importorskip("kuzu")
    from calm_forge.kg_kuzu_backend import KuzuBackend

    backend = KuzuBackend(db_path=tmp_path / "kg.db")
    backend.upsert_node({
        "@id": "trust_domain:prod.fsi",
        "@type": "TrustDomain",
        "spiffe_uri_prefix": "spiffe://prod.fsi",
        "commune": "forge",
        "peer_trust_domains": ["trust_domain:peer.prod"],
    })
    rows = backend.query(
        "MATCH (t:TrustDomain {id: $id}) "
        "RETURN t.spiffe_uri_prefix AS prefix, t.commune AS commune, "
        "       t.peer_trust_domains AS peers",
        params={"id": "trust_domain:prod.fsi"},
    )
    backend.close()
    assert rows[0]["prefix"] == "spiffe://prod.fsi"
    assert rows[0]["commune"] == "forge"
    assert rows[0]["peers"] == ["trust_domain:peer.prod"]


def test_kuzu_load_ingests_trust_domains_dir(tmp_path):
    pytest.importorskip("kuzu")
    from calm_forge.kg_kuzu_backend import KuzuBackend

    _write_trust_domain(tmp_path, "prod.fsi", peers=["trust_domain:peer.prod"])
    _write_workload(tmp_path, "workload:payments", trust_domains=["trust_domain:prod.fsi"])

    backend = KuzuBackend(db_path=tmp_path / "kg.db")
    backend.load(tmp_path)
    td_rows = backend.query("MATCH (t:TrustDomain) RETURN t.id AS id")
    wl_rows = backend.query(
        "MATCH (w:Workload {id: $id}) RETURN w.trust_domains AS tds",
        params={"id": "workload:payments"},
    )
    backend.close()
    assert td_rows == [{"id": "trust_domain:prod.fsi"}]
    assert wl_rows[0]["tds"] == ["trust_domain:prod.fsi"]
