"""Tests for KuzuBackend — schema, upsert, load, invariant, canonical queries."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("kuzu", reason="kuzu not installed; run: pip install calm-forge[graph]")

from calm_forge.kg_kuzu_backend import KGInvariantViolation, KuzuBackend, _list

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db(tmp_path):
    backend = KuzuBackend(db_path=tmp_path / "test.db")
    yield backend
    backend.close()


@pytest.fixture
def kg_dir(tmp_path):
    root = tmp_path / "kg"
    for subdir in ("workloads", "environments", "placements", "policies"):
        (root / subdir).mkdir(parents=True)
    return root


def _write(directory: Path, filename: str, node: dict) -> None:
    (directory / filename).write_text(json.dumps(node))


def _workload(kg_dir: Path, wid: str, caps: list, scope: list | None = None,
              provenance: str = "authored") -> None:
    _write(kg_dir / "workloads", f"{wid.replace(':', '_')}.json", {
        "@type": "Workload", "@id": wid,
        "declared_capabilities": caps,
        "compliance_scope": scope or [],
        "_provenance": {"provenance": provenance},
    })


def _environment(kg_dir: Path, eid: str, caps: list, compliance: str = "",
                 status: str = "ready", repave: bool = True) -> None:
    labels = {"compliance": compliance} if compliance else {}
    _write(kg_dir / "environments", f"{eid.replace(':', '_')}.json", {
        "@type": "ExecutionEnvironment", "@id": eid,
        "region": "us-east-1", "status": status,
        "advertised_capabilities": caps,
        "labels": labels,
        "repave_friendly": repave,
    })


def _placement(kg_dir: Path, pid: str, wid: str, eid: str, caps: list,
               drift_status: str = "ok", deviation_hours: float | None = None) -> None:
    _write(kg_dir / "placements", f"{pid.replace(':', '_')}.json", {
        "@type": "Placement", "@id": pid,
        "workload_id": wid, "environment_id": eid,
        "region": "us-east-1",
        "observed_capabilities": caps,
        "edges": [{
            "@type": "manifests_as", "from": wid, "to": pid,
            "capabilities_granted": caps, "manifested_at": "2026-06-07T00:00:00Z",
            "attestation_level": "software",
        }],
        "drift_state": {
            "status": drift_status,
            "deviation_hours": deviation_hours,
            "last_evaluated": "2026-06-07T00:00:00Z",
        },
    })


# ---------------------------------------------------------------------------
# Schema / init
# ---------------------------------------------------------------------------

def test_backend_creates_database_file(tmp_path):
    backend = KuzuBackend(db_path=tmp_path / "sub" / "kg.db")
    backend.close()
    assert (tmp_path / "sub" / "kg.db").exists()


def test_backend_schema_idempotent(tmp_path):
    b1 = KuzuBackend(db_path=tmp_path / "kg.db")
    b1.close()
    b2 = KuzuBackend(db_path=tmp_path / "kg.db")
    b2.close()


# ---------------------------------------------------------------------------
# upsert_node — Workload
# ---------------------------------------------------------------------------

def test_upsert_workload_roundtrip(db):
    db.upsert_node({"@type": "Workload", "@id": "workload:payments",
                    "declared_capabilities": ["http_read", "vault_dynamic_creds"],
                    "compliance_scope": ["pci"],
                    "_provenance": {"provenance": "authored"}})
    rows = db.query("MATCH (w:Workload {id: 'workload:payments'}) RETURN w.id, w.declared_capabilities, w.compliance_scope")
    assert len(rows) == 1
    assert rows[0]["w.id"] == "workload:payments"
    assert "http_read" in rows[0]["w.declared_capabilities"]
    assert "pci" in rows[0]["w.compliance_scope"]


def test_upsert_workload_idempotent(db):
    node = {"@type": "Workload", "@id": "workload:payments",
            "declared_capabilities": ["http_read"],
            "_provenance": {"provenance": "authored"}}
    db.upsert_node(node)
    db.upsert_node(node)
    rows = db.query("MATCH (w:Workload) RETURN count(w) AS c")
    assert rows[0]["c"] == 1


def test_upsert_workload_update_capabilities(db):
    db.upsert_node({"@type": "Workload", "@id": "workload:payments",
                    "declared_capabilities": ["http_read"],
                    "_provenance": {"provenance": "authored"}})
    db.upsert_node({"@type": "Workload", "@id": "workload:payments",
                    "declared_capabilities": ["http_read", "vault_dynamic_creds"],
                    "_provenance": {"provenance": "authored"}})
    rows = db.query("MATCH (w:Workload {id: 'workload:payments'}) RETURN w.declared_capabilities")
    assert "vault_dynamic_creds" in rows[0]["w.declared_capabilities"]


# ---------------------------------------------------------------------------
# upsert_node — ExecutionEnvironment
# ---------------------------------------------------------------------------

def test_upsert_environment_extracts_compliance_label(db):
    db.upsert_node({"@type": "ExecutionEnvironment", "@id": "env:prod-east-1",
                    "region": "us-east-1", "status": "ready",
                    "advertised_capabilities": ["http_read"],
                    "labels": {"compliance": "pci"}})
    rows = db.query("MATCH (e:ExecutionEnvironment {id: 'env:prod-east-1'}) RETURN e.labels_compliance")
    assert rows[0]["e.labels_compliance"] == ["pci"]


def test_upsert_environment_no_compliance_label(db):
    db.upsert_node({"@type": "ExecutionEnvironment", "@id": "env:non-pci",
                    "region": "us-east-1", "status": "ready",
                    "advertised_capabilities": [], "labels": {}})
    rows = db.query("MATCH (e:ExecutionEnvironment {id: 'env:non-pci'}) RETURN e.labels_compliance")
    assert rows[0]["e.labels_compliance"] == []


# ---------------------------------------------------------------------------
# upsert_node — Placement + edges
# ---------------------------------------------------------------------------

def test_upsert_placement_creates_manifests_as_edge(db):
    db.upsert_node({"@type": "Workload", "@id": "workload:payments",
                    "declared_capabilities": ["http_read"],
                    "_provenance": {"provenance": "authored"}})
    db.upsert_node({"@type": "ExecutionEnvironment", "@id": "env:prod",
                    "region": "us-east-1", "status": "ready",
                    "advertised_capabilities": ["http_read"], "labels": {}})
    db.upsert_node({"@type": "Placement", "@id": "placement:payments:prod",
                    "workload_id": "workload:payments", "environment_id": "env:prod",
                    "region": "us-east-1", "observed_capabilities": ["http_read"],
                    "edges": [{"@type": "manifests_as", "from": "workload:payments",
                               "to": "placement:payments:prod",
                               "capabilities_granted": ["http_read"],
                               "manifested_at": "2026-06-07T00:00:00Z",
                               "attestation_level": "software"}],
                    "drift_state": {"status": "ok", "deviation_hours": None,
                                    "last_evaluated": "2026-06-07T00:00:00Z"}})
    rows = db.query("MATCH (w:Workload)-[r:MANIFESTS_AS]->(p:Placement) RETURN w.id, p.id, r.capabilities_granted")
    assert len(rows) == 1
    assert "http_read" in rows[0]["r.capabilities_granted"]


def test_upsert_placement_creates_placed_on_edge(db):
    db.upsert_node({"@type": "ExecutionEnvironment", "@id": "env:prod",
                    "region": "us-east-1", "status": "ready",
                    "advertised_capabilities": [], "labels": {}})
    db.upsert_node({"@type": "Placement", "@id": "placement:payments:prod",
                    "workload_id": "workload:payments", "environment_id": "env:prod",
                    "region": "us-east-1", "observed_capabilities": [],
                    "edges": [],
                    "drift_state": {"status": "ok", "deviation_hours": None,
                                    "last_evaluated": "2026-06-07T00:00:00Z"}})
    rows = db.query("MATCH (p:Placement)-[:PLACED_ON]->(e:ExecutionEnvironment) RETURN p.id, e.id")
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# Invariant enforcement
# ---------------------------------------------------------------------------

def test_load_raises_on_capabilities_granted_exceeding_declared(tmp_path, kg_dir):
    _workload(kg_dir, "workload:payments", caps=["http_read"])
    _environment(kg_dir, "env:prod", caps=["http_read", "vault_dynamic_creds"], compliance="pci")
    # Placement grants vault_dynamic_creds but workload only declares http_read
    _placement(kg_dir, "placement:payments:prod", "workload:payments", "env:prod",
               caps=["http_read", "vault_dynamic_creds"])

    backend = KuzuBackend(db_path=tmp_path / "kg.db")
    with pytest.raises(KGInvariantViolation, match="vault_dynamic_creds"):
        backend.load(kg_dir)
    backend.close()


def test_load_invariant_skipped_for_reconstructed_workloads(tmp_path, kg_dir):
    _workload(kg_dir, "workload:legacy", caps=[], provenance="reconstructed")
    _environment(kg_dir, "env:prod", caps=["http_read"])
    _placement(kg_dir, "placement:legacy:prod", "workload:legacy", "env:prod",
               caps=["http_read", "vault_dynamic_creds"])

    backend = KuzuBackend(db_path=tmp_path / "kg.db")
    backend.load(kg_dir)  # should not raise
    backend.close()


def test_load_passes_when_granted_subset_of_declared(tmp_path, kg_dir):
    _workload(kg_dir, "workload:payments", caps=["http_read", "vault_dynamic_creds"])
    _environment(kg_dir, "env:prod", caps=["http_read", "vault_dynamic_creds"])
    _placement(kg_dir, "placement:payments:prod", "workload:payments", "env:prod",
               caps=["http_read"])

    backend = KuzuBackend(db_path=tmp_path / "kg.db")
    backend.load(kg_dir)
    backend.close()


# ---------------------------------------------------------------------------
# Canonical query 1 — blast radius
# ---------------------------------------------------------------------------

def test_query_blast_radius(tmp_path, kg_dir):
    _workload(kg_dir, "workload:payments", caps=["vault_dynamic_creds"])
    _environment(kg_dir, "env:prod", caps=["vault_dynamic_creds"], compliance="pci")
    _placement(kg_dir, "placement:payments:prod", "workload:payments", "env:prod",
               caps=["vault_dynamic_creds"], drift_status="violation")

    backend = KuzuBackend(db_path=tmp_path / "kg.db")
    backend.load(kg_dir)

    rows = backend.query("""
        MATCH (p:Placement)-[:PLACED_ON]->(e:ExecutionEnvironment)
        WHERE $cap IN p.observed_capabilities AND 'pci' IN e.labels_compliance
        RETURN p.id AS placement_id, p.workload_id AS workload,
               e.id AS environment_id, e.status AS env_status,
               p.drift_state_status AS drift_status
        ORDER BY e.status DESC
    """, params={"cap": "vault_dynamic_creds"})
    backend.close()

    assert len(rows) == 1
    assert rows[0]["placement_id"] == "placement:payments:prod"
    assert rows[0]["drift_status"] == "violation"


# ---------------------------------------------------------------------------
# Canonical query 2 — repave candidates
# ---------------------------------------------------------------------------

def test_query_repave_candidates(tmp_path, kg_dir):
    _workload(kg_dir, "workload:payments", caps=["http_read"])
    _environment(kg_dir, "env:prod", caps=["http_read"], repave=True)
    _placement(kg_dir, "placement:payments:prod", "workload:payments", "env:prod",
               caps=["http_read"], drift_status="violation", deviation_hours=3.0)

    backend = KuzuBackend(db_path=tmp_path / "kg.db")
    backend.load(kg_dir)

    rows = backend.query("""
        MATCH (p:Placement)-[:PLACED_ON]->(e:ExecutionEnvironment)
        WHERE p.drift_state_status = 'violation'
          AND e.repave_friendly = true
          AND e.status = 'ready'
        RETURN p.id AS placement_id, p.workload_id AS workload,
               p.drift_state_deviation_hours AS hours_in_violation
        ORDER BY p.drift_state_deviation_hours DESC
    """)
    backend.close()

    assert len(rows) == 1
    assert rows[0]["placement_id"] == "placement:payments:prod"
    assert rows[0]["hours_in_violation"] == pytest.approx(3.0)


def test_query_repave_excludes_non_repave_friendly(tmp_path, kg_dir):
    _workload(kg_dir, "workload:payments", caps=["http_read"])
    _environment(kg_dir, "env:prod", caps=["http_read"], repave=False)
    _placement(kg_dir, "placement:payments:prod", "workload:payments", "env:prod",
               caps=["http_read"], drift_status="violation")

    backend = KuzuBackend(db_path=tmp_path / "kg.db")
    backend.load(kg_dir)

    rows = backend.query("""
        MATCH (p:Placement)-[:PLACED_ON]->(e:ExecutionEnvironment)
        WHERE p.drift_state_status = 'violation' AND e.repave_friendly = true AND e.status = 'ready'
        RETURN p.id
    """)
    backend.close()

    assert rows == []


# ---------------------------------------------------------------------------
# Canonical query 3 — 3-hop resilience gap
# ---------------------------------------------------------------------------

def test_query_resilience_gap_three_hop(tmp_path, kg_dir):
    _workload(kg_dir, "workload:regulated", caps=["http_read"], scope=["regulated"])
    _environment(kg_dir, "env:prod", caps=["http_read", "resilience"])
    # Placement observed_capabilities missing 'resilience'
    _placement(kg_dir, "placement:regulated:prod", "workload:regulated", "env:prod",
               caps=["http_read"])

    backend = KuzuBackend(db_path=tmp_path / "kg.db")
    backend.load(kg_dir)

    rows = backend.query("""
        MATCH (w:Workload)-[:MANIFESTS_AS]->(p:Placement)-[:PLACED_ON]->(e:ExecutionEnvironment)
        WHERE 'regulated' IN w.compliance_scope
          AND NOT 'resilience' IN p.observed_capabilities
        RETURN w.id AS workload_id, p.id AS placement_id, e.id AS environment_id
    """)
    backend.close()

    assert len(rows) == 1
    assert rows[0]["workload_id"] == "workload:regulated"


def test_query_resilience_gap_excludes_compliant_placements(tmp_path, kg_dir):
    _workload(kg_dir, "workload:regulated", caps=["http_read", "resilience"], scope=["regulated"])
    _environment(kg_dir, "env:prod", caps=["http_read", "resilience"])
    _placement(kg_dir, "placement:regulated:prod", "workload:regulated", "env:prod",
               caps=["http_read", "resilience"])  # has resilience

    backend = KuzuBackend(db_path=tmp_path / "kg.db")
    backend.load(kg_dir)

    rows = backend.query("""
        MATCH (w:Workload)-[:MANIFESTS_AS]->(p:Placement)-[:PLACED_ON]->(e:ExecutionEnvironment)
        WHERE 'regulated' IN w.compliance_scope AND NOT 'resilience' IN p.observed_capabilities
        RETURN w.id
    """)
    backend.close()

    assert rows == []


# ---------------------------------------------------------------------------
# load — idempotency
# ---------------------------------------------------------------------------

def test_load_idempotent(tmp_path, kg_dir):
    _workload(kg_dir, "workload:payments", caps=["http_read"])
    _environment(kg_dir, "env:prod", caps=["http_read"])
    _placement(kg_dir, "placement:payments:prod", "workload:payments", "env:prod",
               caps=["http_read"])

    backend = KuzuBackend(db_path=tmp_path / "kg.db")
    backend.load(kg_dir)
    backend.load(kg_dir)  # second load must not duplicate

    rows = backend.query("MATCH (w:Workload) RETURN count(w) AS c")
    assert rows[0]["c"] == 1

    rows = backend.query("MATCH (p:Placement) RETURN count(p) AS c")
    assert rows[0]["c"] == 1
    backend.close()


# ---------------------------------------------------------------------------
# load — empty directories
# ---------------------------------------------------------------------------

def test_load_empty_kg_dir(tmp_path, kg_dir):
    backend = KuzuBackend(db_path=tmp_path / "kg.db")
    backend.load(kg_dir)  # no files — must not raise
    rows = backend.query("MATCH (w:Workload) RETURN count(w) AS c")
    assert rows[0]["c"] == 0
    backend.close()


def test_load_missing_subdirs_tolerated(tmp_path):
    empty = tmp_path / "empty_kg"
    empty.mkdir()
    backend = KuzuBackend(db_path=tmp_path / "kg.db")
    backend.load(empty)
    backend.close()


# ---------------------------------------------------------------------------
# _list helper
# ---------------------------------------------------------------------------

def test_list_helper_passthrough():
    assert _list(["a", "b"]) == ["a", "b"]


def test_list_helper_none_returns_empty():
    assert _list(None) == []


def test_list_helper_scalar_wraps():
    assert _list("x") == ["x"]
