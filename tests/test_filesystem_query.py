"""Tests for FilesystemBackend.query() — the flat Cypher subset.

Property names mirror the Kuzu/FalkorDB flattening so flat queries are
portable across backends; traversal raises NotImplementedError.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from calm_forge.kg_backend import FilesystemBackend

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _seed_kg(kg_dir: Path) -> None:
    (kg_dir / "workloads").mkdir(parents=True)
    (kg_dir / "placements").mkdir(parents=True)
    (kg_dir / "environments").mkdir(parents=True)

    (kg_dir / "workloads" / "payments.json").write_text(json.dumps({
        "@id": "workload:payments", "@type": "Workload",
        "declared_capabilities": ["http_read"],
        "trust_domains": ["trust_domain:prod.fsi"],
        "_provenance": {"provenance": "authored"},
    }))
    (kg_dir / "workloads" / "legacy.json").write_text(json.dumps({
        "@id": "workload:legacy", "@type": "Workload",
        "_provenance": {"provenance": "reconstructed"},
    }))
    (kg_dir / "placements" / "p1.json").write_text(json.dumps({
        "@id": "placement:payments:east", "@type": "Placement",
        "workload_id": "workload:payments", "region": "us-east-1",
        "drift_state": {"status": "ok", "deviation_hours": 0.0,
                        "last_evaluated": "2026-06-10T00:00:00Z"},
    }))
    (kg_dir / "placements" / "p2.json").write_text(json.dumps({
        "@id": "placement:payments:west", "@type": "Placement",
        "workload_id": "workload:payments", "region": "eu-west-1",
        "drift_state": {"status": "violation", "deviation_hours": 2.5},
    }))
    (kg_dir / "environments" / "e1.json").write_text(json.dumps({
        "@id": "env:prod-east", "@type": "ExecutionEnvironment",
        "region": "us-east-1", "labels": {"compliance": "pci"},
    }))


@pytest.fixture
def backend(tmp_path):
    _seed_kg(tmp_path)
    return FilesystemBackend(kg_dir=tmp_path)


# ---------------------------------------------------------------------------
# Supported subset
# ---------------------------------------------------------------------------

def test_match_all_with_projection(backend):
    rows = backend.query("MATCH (w:Workload) RETURN w.id AS id")
    assert sorted(r["id"] for r in rows) == ["workload:legacy", "workload:payments"]


def test_inline_property_filter(backend):
    rows = backend.query(
        "MATCH (p:Placement {workload_id: $wid}) RETURN p.id AS id",
        params={"wid": "workload:payments"},
    )
    assert len(rows) == 2


def test_where_clause_filter(backend):
    rows = backend.query(
        "MATCH (p:Placement) WHERE p.drift_state_status = $s RETURN p.id AS id",
        params={"s": "violation"},
    )
    assert rows == [{"id": "placement:payments:west"}]


def test_where_and_combination(backend):
    rows = backend.query(
        "MATCH (p:Placement) WHERE p.workload_id = $wid AND p.region = $r RETURN p.id AS id",
        params={"wid": "workload:payments", "r": "us-east-1"},
    )
    assert rows == [{"id": "placement:payments:east"}]


def test_multiple_return_items(backend):
    rows = backend.query(
        "MATCH (p:Placement {id: $pid}) RETURN p.region AS region, p.drift_state_status AS status",
        params={"pid": "placement:payments:east"},
    )
    assert rows == [{"region": "us-east-1", "status": "ok"}]


def test_return_without_alias_uses_qualified_name(backend):
    rows = backend.query(
        "MATCH (p:Placement {id: $pid}) RETURN p.region",
        params={"pid": "placement:payments:east"},
    )
    assert rows == [{"p.region": "us-east-1"}]


def test_count_projection(backend):
    rows = backend.query("MATCH (p:Placement) RETURN count(p) AS n")
    assert rows == [{"n": 2}]


def test_kuzu_compatible_drift_query_runs_on_filesystem(backend):
    # The exact query used in drift write-back tests against KuzuBackend.
    rows = backend.query(
        "MATCH (p:Placement) WHERE p.workload_id = $wid RETURN p.drift_state_status AS status",
        params={"wid": "workload:payments"},
    )
    assert sorted(r["status"] for r in rows) == ["ok", "violation"]


# ---------------------------------------------------------------------------
# Property flattening parity
# ---------------------------------------------------------------------------

def test_provenance_flattened_from_metadata(backend):
    rows = backend.query(
        "MATCH (w:Workload) WHERE w.provenance = $p RETURN w.id AS id",
        params={"p": "reconstructed"},
    )
    assert rows == [{"id": "workload:legacy"}]


def test_trust_domains_property(backend):
    rows = backend.query(
        "MATCH (w:Workload {id: $id}) RETURN w.trust_domains AS tds",
        params={"id": "workload:payments"},
    )
    assert rows == [{"tds": ["trust_domain:prod.fsi"]}]


def test_drift_deviation_hours_flattened(backend):
    rows = backend.query(
        "MATCH (p:Placement {id: $pid}) RETURN p.drift_state_deviation_hours AS dev",
        params={"pid": "placement:payments:west"},
    )
    assert rows == [{"dev": 2.5}]


def test_last_evaluated_flattened_from_drift_state(backend):
    rows = backend.query(
        "MATCH (p:Placement {id: $pid}) RETURN p.last_evaluated AS ts",
        params={"pid": "placement:payments:east"},
    )
    assert rows == [{"ts": "2026-06-10T00:00:00Z"}]


def test_labels_compliance_flattened(backend):
    rows = backend.query(
        "MATCH (e:ExecutionEnvironment {id: $id}) RETURN e.labels_compliance AS lc",
        params={"id": "env:prod-east"},
    )
    assert rows == [{"lc": ["pci"]}]


# ---------------------------------------------------------------------------
# Unsupported syntax fails loudly
# ---------------------------------------------------------------------------

def test_relationship_traversal_unsupported(backend):
    with pytest.raises(NotImplementedError, match="kuzu"):
        backend.query(
            "MATCH (p:Placement)-[:PLACED_ON]->(e:ExecutionEnvironment) RETURN p.id"
        )


def test_unknown_label_unsupported(backend):
    with pytest.raises(NotImplementedError):
        backend.query("MATCH (a:Agent) RETURN a.id")


def test_garbage_query_unsupported(backend):
    with pytest.raises(NotImplementedError):
        backend.query("CREATE (n:Workload {id: 'x'})")


def test_inequality_where_unsupported(backend):
    with pytest.raises(NotImplementedError):
        backend.query(
            "MATCH (p:Placement) WHERE p.drift_state_deviation_hours > $h RETURN p.id",
            params={"h": 1.0},
        )


def test_missing_param_raises_value_error(backend):
    with pytest.raises(ValueError, match=r"\$wid"):
        backend.query("MATCH (p:Placement {workload_id: $wid}) RETURN p.id")


# ---------------------------------------------------------------------------
# Cross-backend parity (when kuzu installed)
# ---------------------------------------------------------------------------

def test_flat_query_parity_with_kuzu(tmp_path):
    pytest.importorskip("kuzu")
    from calm_forge.kg_kuzu_backend import KuzuBackend

    _seed_kg(tmp_path)
    fs = FilesystemBackend(kg_dir=tmp_path)
    kz = KuzuBackend(db_path=tmp_path / "kg.db")
    kz.load(tmp_path)

    q = "MATCH (p:Placement) WHERE p.workload_id = $wid RETURN p.id AS id, p.drift_state_status AS status"
    params = {"wid": "workload:payments"}

    fs_rows = sorted(fs.query(q, params=params), key=lambda r: r["id"])
    kz_rows = sorted(kz.query(q, params=params), key=lambda r: r["id"])
    kz.close()

    assert fs_rows == kz_rows
