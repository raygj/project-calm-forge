"""Tests for Phase 3 — drift engine write-back to KGBackend.

Uses a RecordingBackend stub so these tests don't require Kuzu.
Kuzu-integrated write-back is covered in test_kg_kuzu_backend.py.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from calm_forge.drift_evaluator import (
    _try_get_backend,
    drift_check_post_deploy,
    evaluate_drift,
    write_drift_state,
)
from calm_forge.intake import (
    intake_acm,
    intake_ansible,
    write_environment_nodes,
    write_placement_nodes,
)

# ---------------------------------------------------------------------------
# Stub backend
# ---------------------------------------------------------------------------

class RecordingBackend:
    """Captures upsert_node calls without touching any database."""

    def __init__(self):
        self.upserted: list[dict] = []
        self.closed = False

    def load(self, kg_dir: str) -> None:
        pass

    def query(self, cypher: str, params: dict | None = None) -> list[dict[str, Any]]:
        return []

    def upsert_node(self, node: dict) -> None:
        self.upserted.append(node)

    def upsert_edge(self, edge: dict) -> None:
        pass

    def close(self) -> None:
        self.closed = True


# ---------------------------------------------------------------------------
# KG fixture helpers
# ---------------------------------------------------------------------------

_ACM = {"clusters": [
    {"name": "prod-east", "region": "us-east-1", "status": "ready",
     "substrate": "x86", "labels": {"compliance": "pci"}, "capabilities": ["http_read"]},
]}
_AAP = {"jobs": [
    {"id": "j1", "workload_name": "payments", "target_cluster": "prod-east",
     "namespace": "payments", "region": "us-east-1", "finished": "2026-06-07T00:00:00Z",
     "observed_capabilities": ["http_read"]},
]}
_CALM = {
    "title": "payments",
    "metadata": {"name": "payments", "data": {"data-residency": ["us-east-1"]}},
    "nodes": [], "relationships": [],
}


def _build_kg(tmp_path: Path) -> Path:
    env_nodes = intake_acm(_ACM)
    write_environment_nodes(env_nodes, tmp_path)
    placement_nodes = intake_ansible(_AAP, env_nodes)
    write_placement_nodes(placement_nodes, tmp_path)
    return tmp_path


# ---------------------------------------------------------------------------
# write_drift_state — backend integration
# ---------------------------------------------------------------------------

def test_write_drift_state_calls_upsert_node_for_each_written_placement(tmp_path):
    _build_kg(tmp_path)
    result = evaluate_drift(_CALM, tmp_path)
    backend = RecordingBackend()
    written = write_drift_state(result, tmp_path, backend=backend)
    assert len(backend.upserted) == len(written)


def test_write_drift_state_upserted_nodes_are_placement_type(tmp_path):
    _build_kg(tmp_path)
    result = evaluate_drift(_CALM, tmp_path)
    backend = RecordingBackend()
    write_drift_state(result, tmp_path, backend=backend)
    for node in backend.upserted:
        assert node.get("@type") == "Placement"


def test_write_drift_state_upserted_node_has_updated_drift_state(tmp_path):
    _build_kg(tmp_path)
    result = evaluate_drift(_CALM, tmp_path)
    backend = RecordingBackend()
    write_drift_state(result, tmp_path, backend=backend)
    for node in backend.upserted:
        assert node["drift_state"]["last_evaluated"] is not None
        assert node["drift_state"]["status"] in ("ok", "violation")


def test_write_drift_state_file_and_backend_agree_on_status(tmp_path):
    _build_kg(tmp_path)
    result = evaluate_drift(_CALM, tmp_path)
    backend = RecordingBackend()
    written = write_drift_state(result, tmp_path, backend=backend)
    for path, node in zip(written, backend.upserted):
        file_node = json.loads(path.read_text())
        assert file_node["drift_state"]["status"] == node["drift_state"]["status"]


def test_write_drift_state_without_backend_still_works(tmp_path):
    _build_kg(tmp_path)
    result = evaluate_drift(_CALM, tmp_path)
    written = write_drift_state(result, tmp_path)  # backend=None default
    assert len(written) >= 1


def test_write_drift_state_backend_not_closed_by_function(tmp_path):
    _build_kg(tmp_path)
    result = evaluate_drift(_CALM, tmp_path)
    backend = RecordingBackend()
    write_drift_state(result, tmp_path, backend=backend)
    assert not backend.closed  # caller owns lifecycle


# ---------------------------------------------------------------------------
# drift_check_post_deploy — backend integration
# ---------------------------------------------------------------------------

def _write_workload(tmp_path: Path) -> dict:
    node = {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "Workload",
        "@id": "workload:payments",
        "declared_capabilities": ["http_read"],
        "metadata": {"name": "payments", "data": {"data-residency": ["us-east-1"]}},
        "nodes": [], "relationships": [],
        "_provenance": {"provenance": "authored"},
    }
    (tmp_path / "workloads").mkdir(parents=True, exist_ok=True)
    (tmp_path / "workloads" / "payments.json").write_text(json.dumps(node))
    return node


def test_drift_check_post_deploy_passes_backend_to_write_drift_state(tmp_path):
    _build_kg(tmp_path)
    _write_workload(tmp_path)
    status_node = {"@id": "deploy:001", "workload_id": "workload:payments"}
    backend = RecordingBackend()
    drift_check_post_deploy(status_node, tmp_path, backend=backend)
    assert len(backend.upserted) >= 1
    assert all(n.get("@type") == "Placement" for n in backend.upserted)


def test_drift_check_post_deploy_without_backend_unchanged(tmp_path):
    _build_kg(tmp_path)
    _write_workload(tmp_path)
    status_node = {"@id": "deploy:001", "workload_id": "workload:payments"}
    result = drift_check_post_deploy(status_node, tmp_path)
    assert "status" in result


# ---------------------------------------------------------------------------
# _try_get_backend
# ---------------------------------------------------------------------------

def test_try_get_backend_returns_none_when_no_env_var(tmp_path):
    with patch.dict(os.environ, {}, clear=False):
        os.environ.pop("CALM_FORGE_KG_BACKEND", None)
        assert _try_get_backend(tmp_path) is None


def test_try_get_backend_returns_none_for_filesystem(tmp_path):
    with patch.dict(os.environ, {"CALM_FORGE_KG_BACKEND": "filesystem"}):
        assert _try_get_backend(tmp_path) is None


def test_try_get_backend_returns_none_for_unknown_type(tmp_path, capsys):
    with patch.dict(os.environ, {"CALM_FORGE_KG_BACKEND": "nonexistent"}):
        result = _try_get_backend(tmp_path)
    assert result is None
    assert "WARNING" in capsys.readouterr().err


def test_try_get_backend_kuzu_returns_backend_when_installed(tmp_path):
    pytest.importorskip("kuzu")
    db_path = str(tmp_path / "test.db")
    with patch.dict(os.environ, {
        "CALM_FORGE_KG_BACKEND": "kuzu",
        "CALM_FORGE_KG_DB_PATH": db_path,
    }):
        backend = _try_get_backend(tmp_path)
    assert backend is not None
    backend.close()


def test_try_get_backend_kuzu_uses_default_path_when_no_db_path_env(tmp_path):
    pytest.importorskip("kuzu")
    with patch.dict(os.environ, {"CALM_FORGE_KG_BACKEND": "kuzu"}):
        os.environ.pop("CALM_FORGE_KG_DB_PATH", None)
        backend = _try_get_backend(tmp_path)
    assert backend is not None
    assert (tmp_path / ".calm_forge" / "kg.db").exists()
    backend.close()


# ---------------------------------------------------------------------------
# End-to-end: write_drift_state + KuzuBackend
# ---------------------------------------------------------------------------

def test_drift_writeback_syncs_drift_status_to_kuzu(tmp_path):
    pytest.importorskip("kuzu")
    from calm_forge.kg_kuzu_backend import KuzuBackend

    _build_kg(tmp_path)
    env_nodes = intake_acm(_ACM)
    placement_nodes = intake_ansible(_AAP, env_nodes)

    db_path = tmp_path / "kg.db"
    backend = KuzuBackend(db_path=db_path)
    for env in env_nodes:
        backend.upsert_node(env)
    for p in placement_nodes:
        backend.upsert_node(p)

    result = evaluate_drift(_CALM, tmp_path)
    write_drift_state(result, tmp_path, backend=backend)

    rows = backend.query(
        "MATCH (p:Placement) WHERE p.workload_id = $wid RETURN p.drift_state_status AS status",
        params={"wid": "workload:payments"},
    )
    backend.close()

    assert len(rows) >= 1
    assert all(r["status"] in ("ok", "violation") for r in rows)


def test_drift_writeback_status_matches_file(tmp_path):
    pytest.importorskip("kuzu")
    from calm_forge.kg_kuzu_backend import KuzuBackend

    _build_kg(tmp_path)
    env_nodes = intake_acm(_ACM)
    placement_nodes = intake_ansible(_AAP, env_nodes)

    db_path = tmp_path / "kg.db"
    backend = KuzuBackend(db_path=db_path)
    for env in env_nodes:
        backend.upsert_node(env)
    for p in placement_nodes:
        backend.upsert_node(p)

    result = evaluate_drift(_CALM, tmp_path)
    written = write_drift_state(result, tmp_path, backend=backend)

    for path in written:
        file_node = json.loads(path.read_text())
        file_status = file_node["drift_state"]["status"]
        rows = backend.query(
            "MATCH (p:Placement {id: $pid}) RETURN p.drift_state_status AS status",
            params={"pid": file_node["@id"]},
        )
        assert rows[0]["status"] == file_status

    backend.close()
