"""Tests for P5-002 — KG Bootstrap from intake sources."""
from __future__ import annotations

import json
from pathlib import Path

from calm_forge.kg_bootstrap import (
    BootstrapConfig,
    BootstrapResult,
    kg_bootstrap,
    load_bootstrap_history,
)

# ---------------------------------------------------------------------------
# Fixture data
# ---------------------------------------------------------------------------

_ACM_FIXTURE = {
    "clusters": [
        {
            "name": "prod-us-east-1",
            "region": "us-east-1",
            "status": "ready",
            "advertised_capabilities": ["confidential_compute"],
        }
    ]
}

_ANSIBLE_FIXTURE = {
    "jobs": [
        {
            "id": "job-001",
            "workload": "fraud-detection-pipeline",
            "cluster": "prod-us-east-1",
            "status": "successful",
            "region": "us-east-1",
            "launched_at": "2026-05-09T00:00:00Z",
        }
    ]
}

_CONCERT_FIXTURE = {
    "applications": [
        {
            "name": "fraud-detection-pipeline",
            "risk_score": 0.4,
            "risk_level": "medium",
            "blocked_environments": [],
            "allowed_environments": [],
            "evaluated_at": "2026-05-09T00:00:00Z",
        }
    ]
}


def _write_fixture(tmp_path: Path, name: str, data: dict) -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(data))
    return p


# ---------------------------------------------------------------------------
# BootstrapConfig / BootstrapResult
# ---------------------------------------------------------------------------

def test_bootstrap_result_to_dict():
    r = BootstrapResult(["acm"], {"acm": 2}, {})
    d = r.to_dict()
    assert d["total_nodes"] == 2
    assert d["sources_run"] == ["acm"]


def test_bootstrap_result_total_nodes_sum():
    r = BootstrapResult(["acm", "ansible"], {"acm": 2, "ansible": 3}, {})
    assert r.to_dict()["total_nodes"] == 5


def test_bootstrap_config_defaults():
    cfg = BootstrapConfig(kg_dir=Path("/tmp/kg"))
    assert cfg.sources == []
    assert cfg.concert_live is False


# ---------------------------------------------------------------------------
# kg_bootstrap — ACM only
# ---------------------------------------------------------------------------

def test_bootstrap_acm_writes_environment_nodes(tmp_path):
    fixture = _write_fixture(tmp_path, "acm.json", _ACM_FIXTURE)
    cfg = BootstrapConfig(kg_dir=tmp_path / "kg", sources=["acm"], acm_fixture_path=fixture)
    result = kg_bootstrap(cfg)
    assert result.nodes_written.get("acm", 0) == 1


def test_bootstrap_acm_sources_run(tmp_path):
    fixture = _write_fixture(tmp_path, "acm.json", _ACM_FIXTURE)
    cfg = BootstrapConfig(kg_dir=tmp_path / "kg", sources=["acm"], acm_fixture_path=fixture)
    result = kg_bootstrap(cfg)
    assert "acm" in result.sources_run


def test_bootstrap_acm_creates_kg_dir(tmp_path):
    fixture = _write_fixture(tmp_path, "acm.json", _ACM_FIXTURE)
    target = tmp_path / "kg"
    cfg = BootstrapConfig(kg_dir=target, sources=["acm"], acm_fixture_path=fixture)
    kg_bootstrap(cfg)
    assert target.is_dir()


def test_bootstrap_acm_env_file_exists(tmp_path):
    fixture = _write_fixture(tmp_path, "acm.json", _ACM_FIXTURE)
    cfg = BootstrapConfig(kg_dir=tmp_path / "kg", sources=["acm"], acm_fixture_path=fixture)
    kg_bootstrap(cfg)
    env_files = list((tmp_path / "kg" / "environments").glob("*.json"))
    assert len(env_files) == 1


# ---------------------------------------------------------------------------
# kg_bootstrap — Ansible only
# ---------------------------------------------------------------------------

def test_bootstrap_ansible_writes_placement_nodes(tmp_path):
    fixture = _write_fixture(tmp_path, "aap.json", _ANSIBLE_FIXTURE)
    cfg = BootstrapConfig(kg_dir=tmp_path / "kg", sources=["ansible"], ansible_fixture_path=fixture)
    result = kg_bootstrap(cfg)
    assert result.nodes_written.get("ansible", 0) == 1


def test_bootstrap_ansible_placement_file_exists(tmp_path):
    fixture = _write_fixture(tmp_path, "aap.json", _ANSIBLE_FIXTURE)
    cfg = BootstrapConfig(kg_dir=tmp_path / "kg", sources=["ansible"], ansible_fixture_path=fixture)
    kg_bootstrap(cfg)
    placement_files = list((tmp_path / "kg" / "placements").glob("*.json"))
    assert len(placement_files) == 1


# ---------------------------------------------------------------------------
# kg_bootstrap — Concert only
# ---------------------------------------------------------------------------

def test_bootstrap_concert_writes_policy_nodes(tmp_path):
    fixture = _write_fixture(tmp_path, "concert.json", _CONCERT_FIXTURE)
    cfg = BootstrapConfig(kg_dir=tmp_path / "kg", sources=["concert"], concert_fixture_path=fixture)
    result = kg_bootstrap(cfg)
    assert result.nodes_written.get("concert", 0) == 1


def test_bootstrap_concert_sources_run(tmp_path):
    fixture = _write_fixture(tmp_path, "concert.json", _CONCERT_FIXTURE)
    cfg = BootstrapConfig(kg_dir=tmp_path / "kg", sources=["concert"], concert_fixture_path=fixture)
    result = kg_bootstrap(cfg)
    assert "concert" in result.sources_run


# ---------------------------------------------------------------------------
# kg_bootstrap — all three sources
# ---------------------------------------------------------------------------

def test_bootstrap_all_sources_writes_all_nodes(tmp_path):
    acm_f = _write_fixture(tmp_path, "acm.json", _ACM_FIXTURE)
    ans_f = _write_fixture(tmp_path, "aap.json", _ANSIBLE_FIXTURE)
    con_f = _write_fixture(tmp_path, "concert.json", _CONCERT_FIXTURE)
    cfg = BootstrapConfig(
        kg_dir=tmp_path / "kg",
        sources=["acm", "ansible", "concert"],
        acm_fixture_path=acm_f,
        ansible_fixture_path=ans_f,
        concert_fixture_path=con_f,
    )
    result = kg_bootstrap(cfg)
    assert len(result.sources_run) == 3
    assert sum(result.nodes_written.values()) == 3


def test_bootstrap_all_sources_no_errors(tmp_path):
    acm_f = _write_fixture(tmp_path, "acm.json", _ACM_FIXTURE)
    ans_f = _write_fixture(tmp_path, "aap.json", _ANSIBLE_FIXTURE)
    con_f = _write_fixture(tmp_path, "concert.json", _CONCERT_FIXTURE)
    cfg = BootstrapConfig(
        kg_dir=tmp_path / "kg",
        sources=["acm", "ansible", "concert"],
        acm_fixture_path=acm_f,
        ansible_fixture_path=ans_f,
        concert_fixture_path=con_f,
    )
    result = kg_bootstrap(cfg)
    assert result.errors == {}


# ---------------------------------------------------------------------------
# kg_bootstrap — empty fixtures (no fixture path → empty intake)
# ---------------------------------------------------------------------------

def test_bootstrap_no_fixture_paths_runs_without_error(tmp_path):
    cfg = BootstrapConfig(kg_dir=tmp_path / "kg", sources=["acm", "ansible", "concert"])
    result = kg_bootstrap(cfg)
    assert result.errors == {}
    assert result.nodes_written == {"acm": 0, "ansible": 0, "concert": 0}


# ---------------------------------------------------------------------------
# kg_bootstrap — source failure does not abort others
# ---------------------------------------------------------------------------

def test_bootstrap_bad_fixture_path_captured_as_error(tmp_path):
    cfg = BootstrapConfig(
        kg_dir=tmp_path / "kg",
        sources=["acm", "concert"],
        acm_fixture_path=tmp_path / "ghost.json",  # does not exist
        concert_fixture_path=_write_fixture(tmp_path, "concert.json", _CONCERT_FIXTURE),
    )
    result = kg_bootstrap(cfg)
    assert "acm" in result.errors
    assert "concert" in result.sources_run


# ---------------------------------------------------------------------------
# Bootstrap history
# ---------------------------------------------------------------------------

def test_bootstrap_appends_history(tmp_path):
    acm_f = _write_fixture(tmp_path, "acm.json", _ACM_FIXTURE)
    cfg = BootstrapConfig(kg_dir=tmp_path / "kg", sources=["acm"], acm_fixture_path=acm_f)
    kg_bootstrap(cfg)
    history = load_bootstrap_history(tmp_path / "kg")
    assert len(history) == 1


def test_bootstrap_history_multiple_runs(tmp_path):
    acm_f = _write_fixture(tmp_path, "acm.json", _ACM_FIXTURE)
    cfg = BootstrapConfig(kg_dir=tmp_path / "kg", sources=["acm"], acm_fixture_path=acm_f)
    kg_bootstrap(cfg)
    kg_bootstrap(cfg)
    history = load_bootstrap_history(tmp_path / "kg")
    assert len(history) == 2


def test_bootstrap_history_has_timestamp(tmp_path):
    acm_f = _write_fixture(tmp_path, "acm.json", _ACM_FIXTURE)
    cfg = BootstrapConfig(kg_dir=tmp_path / "kg", sources=["acm"], acm_fixture_path=acm_f)
    kg_bootstrap(cfg)
    history = load_bootstrap_history(tmp_path / "kg")
    assert history[0]["timestamp"]


def test_bootstrap_history_records_node_counts(tmp_path):
    acm_f = _write_fixture(tmp_path, "acm.json", _ACM_FIXTURE)
    cfg = BootstrapConfig(kg_dir=tmp_path / "kg", sources=["acm"], acm_fixture_path=acm_f)
    kg_bootstrap(cfg)
    history = load_bootstrap_history(tmp_path / "kg")
    assert history[0]["nodes_written"]["acm"] == 1


def test_load_bootstrap_history_empty_dir(tmp_path):
    assert load_bootstrap_history(tmp_path) == []


# ---------------------------------------------------------------------------
# kg_status integration
# ---------------------------------------------------------------------------

def test_kg_status_includes_bootstrap_history_key(tmp_path):
    from calm_forge.kg_inspect import kg_status
    acm_f = _write_fixture(tmp_path, "acm.json", _ACM_FIXTURE)
    kg_dir = tmp_path / "kg"
    cfg = BootstrapConfig(kg_dir=kg_dir, sources=["acm"], acm_fixture_path=acm_f)
    kg_bootstrap(cfg)
    status = kg_status(kg_dir)
    assert "bootstrap_history" in status


def test_kg_status_bootstrap_history_runs_count(tmp_path):
    from calm_forge.kg_inspect import kg_status
    acm_f = _write_fixture(tmp_path, "acm.json", _ACM_FIXTURE)
    kg_dir = tmp_path / "kg"
    cfg = BootstrapConfig(kg_dir=kg_dir, sources=["acm"], acm_fixture_path=acm_f)
    kg_bootstrap(cfg)
    status = kg_status(kg_dir)
    assert status["bootstrap_history"]["runs"] == 1


def test_kg_status_bootstrap_history_no_runs(tmp_path):
    from calm_forge.kg_inspect import kg_status
    kg_dir = tmp_path / "kg"
    kg_dir.mkdir()
    status = kg_status(kg_dir)
    assert status["bootstrap_history"]["runs"] == 0
