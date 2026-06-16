"""Tests for P5-003 — Curvature trending."""
from __future__ import annotations

from calm_forge.drift_evaluator import (
    curvature_trend,
    load_curvature_history,
    record_curvature,
)
from calm_forge.intent_validator import (
    ManifoldEngine,
    validate_architecture_intent,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_CLEAN_ARCH = {
    "workload_id": "workload:fraud-v1",
    "declared_capabilities": ["http_read"],
    "components": [{"id": "scorer", "name": "scorer", "capabilities": ["http_read"]}],
    "edges": [{"@type": "requires_capability", "from": "scorer", "to": "capability:http_read"}],
    "compliance_scope": [],
    "allowed_regions": [],
    "policies": [],
}

_DIRTY_CALM = {
    # CALM instantiation with pii_read but no compliance scope → curvature > 0
    "title": "pii-dirty",
    "nodes": [{"unique-id": "reader", "required-capabilities": ["pii_read"]}],
    "metadata": {},
}


# ---------------------------------------------------------------------------
# record_curvature
# ---------------------------------------------------------------------------

def test_record_curvature_creates_history_file(tmp_path):
    record_curvature("workload:fraud-v1", 0.5, tmp_path)
    assert (tmp_path / "_fabric" / "curvature-history.jsonl").exists()


def test_record_curvature_appends_record(tmp_path):
    record_curvature("workload:fraud-v1", 0.5, tmp_path)
    records = load_curvature_history(tmp_path)
    assert len(records) == 1


def test_record_curvature_stores_curvature_value(tmp_path):
    record_curvature("workload:fraud-v1", 0.75, tmp_path)
    records = load_curvature_history(tmp_path)
    assert records[0]["curvature"] == 0.75


def test_record_curvature_stores_workload_id(tmp_path):
    record_curvature("workload:fraud-v1", 0.5, tmp_path)
    records = load_curvature_history(tmp_path)
    assert records[0]["workload_id"] == "workload:fraud-v1"


def test_record_curvature_has_timestamp(tmp_path):
    record_curvature("workload:fraud-v1", 0.0, tmp_path)
    records = load_curvature_history(tmp_path)
    assert records[0]["timestamp"]


def test_record_curvature_multiple_appends(tmp_path):
    for v in [0.1, 0.2, 0.3]:
        record_curvature("workload:fraud-v1", v, tmp_path)
    records = load_curvature_history(tmp_path)
    assert len(records) == 3


# ---------------------------------------------------------------------------
# load_curvature_history
# ---------------------------------------------------------------------------

def test_load_curvature_history_empty(tmp_path):
    assert load_curvature_history(tmp_path) == []


def test_load_curvature_history_filtered_by_workload(tmp_path):
    record_curvature("workload:fraud-v1", 0.1, tmp_path)
    record_curvature("workload:other", 0.2, tmp_path)
    records = load_curvature_history(tmp_path, "workload:fraud-v1")
    assert all(r["workload_id"] == "workload:fraud-v1" for r in records)
    assert len(records) == 1


def test_load_curvature_history_no_filter_returns_all(tmp_path):
    record_curvature("workload:a", 0.1, tmp_path)
    record_curvature("workload:b", 0.2, tmp_path)
    assert len(load_curvature_history(tmp_path)) == 2


# ---------------------------------------------------------------------------
# curvature_trend
# ---------------------------------------------------------------------------

def test_curvature_trend_insufficient_data_zero_samples(tmp_path):
    result = curvature_trend("workload:fraud-v1", tmp_path)
    assert result["trend"] == "insufficient-data"


def test_curvature_trend_insufficient_data_one_sample(tmp_path):
    record_curvature("workload:fraud-v1", 0.5, tmp_path)
    result = curvature_trend("workload:fraud-v1", tmp_path)
    assert result["trend"] == "insufficient-data"


def test_curvature_trend_degrading(tmp_path):
    for v in [0.0, 0.1, 0.2, 0.3]:
        record_curvature("workload:fraud-v1", v, tmp_path)
    result = curvature_trend("workload:fraud-v1", tmp_path)
    assert result["trend"] == "degrading"


def test_curvature_trend_improving(tmp_path):
    for v in [0.4, 0.3, 0.2, 0.1]:
        record_curvature("workload:fraud-v1", v, tmp_path)
    result = curvature_trend("workload:fraud-v1", tmp_path)
    assert result["trend"] == "improving"


def test_curvature_trend_stable(tmp_path):
    for _ in range(4):
        record_curvature("workload:fraud-v1", 0.0, tmp_path)
    result = curvature_trend("workload:fraud-v1", tmp_path)
    assert result["trend"] == "stable"


def test_curvature_trend_returns_samples(tmp_path):
    for v in [0.1, 0.2]:
        record_curvature("workload:fraud-v1", v, tmp_path)
    result = curvature_trend("workload:fraud-v1", tmp_path)
    assert len(result["samples"]) == 2


def test_curvature_trend_slope_positive_for_degrading(tmp_path):
    for v in [0.0, 0.1, 0.2, 0.3]:
        record_curvature("workload:fraud-v1", v, tmp_path)
    result = curvature_trend("workload:fraud-v1", tmp_path)
    assert result["slope"] > 0


def test_curvature_trend_slope_negative_for_improving(tmp_path):
    for v in [0.3, 0.2, 0.1, 0.0]:
        record_curvature("workload:fraud-v1", v, tmp_path)
    result = curvature_trend("workload:fraud-v1", tmp_path)
    assert result["slope"] < 0


def test_curvature_trend_window_limits_samples(tmp_path):
    for i in range(20):
        record_curvature("workload:fraud-v1", float(i) / 20, tmp_path)
    result = curvature_trend("workload:fraud-v1", tmp_path, window=5)
    assert len(result["samples"]) == 5


def test_curvature_trend_workload_id_in_result(tmp_path):
    record_curvature("workload:fraud-v1", 0.0, tmp_path)
    record_curvature("workload:fraud-v1", 0.1, tmp_path)
    result = curvature_trend("workload:fraud-v1", tmp_path)
    assert result["workload_id"] == "workload:fraud-v1"


# ---------------------------------------------------------------------------
# validate_architecture_intent with record_curvature=True
# ---------------------------------------------------------------------------

def test_validate_record_curvature_writes_history(tmp_path):
    validate_architecture_intent(
        _CLEAN_ARCH,
        engine=ManifoldEngine(),
        run_opa=False,
        kg_dir=tmp_path,
        record_curvature=True,
    )
    assert len(load_curvature_history(tmp_path)) == 1


def test_validate_record_curvature_three_runs(tmp_path):
    for _ in range(3):
        validate_architecture_intent(
            _CLEAN_ARCH,
            engine=ManifoldEngine(),
            run_opa=False,
            kg_dir=tmp_path,
            record_curvature=True,
        )
    assert len(load_curvature_history(tmp_path)) == 3


def test_validate_record_curvature_false_does_not_write(tmp_path):
    validate_architecture_intent(
        _CLEAN_ARCH,
        engine=ManifoldEngine(),
        run_opa=False,
        kg_dir=tmp_path,
        record_curvature=False,
    )
    assert load_curvature_history(tmp_path) == []


def test_validate_record_curvature_opa_engine_does_not_write(tmp_path):
    from calm_forge.intent_validator import OPAEngine
    validate_architecture_intent(
        _CLEAN_ARCH,
        engine=OPAEngine(),
        run_opa=False,
        kg_dir=tmp_path,
        record_curvature=True,
    )
    assert load_curvature_history(tmp_path) == []


def test_validate_record_curvature_dirty_arch_nonzero(tmp_path):
    validate_architecture_intent(
        _DIRTY_CALM,
        engine=ManifoldEngine(),
        run_opa=False,
        kg_dir=tmp_path,
        record_curvature=True,
    )
    history = load_curvature_history(tmp_path)
    assert history[0]["curvature"] > 0.0


# ---------------------------------------------------------------------------
# kg_status curvature_trends integration
# ---------------------------------------------------------------------------

def test_kg_status_curvature_trends_key(tmp_path):
    from calm_forge.kg_inspect import kg_status
    record_curvature("workload:fraud-v1", 0.0, tmp_path)
    record_curvature("workload:fraud-v1", 0.1, tmp_path)
    (tmp_path / "placements").mkdir()
    status = kg_status(tmp_path)
    assert "curvature_trends" in status


def test_kg_status_curvature_trends_empty_when_no_history(tmp_path):
    from calm_forge.kg_inspect import kg_status
    (tmp_path / "placements").mkdir()
    status = kg_status(tmp_path)
    assert status["curvature_trends"] == []


def test_kg_status_curvature_trends_one_entry_per_workload(tmp_path):
    from calm_forge.kg_inspect import kg_status
    record_curvature("workload:a", 0.0, tmp_path)
    record_curvature("workload:a", 0.1, tmp_path)
    record_curvature("workload:b", 0.2, tmp_path)
    record_curvature("workload:b", 0.3, tmp_path)
    (tmp_path / "placements").mkdir()
    status = kg_status(tmp_path)
    assert len(status["curvature_trends"]) == 2
