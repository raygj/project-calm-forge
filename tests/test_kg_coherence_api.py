"""Tests for kg_coherence_api — query_coherence, query_shadow, query_drift."""
from __future__ import annotations

import json
from pathlib import Path

from calm_forge.kg_coherence_api import query_coherence, query_drift, query_shadow

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _write_workload(kg_dir: Path, workload_id: str, provenance: str = "authored") -> None:
    (kg_dir / "workloads").mkdir(parents=True, exist_ok=True)
    node = {
        "@id": workload_id,
        "@type": "Workload",
        "declared_capabilities": ["http_read"],
        "_provenance": {"provenance": provenance},
    }
    fname = workload_id.replace(":", "_").replace("/", "_") + ".json"
    (kg_dir / "workloads" / fname).write_text(json.dumps(node))


def _write_placement(kg_dir: Path, workload_id: str, drift_status: str = "ok",
                     last_evaluated: str | None = None) -> None:
    (kg_dir / "placements").mkdir(parents=True, exist_ok=True)
    node = {
        "@id": f"placement:{workload_id}-us-east-1",
        "@type": "Placement",
        "workload_id": workload_id,
        "region": "us-east-1",
        "observed_capabilities": ["http_read"],
        "drift_state": {
            "status": drift_status,
            "deviation_hours": 0.0 if drift_status == "ok" else 2.5,
            "last_evaluated": last_evaluated or "2026-06-06T00:00:00Z",
        },
    }
    fname = workload_id.replace(":", "_") + "_placement.json"
    (kg_dir / "placements" / fname).write_text(json.dumps(node))


# ---------------------------------------------------------------------------
# query_coherence
# ---------------------------------------------------------------------------

def test_coherence_returns_workload_id(tmp_path):
    _write_workload(tmp_path, "workload:payments")
    _write_placement(tmp_path, "workload:payments")
    result = query_coherence(tmp_path, "workload:payments")
    assert result["workload_id"] == "workload:payments"


def test_coherence_returns_zero_curvature_when_no_history(tmp_path):
    _write_workload(tmp_path, "workload:payments")
    result = query_coherence(tmp_path, "workload:payments")
    assert result["curvature"] == 0.0


def test_coherence_returns_curvature_from_history(tmp_path):
    from calm_forge.drift_evaluator import record_curvature
    _write_workload(tmp_path, "workload:payments")
    record_curvature("workload:payments", 0.75, tmp_path)
    result = query_coherence(tmp_path, "workload:payments")
    assert result["curvature"] == 0.75


def test_coherence_returns_federation_available_true(tmp_path):
    result = query_coherence(tmp_path, "workload:payments")
    assert result["federation_available"] is True


def test_coherence_returns_placement_list(tmp_path):
    _write_workload(tmp_path, "workload:payments")
    _write_placement(tmp_path, "workload:payments")
    result = query_coherence(tmp_path, "workload:payments")
    assert len(result["placements"]) == 1


def test_coherence_placements_scoped_to_workload(tmp_path):
    _write_workload(tmp_path, "workload:payments")
    _write_workload(tmp_path, "workload:fraud")
    _write_placement(tmp_path, "workload:payments")
    _write_placement(tmp_path, "workload:fraud")
    result = query_coherence(tmp_path, "workload:payments")
    assert all(p["workload_id"] == "workload:payments" for p in result["placements"])


def test_coherence_lag_is_none_when_no_sync(tmp_path):
    result = query_coherence(tmp_path, "workload:payments")
    assert result["coherence_lag"] is None


def test_coherence_lag_is_string_when_history_exists(tmp_path):
    from calm_forge.drift_evaluator import record_curvature
    record_curvature("workload:payments", 0.0, tmp_path)
    result = query_coherence(tmp_path, "workload:payments")
    assert result["coherence_lag"] is not None
    assert result["coherence_lag"].startswith("PT")


def test_coherence_lag_wire_format_contract(tmp_path):
    """coherence_lag wire format is a CONTRACT TERM (reasoner--calm-forge
    handshake, 2026-06-12): always null or exactly "PT<integer>S" — whole
    seconds, never negative. The Reasoner parses this; do not change the
    format without amending the handshake.
    """
    import re

    from calm_forge.drift_evaluator import record_curvature
    from calm_forge.kg_coherence_api import _compute_lag

    record_curvature("workload:payments", 0.0, tmp_path)
    result = query_coherence(tmp_path, "workload:payments")
    assert re.fullmatch(r"PT\d+S", result["coherence_lag"])

    # Direct pins on the helper, including edge cases
    assert _compute_lag(None) is None
    assert _compute_lag("not-a-timestamp") is None
    assert re.fullmatch(r"PT\d+S", _compute_lag("2026-01-01T00:00:00Z"))
    # Clock skew (future last_sync) clamps to zero, never negative
    assert _compute_lag("2999-01-01T00:00:00Z") == "PT0S"


def test_coherence_placement_summary_has_drift_status(tmp_path):
    _write_placement(tmp_path, "workload:payments", drift_status="violation")
    result = query_coherence(tmp_path, "workload:payments")
    assert result["placements"][0]["drift_status"] == "violation"


# ---------------------------------------------------------------------------
# query_shadow
# ---------------------------------------------------------------------------

def test_shadow_empty_agents_returns_all_authored_unmatched(tmp_path):
    _write_workload(tmp_path, "workload:payments", provenance="authored")
    result = query_shadow(tmp_path, [])
    assert "workload:payments" in result["unmatched_authored"]


def test_shadow_matching_agent_removes_from_unmatched(tmp_path):
    _write_workload(tmp_path, "workload:payments", provenance="authored")
    result = query_shadow(tmp_path, ["workload:payments"])
    assert "workload:payments" not in result["unmatched_authored"]


def test_shadow_unknown_agent_appears_in_shadow_agents(tmp_path):
    _write_workload(tmp_path, "workload:payments")
    result = query_shadow(tmp_path, ["workload:unknown-svc"])
    assert "workload:unknown-svc" in result["shadow_agents"]


def test_shadow_reconstructed_workload_in_separate_bucket(tmp_path):
    _write_workload(tmp_path, "workload:legacy", provenance="reconstructed")
    result = query_shadow(tmp_path, [])
    assert "workload:legacy" in result["unmatched_reconstructed"]
    assert "workload:legacy" not in result["unmatched_authored"]


def test_shadow_no_cross_contamination_between_buckets(tmp_path):
    _write_workload(tmp_path, "workload:authored-x", provenance="authored")
    _write_workload(tmp_path, "workload:reconstructed-x", provenance="reconstructed")
    result = query_shadow(tmp_path, [])
    assert "workload:authored-x" not in result["unmatched_reconstructed"]
    assert "workload:reconstructed-x" not in result["unmatched_authored"]


def test_shadow_fully_matched_returns_empty_buckets(tmp_path):
    _write_workload(tmp_path, "workload:payments", provenance="authored")
    result = query_shadow(tmp_path, ["workload:payments"])
    assert result["shadow_agents"] == []
    assert result["unmatched_authored"] == []


def test_shadow_response_has_last_sync_key(tmp_path):
    result = query_shadow(tmp_path, [])
    assert "calm_forge_last_sync" in result


# ---------------------------------------------------------------------------
# query_drift
# ---------------------------------------------------------------------------

def test_drift_returns_all_placements_when_no_filter(tmp_path):
    _write_placement(tmp_path, "workload:payments", drift_status="ok")
    _write_placement(tmp_path, "workload:fraud", drift_status="violation")
    result = query_drift(tmp_path, workload_id=None, status=None)
    assert len(result["placements"]) == 2


def test_drift_filters_by_workload_id(tmp_path):
    _write_placement(tmp_path, "workload:payments", drift_status="ok")
    _write_placement(tmp_path, "workload:fraud", drift_status="violation")
    result = query_drift(tmp_path, workload_id="workload:payments", status=None)
    assert len(result["placements"]) == 1
    assert result["placements"][0]["workload_id"] == "workload:payments"


def test_drift_filters_by_status(tmp_path):
    _write_placement(tmp_path, "workload:payments", drift_status="ok")
    _write_placement(tmp_path, "workload:fraud", drift_status="violation")
    result = query_drift(tmp_path, workload_id=None, status="violation")
    assert len(result["placements"]) == 1
    assert result["placements"][0]["drift_status"] == "violation"


def test_drift_combined_filter(tmp_path):
    _write_placement(tmp_path, "workload:payments", drift_status="violation")
    _write_placement(tmp_path, "workload:fraud", drift_status="violation")
    result = query_drift(tmp_path, workload_id="workload:payments", status="violation")
    assert len(result["placements"]) == 1


def test_drift_empty_kg_returns_empty_placements(tmp_path):
    result = query_drift(tmp_path, workload_id=None, status=None)
    assert result["placements"] == []


def test_drift_response_has_last_sync_key(tmp_path):
    result = query_drift(tmp_path, workload_id=None, status=None)
    assert "calm_forge_last_sync" in result
