"""Tests for round-trip constraint and calm.drift evaluation."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from calm_forge.kg_compiler import compile_all, compile_drift
from calm_forge.kg_loader import _KG_DIR, assert_round_trip_ready, load_patterns
from calm_forge.opa_gate import evaluate_drift

# ---------------------------------------------------------------------------
# Round-trip constraint — assert_round_trip_ready
# ---------------------------------------------------------------------------


def test_round_trip_ready_minimal_valid(tmp_path: Path) -> None:
    pattern = {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "Workload",
        "@id": "workload:test:v1",
        "version": "1.0.0",
        "name": "test",
        "purpose": "Test",
        "owner": "test-team",
        "_provenance": {"authored_by": "test", "authored_at": "2026-04-21T00:00:00Z"},
        "node_class": "authored",
        "plane": "architecture",
        "policies": [],
    }
    gaps = assert_round_trip_ready(pattern)
    assert gaps == [], f"Expected no gaps, got: {gaps}"


def test_round_trip_ready_missing_provenance_fields() -> None:
    pattern = {
        "@context": "...",
        "@type": "Workload",
        "@id": "workload:test:v1",
        "version": "1.0.0",
        "name": "test",
        "purpose": "Test",
        "owner": "test-team",
        "_provenance": {},  # missing authored_by and authored_at
        "policies": [],
    }
    gaps = assert_round_trip_ready(pattern)
    assert any("authored_by" in g for g in gaps)
    assert any("authored_at" in g for g in gaps)


def test_round_trip_ready_missing_workload_fields() -> None:
    pattern = {
        "@type": "Workload",
        "@id": "workload:test:v1",
        # missing: @context, version, name, purpose, owner, _provenance
        "policies": [],
    }
    gaps = assert_round_trip_ready(pattern)
    assert any("@context" in g for g in gaps)
    assert any("name" in g for g in gaps)


def test_round_trip_ready_policy_missing_fields() -> None:
    pattern = {
        "@context": "...",
        "@type": "Workload",
        "@id": "workload:test:v1",
        "version": "1.0.0",
        "name": "test",
        "purpose": "Test",
        "owner": "test-team",
        "_provenance": {"authored_by": "test", "authored_at": "2026-04-21T00:00:00Z"},
        "policies": [
            {
                "@type": "Policy",
                "@id": "workload:test:policy:x",
                "predicate_type": "placement_constraint",
                # missing: enforcement_mode, evaluated_by, provenance, required_labels
            }
        ],
    }
    gaps = assert_round_trip_ready(pattern)
    assert any("enforcement_mode" in g for g in gaps)
    assert any("evaluated_by" in g for g in gaps)
    assert any("required_labels" in g for g in gaps)


def test_round_trip_ready_placement_constraint_no_labels() -> None:
    pattern = {
        "@context": "...",
        "@type": "Workload",
        "@id": "workload:test:v1",
        "version": "1.0.0",
        "name": "test",
        "purpose": "Test",
        "owner": "test-team",
        "_provenance": {"authored_by": "test", "authored_at": "2026-04-21T00:00:00Z"},
        "policies": [
            {
                "@type": "Policy",
                "@id": "workload:test:policy:p",
                "predicate_type": "placement_constraint",
                "enforcement_mode": "enforce",
                "evaluated_by": "calm.placement.label_constraint",
                "provenance": "authored",
                "required_labels": {},  # empty — should flag
            }
        ],
    }
    gaps = assert_round_trip_ready(pattern)
    assert any("required_labels" in g for g in gaps)


def test_round_trip_ready_real_patterns_pass() -> None:
    """All built-in reference patterns must be round-trip ready."""
    patterns = load_patterns(_KG_DIR)
    assert len(patterns) >= 3, "Expected at least 3 reference patterns"

    for pattern in patterns:
        gaps = assert_round_trip_ready(pattern)
        assert gaps == [], (
            f"Pattern '{pattern.get('name')}' failed round-trip constraint:\n"
            + "\n".join(f"  - {g}" for g in gaps)
        )


# ---------------------------------------------------------------------------
# calm.drift Rego compilation
# ---------------------------------------------------------------------------


def test_compile_drift_package_declaration() -> None:
    rego = compile_drift()
    assert "package calm.drift" in rego


def test_compile_drift_capability_ceiling_rule() -> None:
    rego = compile_drift()
    assert "capability-ceiling" in rego
    assert "observed_capabilities" in rego
    assert "declared_capabilities" in rego


def test_compile_drift_threshold_rule() -> None:
    rego = compile_drift()
    assert "drift_threshold" in rego
    assert "deviation_hours" in rego
    assert "max_deviation_hours" in rego


def test_compile_drift_violations_array() -> None:
    rego = compile_drift()
    assert "drift_violations :=" in rego


def test_compile_all_drift_is_not_stub() -> None:
    """drift package must contain real rules, not the old stub."""
    result = compile_all([])
    rego = result["calm_drift.rego"]
    assert "capability-ceiling" in rego
    assert "drift_threshold" in rego
    # Old stub marker must be gone
    assert "stub — diff engine will populate" not in rego


# ---------------------------------------------------------------------------
# evaluate_drift — Python side
# ---------------------------------------------------------------------------

_WORKLOAD = {
    "@type": "Workload",
    "@id": "workload:test:v1",
    "declared_capabilities": ["http_read", "vault_dynamic_creds"],
}

_PLACEMENT_COMPLIANT = {
    "@type": "Placement",
    "@id": "placement:test:prod-east",
    "workload_id": "workload:test:v1",
    "observed_capabilities": ["http_read", "vault_dynamic_creds"],
    "drift_state": {"deviation_hours": 0, "status": "compliant"},
}

_PLACEMENT_CAPABILITY_BREACH = {
    "@type": "Placement",
    "@id": "placement:test:prod-east",
    "workload_id": "workload:test:v1",
    "observed_capabilities": ["http_read", "vault_dynamic_creds", "admin_access"],
    "drift_state": {"deviation_hours": 0, "status": "compliant"},
}

_PLACEMENT_DRIFT_EXCEEDED = {
    "@type": "Placement",
    "@id": "placement:test:prod-east",
    "workload_id": "workload:test:v1",
    "observed_capabilities": ["http_read"],
    "drift_state": {"deviation_hours": 6, "status": "drifted"},
}

_DRIFT_POLICY = {
    "@type": "Policy",
    "@id": "workload:test:policy:drift",
    "predicate_type": "drift_threshold",
    "max_deviation_hours": 4,
    "enforcement_mode": "enforce",
}


def test_evaluate_drift_opa_not_available() -> None:
    with patch("calm_forge.opa_gate.is_opa_available", return_value=False):
        result = evaluate_drift(_WORKLOAD, _PLACEMENT_COMPLIANT)
    assert result["compliant"] is True
    assert result["opa_available"] is False
    assert "warning" in result


def test_evaluate_drift_compliant_no_violations() -> None:
    with (
        patch("calm_forge.opa_gate.is_opa_available", return_value=True),
        patch("calm_forge.opa_gate._run_opa_eval", return_value=[]),
    ):
        result = evaluate_drift(_WORKLOAD, _PLACEMENT_COMPLIANT)
    assert result["compliant"] is True
    assert result["violations"] == []


def test_evaluate_drift_capability_breach() -> None:
    mock_violation = [
        {
            "rule": "capability-ceiling",
            "severity": "error",
            "message": "Capability 'admin_access' observed but not declared",
        }
    ]
    with (
        patch("calm_forge.opa_gate.is_opa_available", return_value=True),
        patch("calm_forge.opa_gate._run_opa_eval", return_value=mock_violation),
    ):
        result = evaluate_drift(_WORKLOAD, _PLACEMENT_CAPABILITY_BREACH)
    assert result["compliant"] is False
    assert len(result["violations"]) == 1
    assert result["violations"][0]["rule"] == "capability-ceiling"


def test_evaluate_drift_threshold_exceeded() -> None:
    mock_violation = [
        {
            "rule": "workload:test:policy:drift",
            "severity": "error",
            "message": "Drift threshold exceeded: 6 hours > declared max 4 hours",
        }
    ]
    with (
        patch("calm_forge.opa_gate.is_opa_available", return_value=True),
        patch("calm_forge.opa_gate._run_opa_eval", return_value=mock_violation),
    ):
        result = evaluate_drift(_WORKLOAD, _PLACEMENT_DRIFT_EXCEEDED, policies=[_DRIFT_POLICY])
    assert result["compliant"] is False
    assert result["violations"][0]["severity"] == "error"


def test_evaluate_drift_passes_correct_query() -> None:
    """evaluate_drift must query calm.drift.drift_violations, not calm.violations."""
    captured_queries = []

    def capture(opa_input, bundle_path, query="data.calm.violations"):
        captured_queries.append(query)
        return []

    with (
        patch("calm_forge.opa_gate.is_opa_available", return_value=True),
        patch("calm_forge.opa_gate._run_opa_eval", side_effect=capture),
    ):
        evaluate_drift(_WORKLOAD, _PLACEMENT_COMPLIANT)

    assert captured_queries, "Expected _run_opa_eval to be called"
    assert all("calm.drift" in q for q in captured_queries), (
        f"Expected calm.drift query, got: {captured_queries}"
    )
