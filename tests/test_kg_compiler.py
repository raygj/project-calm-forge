"""Tests for kg_compiler — KG Policy predicate nodes → OPA Rego rules."""
from __future__ import annotations

import shutil
import subprocess

import pytest

from calm_forge.kg_compiler import (
    DRIFT_ENGINE,
    PRE_GENERATION,
    RUNTIME,
    _compile_compliance_boundary,
    _compile_placement_constraint,
    _safe_rule_id,
    compile_all,
    compile_drift,
    compile_violations,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_PLACEMENT_POLICY = {
    "@type": "Policy",
    "@id": "workload:test:policy:placement",
    "predicate_type": "placement_constraint",
    "required_labels": {"environment": "prod", "compliance": "pci"},
    "enforcement_mode": "enforce",
    "provenance": "authored",
    "rationale": "Must run on prod-pci clusters",
}

_BOUNDARY_POLICY = {
    "@type": "Policy",
    "@id": "workload:test:policy:region",
    "predicate_type": "compliance_boundary",
    "allowed_regions": ["us-east-1", "eu-west-1"],
    "enforcement_mode": "enforce",
    "provenance": "authored",
    "rationale": "Data residency",
}

_DRIFT_POLICY = {
    "@type": "Policy",
    "@id": "workload:test:policy:drift",
    "predicate_type": "drift_threshold",
    "max_deviation_hours": 4,
    "enforcement_mode": "audit",
    "provenance": "authored",
}

_CAPABILITY_POLICY = {
    "@type": "Policy",
    "@id": "workload:test:policy:cap",
    "predicate_type": "capability_requirement",
    "required_capability": "confidential_compute",
    "enforcement_mode": "enforce",
    "provenance": "authored",
}

_CEILING_POLICY = {
    "@type": "Policy",
    "@id": "workload:test:policy:ceiling",
    "predicate_type": "capability_ceiling",
    "enforcement_mode": "enforce",
    "provenance": "authored",
}


# ---------------------------------------------------------------------------
# Predicate classification
# ---------------------------------------------------------------------------


def test_predicate_context_sets_are_disjoint() -> None:
    assert PRE_GENERATION & DRIFT_ENGINE == set()
    assert PRE_GENERATION & RUNTIME == set()
    assert DRIFT_ENGINE & RUNTIME == set()


def test_pre_generation_predicates() -> None:
    assert "placement_constraint" in PRE_GENERATION
    assert "compliance_boundary" in PRE_GENERATION


def test_drift_engine_predicates() -> None:
    assert "drift_threshold" in DRIFT_ENGINE
    assert "lifecycle_condition" in DRIFT_ENGINE


def test_runtime_predicates() -> None:
    assert "capability_ceiling" in RUNTIME
    assert "capability_requirement" in RUNTIME
    assert "isolation_requirement" in RUNTIME


# ---------------------------------------------------------------------------
# compile_violations output structure
# ---------------------------------------------------------------------------


def test_compile_violations_package_declaration() -> None:
    rego = compile_violations([_PLACEMENT_POLICY])
    assert "package calm" in rego


def test_compile_violations_array_footer() -> None:
    rego = compile_violations([_PLACEMENT_POLICY])
    assert "violations := [v | v := violation[_]]" in rego


def test_compile_violations_is_auto_generated() -> None:
    rego = compile_violations([])
    assert "AUTO-GENERATED" in rego


# ---------------------------------------------------------------------------
# placement_constraint compilation
# ---------------------------------------------------------------------------


def test_placement_constraint_generates_violation_rule() -> None:
    rego = _compile_placement_constraint(_PLACEMENT_POLICY, "enforce")
    assert "violation contains v if" in rego
    assert '"environment"' in rego
    assert '"prod"' in rego
    assert '"compliance"' in rego
    assert '"pci"' in rego


def test_placement_constraint_severity_enforce() -> None:
    rego = _compile_placement_constraint(_PLACEMENT_POLICY, "enforce")
    assert '"error"' in rego


def test_placement_constraint_severity_audit() -> None:
    policy = {**_PLACEMENT_POLICY, "enforcement_mode": "audit"}
    rego = _compile_placement_constraint(policy, "audit")
    assert '"warning"' in rego


def test_placement_constraint_empty_labels() -> None:
    policy = {**_PLACEMENT_POLICY, "required_labels": {}}
    rego = _compile_placement_constraint(policy, "enforce")
    assert "skipped" in rego


# ---------------------------------------------------------------------------
# compliance_boundary compilation
# ---------------------------------------------------------------------------


def test_compliance_boundary_generates_violation_rule() -> None:
    rego = _compile_compliance_boundary(_BOUNDARY_POLICY, "enforce")
    assert "violation contains v if" in rego
    assert "us-east-1" in rego
    assert "eu-west-1" in rego


def test_compliance_boundary_region_check() -> None:
    rego = _compile_compliance_boundary(_BOUNDARY_POLICY, "enforce")
    assert "not region in" in rego


def test_compliance_boundary_empty_regions() -> None:
    policy = {**_BOUNDARY_POLICY, "allowed_regions": []}
    rego = _compile_compliance_boundary(policy, "enforce")
    assert "skipped" in rego


# ---------------------------------------------------------------------------
# Non-pre-generation predicates are commented out, not compiled
# ---------------------------------------------------------------------------


def test_drift_predicate_becomes_comment() -> None:
    rego = compile_violations([_DRIFT_POLICY])
    assert "violation contains v if" not in rego
    assert "DRIFT_ENGINE" in rego
    assert "drift_threshold" in rego


def test_capability_predicate_becomes_comment() -> None:
    rego = compile_violations([_CAPABILITY_POLICY])
    assert "violation contains v if" not in rego
    assert "RUNTIME" in rego


def test_ceiling_predicate_becomes_comment() -> None:
    rego = compile_violations([_CEILING_POLICY])
    assert "violation contains v if" not in rego


# ---------------------------------------------------------------------------
# Mixed policy list
# ---------------------------------------------------------------------------


def test_compile_mixed_policies() -> None:
    policies = [_PLACEMENT_POLICY, _BOUNDARY_POLICY, _DRIFT_POLICY, _CAPABILITY_POLICY]
    rego = compile_violations(policies)
    # Pre-generation predicates each compile to one violation contains v if rule block
    assert rego.count("violation contains v if") == 2  # placement (1 block, 2 label checks) + boundary (1 block)
    # Drift and runtime become comments only
    assert "DRIFT_ENGINE" in rego
    assert "RUNTIME" in rego


# ---------------------------------------------------------------------------
# compile_drift_stub
# ---------------------------------------------------------------------------


def test_drift_package() -> None:
    rego = compile_drift()
    assert "package calm.drift" in rego
    assert "AUTO-GENERATED" in rego
    assert "drift_violations" in rego


# ---------------------------------------------------------------------------
# compile_all
# ---------------------------------------------------------------------------


def test_compile_all_returns_both_files() -> None:
    result = compile_all([_PLACEMENT_POLICY])
    assert "calm_violations.rego" in result
    assert "calm_drift.rego" in result


def test_compile_all_violations_has_rules() -> None:
    result = compile_all([_PLACEMENT_POLICY])
    assert "violation contains v if" in result["calm_violations.rego"]


def test_compile_all_drift_is_stub() -> None:
    result = compile_all([_PLACEMENT_POLICY])
    assert "package calm.drift" in result["calm_drift.rego"]


# ---------------------------------------------------------------------------
# _safe_rule_id
# ---------------------------------------------------------------------------


def test_safe_rule_id_strips_workload_prefix() -> None:
    assert "workload:" not in _safe_rule_id("workload:test:policy:placement")


def test_safe_rule_id_replaces_colons() -> None:
    result = _safe_rule_id("workload:test:policy:x")
    assert ":" not in result


# ---------------------------------------------------------------------------
# Integration: compile from real KG patterns
# ---------------------------------------------------------------------------


def test_compile_from_real_patterns() -> None:
    """Smoke test: compile the built-in KG patterns and get valid Rego."""
    from calm_forge.kg_loader import _KG_DIR, extract_policies, load_patterns

    all_policies = []
    for pattern in load_patterns(_KG_DIR):
        all_policies.extend(extract_policies(pattern))

    assert len(all_policies) > 0

    rego = compile_violations(all_policies)
    assert "package calm" in rego
    assert "violations :=" in rego
    # Should have at least some compiled rules from pci + fraud patterns
    assert "violation contains v if" in rego


# ---------------------------------------------------------------------------
# Regression: emitted Rego must actually parse under the OPA we ship against.
# OPA 1.x defaults to Rego v1 — these guard against v0 syntax / malformed
# string interpolation silently degrading validation to opa-error (see CI).
# Skips when the OPA binary is absent (matches graceful-degradation behavior).
# ---------------------------------------------------------------------------


def _opa_check(bundle_dir: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["opa", "check", bundle_dir],
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_builtin_bundle_parses_under_opa() -> None:
    from calm_forge.opa_gate import _BUILTIN_BUNDLE

    if shutil.which("opa") is None:
        pytest.skip("opa binary not available")

    result = _opa_check(str(_BUILTIN_BUNDLE))
    assert result.returncode == 0, f"built-in bundle failed opa check:\n{result.stdout}{result.stderr}"


def test_compiled_bundle_parses_under_opa(tmp_path) -> None:
    if shutil.which("opa") is None:
        pytest.skip("opa binary not available")

    # Exercise every emitting template: placement, compliance boundary, drift.
    policies = [_PLACEMENT_POLICY, _BOUNDARY_POLICY, _DRIFT_POLICY]
    for filename, content in compile_all(policies).items():
        (tmp_path / filename).write_text(content)

    result = _opa_check(str(tmp_path))
    assert result.returncode == 0, f"compiled bundle failed opa check:\n{result.stdout}{result.stderr}"
