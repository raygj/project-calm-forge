"""The Gate — archetype evaluation harness and VSA emission (MP-33, ADR-013 §2/§3/§6).

Behaviours pinned with their reason:

1. **Fail closed.** The verdict is PASSED iff every check passed; an empty suite raises
   rather than returning a vacuous PASSED (ADR-013 §6).
2. **Quarantine is autonomic-contraction** (ADR-013 §3) and carries its cause.
3. **The VSA is a stock in-toto/DSSE statement** — a DSSE envelope verifies with the same
   machinery as SLSA provenance (MP-07), so no gate-specific verifier is needed.
4. **The suite is pinned by digest** — the VSA's evidence scope is machine-readable, never
   implied (ADR-013 §4/§6).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.gate_runner import (
    AUTONOMIC_CONTRACTION,
    CHECK_DB_DRIVER,
    CHECK_MTLS,
    CHECK_RESOURCE,
    CHECK_SYNTHETIC,
    RESULT_FAILED,
    RESULT_PASSED,
    VSA_PREDICATE_TYPE,
    GateError,
    artifact_descriptor,
    run_check,
    run_gate,
    suite_descriptor,
    write_gate_result,
)
from calm_forge.passport import generate_keypair, public_key_b64
from calm_forge.provenance import statement_from_envelope, verify_envelope

FIXED_TIME = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)
_ARTIFACT = artifact_descriptor(
    "registry.example/payments/api", "sha256:" + "e9" * 32
)
_SUITE = suite_descriptor("kg://supply_chain/archetype-suite/v1", content={"v": 1})


def _mtls(passed=True):
    return {
        "name": "mtls", "kind": "mtls_handshake", "archetype": "go-strict-tls",
        "spec": {"min_tls_version": "1.3", "require_mutual": True},
        "evidence": {"negotiated_tls_version": "1.3" if passed else "1.1", "mutual": True},
    }


# ---------------------------------------------------------------------------
# The four check kinds
# ---------------------------------------------------------------------------

def test_mtls_check_passes_and_fails():
    ok = run_check(_mtls(passed=True))
    assert ok.passed and ok.archetype == "go-strict-tls"
    bad = run_check(_mtls(passed=False))
    assert not bad.passed and "TLS" in bad.detail


def test_mtls_requires_mutual_when_asked():
    outcome = run_check({
        "name": "m", "kind": "mtls_handshake",
        "spec": {"require_mutual": True}, "evidence": {"mutual": False},
    })
    assert not outcome.passed and "mutual" in outcome.detail


def test_db_driver_version_comparison():
    ok = run_check({"name": "db", "kind": "db_driver_compat",
                    "spec": {"driver": "postgresql", "min_version": "42.6"},
                    "evidence": {"driver": "postgresql", "version": "42.7.3"}})
    assert ok.passed
    old = run_check({"name": "db", "kind": "db_driver_compat",
                     "spec": {"driver": "postgresql", "min_version": "42.6"},
                     "evidence": {"driver": "postgresql", "version": "42.5.0"}})
    assert not old.passed


def test_resource_profile_budget():
    over = run_check({"name": "r", "kind": "resource_profile",
                      "spec": {"max_memory_mb": 512},
                      "evidence": {"memory_mb": 900}})
    assert not over.passed and "memory" in over.detail


def test_synthetic_transaction_status_and_latency():
    slow = run_check({"name": "s", "kind": "synthetic_transaction",
                      "spec": {"expect_status": 200, "max_latency_ms": 100},
                      "evidence": {"status": 200, "latency_ms": 250}})
    assert not slow.passed and "latency" in slow.detail


def test_an_unknown_check_kind_raises_rather_than_passing():
    """A check the harness cannot run must not read as satisfied — that would let an
    unimplemented requirement look met."""
    with pytest.raises(GateError, match="unknown check kind"):
        run_check({"name": "x", "kind": "quantum_entanglement_probe"})


# ---------------------------------------------------------------------------
# The verdict — fail closed
# ---------------------------------------------------------------------------

def test_all_checks_pass_is_a_passed_vsa_with_no_quarantine():
    result = run_gate(artifact=_ARTIFACT, suite=_SUITE, checks=[_mtls(True)],
                      time_verified=FIXED_TIME)
    assert result.result == RESULT_PASSED
    assert result.passed and result.quarantine is None
    assert result.vsa["predicate"]["verificationResult"] == RESULT_PASSED


def test_any_failing_check_fails_the_gate_and_quarantines():
    result = run_gate(artifact=_ARTIFACT, suite=_SUITE,
                      checks=[_mtls(True), _mtls(False)], time_verified=FIXED_TIME)
    assert result.result == RESULT_FAILED
    assert result.quarantine is not None
    assert result.quarantine["authority_class"] == AUTONOMIC_CONTRACTION
    assert result.quarantine["cause"] == "gate_failed"
    assert len(result.quarantine["failed_checks"]) == 1


def test_an_empty_suite_is_a_caller_error_not_a_vacuous_pass():
    """A gate that verifies nothing and returns PASSED is the theater ADR-013 §6 warns
    against."""
    with pytest.raises(GateError, match="at least one check"):
        run_gate(artifact=_ARTIFACT, suite=_SUITE, checks=[])


def test_artifact_and_suite_must_carry_a_digest():
    with pytest.raises(GateError, match="artifact descriptor needs"):
        run_gate(artifact={"uri": "x"}, suite=_SUITE, checks=[_mtls()])
    with pytest.raises(GateError, match="suite descriptor needs"):
        run_gate(artifact=_ARTIFACT, suite={"uri": "x"}, checks=[_mtls()])


# ---------------------------------------------------------------------------
# The VSA shape
# ---------------------------------------------------------------------------

def test_vsa_is_a_standard_slsa_verification_summary():
    result = run_gate(artifact=_ARTIFACT, suite=_SUITE, checks=[_mtls(True)],
                      input_attestations=[{"uri": "kg://sbom/x",
                                           "digest": {"sha256": "a" * 64}}],
                      time_verified=FIXED_TIME)
    vsa = result.vsa
    assert vsa["predicateType"] == VSA_PREDICATE_TYPE
    assert vsa["subject"] == [_ARTIFACT]
    pred = vsa["predicate"]
    assert pred["policy"] == _SUITE
    assert pred["resourceUri"] == _ARTIFACT["uri"]
    assert pred["verifier"]["id"].startswith("https://calm-forge/gate@")
    assert pred["inputAttestations"][0]["uri"] == "kg://sbom/x"
    assert pred["timeVerified"] == "2026-08-22T12:00:00Z"


def test_vsa_records_only_the_archetypes_that_ran():
    """§5 runs the affected archetypes, so the VSA must record the subset it evaluated —
    scope honesty, and the set MP-36 reasons about."""
    result = run_gate(
        artifact=_ARTIFACT, suite=_SUITE, time_verified=FIXED_TIME,
        checks=[_mtls(True),
                {"name": "db", "kind": "db_driver_compat", "archetype": "java-spring-heavy",
                 "spec": {"driver": "postgresql"}, "evidence": {"driver": "postgresql"}}],
    )
    assert result.vsa["predicate"]["evaluatedArchetypes"] == [
        "go-strict-tls", "java-spring-heavy"]


# ---------------------------------------------------------------------------
# Suite descriptor
# ---------------------------------------------------------------------------

def test_suite_descriptor_hashes_content_deterministically():
    a = suite_descriptor("kg://s/v1", content={"a": 1, "b": 2})
    b = suite_descriptor("kg://s/v1", content={"b": 2, "a": 1})
    assert a == b  # canonical JSON — key order does not matter


def test_suite_descriptor_accepts_a_precomputed_digest():
    d = suite_descriptor("kg://s/v1", digest_sha256="sha256:" + "c" * 64)
    assert d["digest"]["sha256"] == "c" * 64


def test_a_suite_with_no_digest_is_refused():
    """A suite reference with no digest cannot pin the scope of the evidence (ADR-013 §4)."""
    with pytest.raises(GateError, match="needs a digest"):
        suite_descriptor("kg://s/v1")


# ---------------------------------------------------------------------------
# Signing — rides the SLSA provenance / MP-07 key posture
# ---------------------------------------------------------------------------

def test_a_signed_vsa_verifies_with_stock_dsse_machinery():
    key = generate_keypair()
    result = run_gate(artifact=_ARTIFACT, suite=_SUITE, checks=[_mtls(True)],
                      key=key, time_verified=FIXED_TIME)
    assert result.envelope is not None
    assert verify_envelope(result.envelope, public_key_b64(key)) is True
    # the envelope carries the same statement
    assert statement_from_envelope(result.envelope) == result.vsa


def test_tampering_with_a_signed_vsa_breaks_verification():
    key = generate_keypair()
    result = run_gate(artifact=_ARTIFACT, suite=_SUITE, checks=[_mtls(True)],
                      key=key, time_verified=FIXED_TIME)
    envelope = dict(result.envelope)
    import base64
    tampered = json.loads(base64.b64decode(envelope["payload"]))
    tampered["predicate"]["verificationResult"] = RESULT_FAILED
    envelope["payload"] = base64.b64encode(
        (json.dumps(tampered, indent=2) + "\n").encode()).decode()
    assert verify_envelope(envelope, public_key_b64(key)) is False


def test_without_a_key_the_vsa_is_unsigned():
    result = run_gate(artifact=_ARTIFACT, suite=_SUITE, checks=[_mtls(True)],
                      time_verified=FIXED_TIME)
    assert result.envelope is None


def test_the_vsa_is_deterministic_for_fixed_inputs():
    """No hidden wall clock: with timeVerified fixed, two runs render byte-identical, so a
    no-op re-gate does not churn the attestation digest."""
    from calm_forge.provenance import render
    a = run_gate(artifact=_ARTIFACT, suite=_SUITE, checks=[_mtls(True)], time_verified=FIXED_TIME)
    b = run_gate(artifact=_ARTIFACT, suite=_SUITE, checks=[_mtls(True)], time_verified=FIXED_TIME)
    assert render(a.vsa) == render(b.vsa)


# ---------------------------------------------------------------------------
# Files and CLI
# ---------------------------------------------------------------------------

def test_write_gate_result_writes_vsa_envelope_and_quarantine(tmp_path):
    key = generate_keypair()
    result = run_gate(artifact=_ARTIFACT, suite=_SUITE,
                      checks=[_mtls(True), _mtls(False)], key=key, time_verified=FIXED_TIME)
    paths = write_gate_result(result, tmp_path)
    names = {p.name for p in paths}
    assert names == {"vsa.slsa.json", "vsa.slsa.dsse.json", "quarantine.json"}


def test_cli_gate_run_passes_the_shipped_spec(tmp_path):
    res = CliRunner().invoke(cli, [
        "gate", "run",
        "--spec", "examples/gate/payments-api-gate-spec.json",
        "--output-dir", str(tmp_path), "--key", str(tmp_path / "gate.pem"),
    ])
    assert res.exit_code == 0, res.output
    assert "Gate PASSED" in res.output
    vsa = json.loads((tmp_path / "vsa.slsa.json").read_text())
    assert vsa["predicate"]["verificationResult"] == "PASSED"
    # signed, and it verifies
    from calm_forge.passport import load_private_key
    env = json.loads((tmp_path / "vsa.slsa.dsse.json").read_text())
    assert verify_envelope(env, public_key_b64(load_private_key(tmp_path / "gate.pem")))
    assert not (tmp_path / "quarantine.json").exists()


def test_cli_gate_run_fails_closed_and_quarantines(tmp_path):
    spec = json.loads(
        __import__("pathlib").Path("examples/gate/payments-api-gate-spec.json").read_text())
    spec["checks"][0]["evidence"]["negotiated_tls_version"] = "1.0"
    spec_path = tmp_path / "bad-spec.json"
    spec_path.write_text(json.dumps(spec))
    res = CliRunner().invoke(cli, [
        "gate", "run", "--spec", str(spec_path), "--output-dir", str(tmp_path),
    ])
    assert res.exit_code == 1
    assert "Gate FAILED" in res.output
    q = json.loads((tmp_path / "quarantine.json").read_text())
    assert q["authority_class"] == AUTONOMIC_CONTRACTION
    assert q["failed_checks"][0]["name"] == "api-mtls"


# ---------------------------------------------------------------------------
# A declared requirement with no measurement fails closed
#
# Found in review, not by these tests: three of the four check kinds originally
# compared with `... and observed is not None and observed > required`, which only
# fails on evidence of a breach. An archetype declaring a budget that nobody measured
# returned PASSED, and run_gate then signed a VSA saying so — false assurance carrying
# a signature, which is worse than no gate at all (ADR-013 §6). The version comparisons
# in mTLS and db-driver already got this right; it simply was not applied uniformly.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("check", [
    {"kind": CHECK_RESOURCE, "name": "mem", "spec": {"max_memory_mb": 512}, "evidence": {}},
    {"kind": CHECK_RESOURCE, "name": "cpu", "spec": {"max_cpu_millicores": 500}, "evidence": {}},
    {"kind": CHECK_SYNTHETIC, "name": "lat", "spec": {"max_latency_ms": 200},
     "evidence": {"status": "ok"}},
    {"kind": CHECK_MTLS, "name": "cipher", "spec": {"allowed_ciphers": ["TLS_AES_256"]},
     "evidence": {}},
    {"kind": CHECK_MTLS, "name": "tls", "spec": {"min_tls_version": "1.2"}, "evidence": {}},
    {"kind": CHECK_DB_DRIVER, "name": "ver", "spec": {"min_version": "8.0"},
     "evidence": {"driver": "mysql"}},
])
def test_a_declared_requirement_with_no_measurement_fails(check):
    outcome = run_check(check)
    assert not outcome.passed
    assert "not observed" in outcome.detail


@pytest.mark.parametrize("check", [
    {"kind": CHECK_RESOURCE, "name": "r", "spec": {}, "evidence": {}},
    {"kind": CHECK_SYNTHETIC, "name": "s", "spec": {}, "evidence": {}},
    {"kind": CHECK_MTLS, "name": "m", "spec": {}, "evidence": {}},
    {"kind": CHECK_DB_DRIVER, "name": "d", "spec": {}, "evidence": {}},
])
def test_a_check_declaring_nothing_still_passes(check):
    # The rule is "declared but unmeasured fails", not "empty evidence fails". An
    # archetype that asserts no budget on a dimension is not asking for a measurement.
    assert run_check(check).passed


def test_an_unmeasured_dimension_fails_the_whole_gate_and_quarantines():
    result = run_gate(
        artifact=artifact_descriptor("pkg:oci/app@sha256:" + "a" * 64, "a" * 64),
        suite=suite_descriptor("suite@v1", content={"personas": 1}),
        checks=[
            {"kind": CHECK_MTLS, "name": "ok", "spec": {"min_tls_version": "1.2"},
             "evidence": {"negotiated_tls_version": "1.3"}},
            {"kind": CHECK_RESOURCE, "name": "unmeasured",
             "spec": {"max_memory_mb": 512}, "evidence": {}},
        ],
        time_verified=FIXED_TIME,
    )
    assert result.result == RESULT_FAILED
    assert result.quarantine is not None
    assert [o.name for o in result.failed_checks()] == ["unmeasured"]
