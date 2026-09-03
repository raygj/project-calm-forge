"""Tier 3 admission — VSA chain + digest pin (MP-34, ADR-013 §1–3)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.gate_admission import (
    GOVERNED_EXPANSION,
    AdmissionError,
    admit,
    countersign_envelope,
    is_digest_pin,
    pull_digest,
)
from calm_forge.gate_runner import artifact_descriptor, run_gate, suite_descriptor
from calm_forge.passport import generate_keypair, public_key_b64
from calm_forge.provenance import verify_envelope

FIXED_TIME = datetime(2026, 8, 22, 12, 0, 0, tzinfo=timezone.utc)
_DIGEST = "e9" * 32
_ARTIFACT = artifact_descriptor("registry.example/payments/api", f"sha256:{_DIGEST}")
_SUITE = suite_descriptor("kg://supply_chain/archetype-suite/v1", content={"v": 1})
_ANCHOR_REF = "kg://anchor/APP-10432"
_HUMAN = {
    "@id": _ANCHOR_REF,
    "@type": "AccountabilityAnchor",
    "node_class": "reference",
    "accountable_for": {"id": "E44921", "identity_class": "human"},
}
_ROBOT = {
    "@id": _ANCHOR_REF,
    "@type": "AccountabilityAnchor",
    "node_class": "reference",
    "accountable_for": {"id": "FID-x", "identity_class": "functional_id"},
}


def _passing_check() -> dict:
    return {
        "name": "mtls",
        "kind": "mtls_handshake",
        "archetype": "go-strict-tls",
        "spec": {"min_tls_version": "1.3", "require_mutual": True},
        "evidence": {"negotiated_tls_version": "1.3", "mutual": True},
    }


def _failing_check() -> dict:
    check = _passing_check()
    check["evidence"] = {"negotiated_tls_version": "1.1", "mutual": True}
    return check


def _signed_vsa(key, *, passed: bool = True):
    result = run_gate(
        artifact=_ARTIFACT,
        suite=_SUITE,
        checks=[_passing_check() if passed else _failing_check()],
        key=key,
        time_verified=FIXED_TIME,
    )
    assert result.envelope is not None
    return result


# ---------------------------------------------------------------------------
# Digest pins
# ---------------------------------------------------------------------------


def test_digest_pin_accepts_name_at_sha256_and_bare_sha256() -> None:
    assert pull_digest(f"registry.example/payments/api@sha256:{_DIGEST}") == _DIGEST
    assert pull_digest(f"sha256:{_DIGEST}") == _DIGEST
    assert is_digest_pin(f"sha256:{_DIGEST}")


def test_tag_is_not_a_digest_pin() -> None:
    for ref in (
        "registry.example/payments/api:latest",
        "registry.example/payments/api:v1.2.3",
        "registry.example/payments/api",
    ):
        assert pull_digest(ref) is None
        assert not is_digest_pin(ref)


# ---------------------------------------------------------------------------
# Countersign
# ---------------------------------------------------------------------------


def test_countersign_adds_a_second_signature_over_the_same_payload() -> None:
    gate_key = generate_keypair()
    human_key = generate_keypair()
    result = _signed_vsa(gate_key)
    signed = countersign_envelope(result.envelope, human_key, anchor_ref=_ANCHOR_REF)
    assert len(signed["signatures"]) == 2
    assert signed["payload"] == result.envelope["payload"]
    assert signed["signatures"][1]["anchor_ref"] == _ANCHOR_REF
    assert verify_envelope(signed, public_key_b64(gate_key))
    assert verify_envelope(signed, public_key_b64(human_key))


def test_countersign_rejects_a_name_that_is_not_an_anchor_ref() -> None:
    result = _signed_vsa(generate_keypair())
    with pytest.raises(AdmissionError, match="kg://anchor"):
        countersign_envelope(
            result.envelope, generate_keypair(), anchor_ref="alice@example.com"
        )


def test_same_key_cannot_countersign_its_own_gate_vsa() -> None:
    key = generate_keypair()
    result = _signed_vsa(key)
    with pytest.raises(AdmissionError, match="two parties"):
        countersign_envelope(result.envelope, key, anchor_ref=_ANCHOR_REF)


# ---------------------------------------------------------------------------
# Admit
# ---------------------------------------------------------------------------


def _admit(envelope, gate_key, human_key, pull=None, anchors=None):
    return admit(
        envelope,
        gate_public_key_b64=public_key_b64(gate_key),
        countersigner_public_key_b64=public_key_b64(human_key),
        pull_ref=pull or f"registry.example/payments/api@sha256:{_DIGEST}",
        anchors=anchors if anchors is not None else [_HUMAN],
    )


def test_admit_passes_a_countersigned_passed_vsa_on_a_digest_pin() -> None:
    gate_key = generate_keypair()
    human_key = generate_keypair()
    result = _signed_vsa(gate_key)
    signed = countersign_envelope(result.envelope, human_key, anchor_ref=_ANCHOR_REF)
    decision = _admit(signed, gate_key, human_key)
    assert decision.admitted
    assert decision.authority_class == GOVERNED_EXPANSION
    assert decision.subject_digest == _DIGEST
    assert decision.anchor_ref == _ANCHOR_REF
    assert decision.policy_digest == _SUITE["digest"]["sha256"]


def test_tag_pull_is_rejected_even_when_the_chain_is_valid() -> None:
    gate_key = generate_keypair()
    human_key = generate_keypair()
    signed = countersign_envelope(
        _signed_vsa(gate_key).envelope, human_key, anchor_ref=_ANCHOR_REF
    )
    with pytest.raises(AdmissionError, match="digest pin"):
        _admit(signed, gate_key, human_key, pull="registry.example/payments/api:latest")


def test_failed_vsa_cannot_be_admitted() -> None:
    gate_key = generate_keypair()
    human_key = generate_keypair()
    signed = countersign_envelope(
        _signed_vsa(gate_key, passed=False).envelope, human_key, anchor_ref=_ANCHOR_REF
    )
    with pytest.raises(AdmissionError, match="FAILED"):
        _admit(signed, gate_key, human_key)


def test_missing_countersignature_is_rejected() -> None:
    gate_key = generate_keypair()
    human_key = generate_keypair()
    with pytest.raises(AdmissionError, match="countersignature"):
        _admit(_signed_vsa(gate_key).envelope, gate_key, human_key)


def test_wrong_pull_digest_is_rejected() -> None:
    gate_key = generate_keypair()
    human_key = generate_keypair()
    signed = countersign_envelope(
        _signed_vsa(gate_key).envelope, human_key, anchor_ref=_ANCHOR_REF
    )
    other = "ab" * 32
    with pytest.raises(AdmissionError, match="does not match"):
        _admit(signed, gate_key, human_key, pull=f"sha256:{other}")


def test_unresolvable_anchor_is_rejected() -> None:
    gate_key = generate_keypair()
    human_key = generate_keypair()
    signed = countersign_envelope(
        _signed_vsa(gate_key).envelope, human_key, anchor_ref=_ANCHOR_REF
    )
    with pytest.raises(AdmissionError, match="does not resolve"):
        _admit(signed, gate_key, human_key, anchors=[])


def test_non_human_accountable_for_is_rejected() -> None:
    gate_key = generate_keypair()
    human_key = generate_keypair()
    signed = countersign_envelope(
        _signed_vsa(gate_key).envelope, human_key, anchor_ref=_ANCHOR_REF
    )
    with pytest.raises(AdmissionError, match="associated_with"):
        _admit(signed, gate_key, human_key, anchors=[_ROBOT])


def test_forged_gate_signature_is_rejected() -> None:
    gate_key = generate_keypair()
    human_key = generate_keypair()
    signed = countersign_envelope(
        _signed_vsa(gate_key).envelope, human_key, anchor_ref=_ANCHOR_REF
    )
    with pytest.raises(AdmissionError, match="automated VSA"):
        _admit(signed, generate_keypair(), human_key)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_countersign_and_admit(tmp_path: Path) -> None:
    runner = CliRunner()
    spec = {
        "artifact": {"uri": "registry.example/payments/api", "digest": {"sha256": _DIGEST}},
        "suite": {"uri": "kg://supply_chain/archetype-suite/v1", "content": {"v": 1}},
        "checks": [_passing_check()],
    }
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec))
    gate_key = tmp_path / "gate.pem"
    out = tmp_path / "gate"
    run = runner.invoke(cli, [
        "gate", "run", "--spec", str(spec_path),
        "--output-dir", str(out), "--key", str(gate_key),
    ])
    assert run.exit_code == 0, run.output

    human_key = tmp_path / "human.pem"
    countersigned = tmp_path / "vsa.countersigned.json"
    cs = runner.invoke(cli, [
        "gate", "countersign",
        "--envelope", str(out / "vsa.slsa.dsse.json"),
        "--key", str(human_key),
        "--anchor-ref", _ANCHOR_REF,
        "--output", str(countersigned),
    ])
    assert cs.exit_code == 0, cs.output

    anchors = tmp_path / "anchors.json"
    anchors.write_text(json.dumps([_HUMAN]))
    admitted = runner.invoke(cli, [
        "gate", "admit",
        "--envelope", str(countersigned),
        "--gate-key", str(gate_key),
        "--countersigner-key", str(human_key),
        "--pull", f"registry.example/payments/api@sha256:{_DIGEST}",
        "--anchors", str(anchors),
    ])
    assert admitted.exit_code == 0, admitted.output
    assert "ADMITTED" in admitted.output

    tagged = runner.invoke(cli, [
        "gate", "admit",
        "--envelope", str(countersigned),
        "--gate-key", str(gate_key),
        "--countersigner-key", str(human_key),
        "--pull", "registry.example/payments/api:latest",
        "--anchors", str(anchors),
    ])
    assert tagged.exit_code != 0
    assert "digest pin" in tagged.output
