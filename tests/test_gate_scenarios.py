"""MP-38 — the seven ADR-013 Follow-up gate-check scenarios.

These are not new behaviours. They compose MP-32 through MP-36 and pin the
runbook that is easy to get backwards: when the gate is down, promotion fails
closed and quarantine fails open. Scenario 8 exercises the MP-36 review
correction — an uncomparable standing promotion is a finding, not silence.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.cross_plane_drift import (
    ARCHETYPES_NEWER_THAN_PROMOTION,
    GOVERNED,
    evaluate_promotions,
)
from calm_forge.gate_admission import AdmissionError, admit, countersign_envelope
from calm_forge.gate_runner import (
    ACTION_PROMOTION,
    ACTION_QUARANTINE,
    AUTONOMIC_CONTRACTION,
    RESULT_FAILED,
    RESULT_PASSED,
    GateError,
    artifact_descriptor,
    quarantine_record,
    run_gate,
    suite_descriptor,
    unavailable_allows,
)
from calm_forge.intake_archetypes import SCHEMA_KEY, digestable_suite, intake_archetypes
from calm_forge.passport import generate_keypair, public_key_b64
from calm_forge.provenance import verify_envelope
from calm_forge.registry_intake import diff_drops, intake_drop, select_affected_archetypes

_SC = Path(__file__).resolve().parents[1] / "examples" / "supply-chain"
_DIGEST = "e9" * 32
_ARTIFACT = artifact_descriptor("registry.example/payments/api", f"sha256:{_DIGEST}")
_ANCHOR = "kg://anchor/APP-10432"
_HUMAN = {
    "@id": _ANCHOR,
    "@type": "AccountabilityAnchor",
    "node_class": "reference",
    "accountable_for": {"id": "E44921", "identity_class": "human"},
}


def _check(*, passed: bool = True, archetype: str = "go-strict-tls") -> dict:
    return {
        "name": "mtls",
        "kind": "mtls_handshake",
        "archetype": archetype,
        "spec": {"min_tls_version": "1.3", "require_mutual": True},
        "evidence": {
            "negotiated_tls_version": "1.3" if passed else "1.1",
            "mutual": True,
        },
    }


def _suite_content() -> dict:
    return digestable_suite("v0", [])


def _signed_pass(*, key=None, passed: bool = True):
    key = key or generate_keypair()
    result = run_gate(
        artifact=_ARTIFACT,
        suite=suite_descriptor(
            "kg://supply_chain/archetype-suite/v0", content=_suite_content()
        ),
        checks=[_check(passed=passed)],
        key=key,
    )
    return key, result


def _countersigned(result, human_key=None):
    human_key = human_key or generate_keypair()
    envelope = countersign_envelope(result.envelope, human_key, anchor_ref=_ANCHOR)
    return human_key, envelope


# ---------------------------------------------------------------------------
# (1) drop → affected archetypes selected from the N→N±1 diff
# ---------------------------------------------------------------------------


def test_scenario_1_drop_selects_affected_archetypes_from_the_diff() -> None:
    before = intake_drop(
        json.loads((_SC / "drop-n.cyclonedx.json").read_text()),
        image_ref="n", image_digest="sha256:" + "aa" * 32,
    )
    after = intake_drop(
        json.loads((_SC / "drop-n1.cyclonedx.json").read_text()),
        image_ref="n1", image_digest="sha256:" + "bb" * 32,
    )
    surfaces = json.loads((_SC / "archetype-suite.json").read_text())
    affected = select_affected_archetypes(diff_drops(before, after), surfaces["archetypes"])
    assert affected == ["go-strict-tls", "java-spring-heavy"]
    assert "static-html" not in affected


# ---------------------------------------------------------------------------
# (2) pass → VSA verifies with stock tooling
# ---------------------------------------------------------------------------


def test_scenario_2_a_passing_gate_vsa_verifies_with_stock_dsse() -> None:
    key, result = _signed_pass()
    assert result.result == RESULT_PASSED
    assert result.quarantine is None
    assert verify_envelope(result.envelope, public_key_b64(key))


# ---------------------------------------------------------------------------
# (3) fail → quarantine record, no promotion path
# ---------------------------------------------------------------------------


def test_scenario_3_a_failing_gate_quarantines_and_cannot_be_admitted() -> None:
    gate_key, result = _signed_pass(passed=False)
    assert result.result == RESULT_FAILED
    assert result.quarantine is not None
    assert result.quarantine["authority_class"] == AUTONOMIC_CONTRACTION
    human_key, envelope = _countersigned(result)
    with pytest.raises(AdmissionError, match="FAILED"):
        admit(
            envelope,
            gate_public_key_b64=public_key_b64(gate_key),
            countersigner_public_key_b64=public_key_b64(human_key),
            pull_ref=f"registry.example/payments/api@sha256:{_DIGEST}",
            anchors=[_HUMAN],
        )


# ---------------------------------------------------------------------------
# (4) Tier 2→3 requires a countersignature that resolves to a human
# ---------------------------------------------------------------------------


def test_scenario_4_tier3_requires_a_human_countersignature() -> None:
    gate_key, result = _signed_pass()
    human_key, envelope = _countersigned(result)
    decision = admit(
        envelope,
        gate_public_key_b64=public_key_b64(gate_key),
        countersigner_public_key_b64=public_key_b64(human_key),
        pull_ref=f"registry.example/payments/api@sha256:{_DIGEST}",
        anchors=[_HUMAN],
    )
    assert decision.admitted
    assert decision.anchor_ref == _ANCHOR

    with pytest.raises(AdmissionError, match="countersignature"):
        admit(
            result.envelope,  # gate signature only
            gate_public_key_b64=public_key_b64(gate_key),
            countersigner_public_key_b64=public_key_b64(human_key),
            pull_ref=f"registry.example/payments/api@sha256:{_DIGEST}",
            anchors=[_HUMAN],
        )


# ---------------------------------------------------------------------------
# (5) suite version bump → standing VSAs flagged
# ---------------------------------------------------------------------------


def test_scenario_5_a_suite_bump_flags_standing_promotions() -> None:
    _, result = _signed_pass()
    tightened = intake_archetypes({
        SCHEMA_KEY: "0.1",
        "suite_version": "v0",
        "archetypes": [{
            "name": "fixture-persona",
            "coverage": {
                "workload_classes": [{"class": "payments-java-api", "count": 1}],
                "basis": "scenario fixture, not an inventory join",
            },
        }],
    })["supply_chain_nodes"]
    (finding,) = evaluate_promotions([result.vsa], tightened)
    assert finding.finding_type == ARCHETYPES_NEWER_THAN_PROMOTION
    assert finding.authority_class == GOVERNED
    assert finding.evidence["comparable"] is True


# ---------------------------------------------------------------------------
# (6) tag-based production pull → admission rejection
# ---------------------------------------------------------------------------


def test_scenario_6_a_tag_pull_is_refused_even_when_the_chain_is_valid() -> None:
    gate_key, result = _signed_pass()
    human_key, envelope = _countersigned(result)
    with pytest.raises(AdmissionError, match="digest pin"):
        admit(
            envelope,
            gate_public_key_b64=public_key_b64(gate_key),
            countersigner_public_key_b64=public_key_b64(human_key),
            pull_ref="registry.example/payments/api:latest",
            anchors=[_HUMAN],
        )


# ---------------------------------------------------------------------------
# (7) gate unavailable → promotion fails closed, quarantine fails open
# ---------------------------------------------------------------------------


def test_scenario_7_unavailable_gate_blocks_promotion_and_still_quarantines() -> None:
    assert unavailable_allows(ACTION_PROMOTION) is False
    assert unavailable_allows(ACTION_QUARANTINE) is True

    gate_key, result = _signed_pass()
    human_key, envelope = _countersigned(result)
    with pytest.raises(AdmissionError, match="gate unavailable"):
        admit(
            envelope,
            gate_public_key_b64=public_key_b64(gate_key),
            countersigner_public_key_b64=public_key_b64(human_key),
            pull_ref=f"registry.example/payments/api@sha256:{_DIGEST}",
            anchors=[_HUMAN],
            gate_available=False,
        )

    # Fail open: a down gate must not prevent refusing exposure.
    record = quarantine_record(_ARTIFACT, result.suite, result.outcomes)
    assert record["authority_class"] == AUTONOMIC_CONTRACTION
    assert record["disposition"] == "quarantined"

    with pytest.raises(GateError, match="unknown gate action"):
        unavailable_allows("wave-through")


# ---------------------------------------------------------------------------
# Uncomparable standing promotion (MP-36 review correction; MP-57 names it later)
# ---------------------------------------------------------------------------


def test_scenario_uncomparable_passed_vsa_is_a_finding_not_silence() -> None:
    _, result = _signed_pass()
    unpinned = copy.deepcopy(result.vsa)
    unpinned["predicate"]["policy"].pop("digest")
    docs = intake_archetypes({
        SCHEMA_KEY: "0.1", "suite_version": "v0", "archetypes": [],
    })["supply_chain_nodes"]
    (finding,) = evaluate_promotions([unpinned], docs)
    assert finding.evidence["comparable"] is False
    assert finding.authority_class == GOVERNED


def test_cli_admit_refuses_when_the_gate_is_unavailable(tmp_path: Path) -> None:
    runner = CliRunner()
    spec = {
        "artifact": {"uri": "registry.example/payments/api", "digest": {"sha256": _DIGEST}},
        "suite": {
            "uri": "kg://supply_chain/archetype-suite/v0",
            "content": _suite_content(),
        },
        "checks": [_check()],
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
        "--anchor-ref", _ANCHOR,
        "--output", str(countersigned),
    ])
    assert cs.exit_code == 0, cs.output

    anchors = tmp_path / "anchors.json"
    anchors.write_text(json.dumps([_HUMAN]))
    refused = runner.invoke(cli, [
        "gate", "admit",
        "--envelope", str(countersigned),
        "--gate-key", str(gate_key),
        "--countersigner-key", str(human_key),
        "--pull", f"registry.example/payments/api@sha256:{_DIGEST}",
        "--anchors", str(anchors),
        "--gate-unavailable",
    ])
    assert refused.exit_code != 0
    assert "gate unavailable" in refused.output
