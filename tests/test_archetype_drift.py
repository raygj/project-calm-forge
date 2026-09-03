"""MP-36 — ARCHETYPES_NEWER_THAN_PROMOTION (ADR-013 §4).

Flagging is a digest read and is automatic. Acting — re-validation or demotion — is
governed, because pulling a production artifact expands risk elsewhere. Same inversion
as MP-11 and MP-55: the observation is cheap, the act is not, and authority_class
names the act.
"""

from __future__ import annotations

from calm_forge.cross_plane_drift import (
    ARCHETYPES_NEWER_THAN_PROMOTION,
    GOVERNED,
    REMEDIATION_ESCALATE,
    evaluate,
    evaluate_promotions,
)
from calm_forge.gate_runner import artifact_descriptor, run_gate, suite_descriptor
from calm_forge.intake_archetypes import (
    SCHEMA_KEY,
    digestable_suite,
    intake_archetypes,
    suite_digest,
)
from calm_forge.kg_plane import PLANE_SUPPLY_CHAIN

_EMPTY = {SCHEMA_KEY: "0.1", "suite_version": "v0", "archetypes": []}
_ONE = {
    SCHEMA_KEY: "0.1",
    "suite_version": "v0",
    "archetypes": [{
        "name": "fixture-persona",
        "coverage": {
            "workload_classes": [{"class": "payments-java-api", "count": 1}],
            "basis": "unit-test fixture, not an inventory join",
        },
    }],
}


def _docs(document: dict) -> list[dict]:
    result = intake_archetypes(document)
    return result["supply_chain_nodes"]


def _vsa(suite_content, *, passed: bool = True, archetypes: list[str] | None = None):
    check = {
        "name": "mtls",
        "kind": "mtls_handshake",
        "archetype": (archetypes or ["fixture-persona"])[0],
        "spec": {"min_tls_version": "1.3", "require_mutual": True},
        "evidence": {
            "negotiated_tls_version": "1.3" if passed else "1.1",
            "mutual": True,
        },
    }
    uri = "kg://supply_chain/archetype-suite/v0"
    result = run_gate(
        artifact=artifact_descriptor("registry.example/payments/api", "ab" * 32),
        suite=suite_descriptor(uri, content=suite_content),
        checks=[check],
    )
    return result.vsa


# ---------------------------------------------------------------------------
# The finding
# ---------------------------------------------------------------------------


def test_a_tightened_suite_flags_a_standing_promotion() -> None:
    vsa = _vsa(digestable_suite("v0", []))
    (finding,) = evaluate_promotions([vsa], _docs(_ONE))
    assert finding.finding_type == ARCHETYPES_NEWER_THAN_PROMOTION
    assert finding.authority_class == GOVERNED
    assert finding.remediation == REMEDIATION_ESCALATE
    assert finding.plane == PLANE_SUPPLY_CHAIN
    assert finding.subject == "registry.example/payments/api"


def test_matching_digests_raise_nothing() -> None:
    docs = _docs(_EMPTY)
    payload = digestable_suite("v0", [])
    assert suite_digest("v0", []) == suite_descriptor(
        "kg://unused", content=payload
    )["digest"]["sha256"]
    vsa = _vsa(payload)
    assert evaluate_promotions([vsa], docs) == []


def test_a_failed_vsa_is_not_a_promotion() -> None:
    vsa = _vsa(digestable_suite("v0", []), passed=False)
    assert evaluate_promotions([vsa], _docs(_ONE)) == []


def test_no_suite_in_the_graph_is_not_a_finding() -> None:
    # No current policy to be newer. Distinct from "policy moved".
    vsa = _vsa(digestable_suite("v0", []))
    assert evaluate_promotions([vsa], []) == []


def test_unresolvable_policy_uri_is_a_finding() -> None:
    vsa = _vsa(digestable_suite("v0", []))
    vsa["predicate"]["policy"]["uri"] = "kg://supply_chain/archetype-suite/gone"
    (finding,) = evaluate_promotions([vsa], _docs(_EMPTY))
    assert finding.finding_type == ARCHETYPES_NEWER_THAN_PROMOTION
    assert finding.evidence["current_suite_digest"] is None


def test_evaluated_archetypes_travel_as_evidence() -> None:
    vsa = _vsa(digestable_suite("v0", []), archetypes=["fixture-persona"])
    (finding,) = evaluate_promotions([vsa], _docs(_ONE))
    assert finding.evidence["evaluated_archetypes"] == ["fixture-persona"]
    assert "policy_digest_as_read" in finding.evidence
    assert finding.evidence["current_suite_digest"] != finding.evidence["policy_digest_as_read"]


def test_comparison_is_by_content_not_clock() -> None:
    vsa = _vsa(digestable_suite("v0", []))
    docs = _docs(_ONE)
    assert [f.to_dict() for f in evaluate_promotions([vsa], docs)] == (
        [f.to_dict() for f in evaluate_promotions([vsa], docs)]
    )


def test_wired_through_evaluate() -> None:
    vsa = _vsa(digestable_suite("v0", []))
    report = evaluate(_docs(_ONE), vsas=[vsa])
    types = [f.finding_type for f in report.findings]
    assert ARCHETYPES_NEWER_THAN_PROMOTION in types
    (finding,) = [f for f in report.findings if f.finding_type == ARCHETYPES_NEWER_THAN_PROMOTION]
    assert finding.authority_class == GOVERNED


# ---------------------------------------------------------------------------
# Uncomparable is not unchanged
# ---------------------------------------------------------------------------


def _unpin(vsa: dict, *, drop: str) -> dict:
    """Same PASSED VSA with its policy pin removed."""
    import copy

    stripped = copy.deepcopy(vsa)
    policy = stripped["predicate"]["policy"]
    if drop == "digest":
        policy.pop("digest", None)
    else:
        policy.pop("uri", None)
    return stripped


def test_a_passed_vsa_with_no_policy_digest_is_a_finding() -> None:
    """Skipping this would make an unpinned VSA the safest kind to hold."""
    vsa = _unpin(_vsa(digestable_suite("v0", [])), drop="digest")
    (finding,) = evaluate_promotions([vsa], _docs(_ONE))
    assert finding.finding_type == ARCHETYPES_NEWER_THAN_PROMOTION
    assert finding.authority_class == GOVERNED
    assert finding.remediation == REMEDIATION_ESCALATE
    assert finding.evidence["comparable"] is False
    assert "cannot be compared" in finding.detail


def test_a_passed_vsa_with_no_policy_uri_is_a_finding() -> None:
    vsa = _unpin(_vsa(digestable_suite("v0", [])), drop="uri")
    (finding,) = evaluate_promotions([vsa], _docs(_ONE))
    assert finding.evidence["comparable"] is False
    assert finding.node_id is None


def test_an_unpinned_failed_vsa_is_still_not_a_promotion() -> None:
    """Fail-closed on comparability must not resurrect quarantine records."""
    vsa = _unpin(_vsa(digestable_suite("v0", []), passed=False), drop="digest")
    assert evaluate_promotions([vsa], _docs(_ONE)) == []


def test_a_compared_finding_says_so() -> None:
    (finding,) = evaluate_promotions([_vsa(digestable_suite("v0", []))], _docs(_ONE))
    assert finding.evidence["comparable"] is True


def test_a_vanished_suite_reads_as_gone_not_as_changed() -> None:
    """`policy gone` and `policy superseded` are different facts to a human."""
    vsa = _vsa(digestable_suite("v0", []))
    vsa["predicate"]["policy"]["uri"] = "kg://supply_chain/archetype-suite/vanished"
    (finding,) = evaluate_promotions([vsa], _docs(_ONE))
    assert "no longer in the graph" in finding.detail
    assert finding.evidence["current_suite_digest"] is None
