"""MP-55 — REQUIREMENTS_NEWER_THAN_CODE and the `realizes` predicate (ADR-015 §2–3).

The finding is one line of routing, and the routing is the entire point.

Before MP-55, `evaluate_artifacts` classified *every* changed plane dependency as
`autonomic / recompile`. That is correct for a control: recompiling converges enforcement
toward current authoring, and it is reversible. It is wrong for a requirement, because the
convergent act there is **regenerating an application** — which changes running software and
expands risk somewhere else.

So the observation is identical and the authority is not. Same inversion as MP-11
(`ORPHANED_POLICY`) and MP-36 (`ARCHETYPES_NEWER_THAN_PROMOTION`), and the failure mode if
the routing is ever removed is not a wrong label: it is a machine authorised to regenerate
an application unattended.
"""
from __future__ import annotations

import pytest

from calm_forge.cross_plane_drift import (
    AUTONOMIC,
    CONTROLS_NEWER_THAN_POLICY,
    GOVERNED,
    ORPHANED_POLICY,
    REMEDIATION_RECOMPILE,
    REMEDIATION_REGENERATE,
    REQUIREMENTS_NEWER_THAN_CODE,
    evaluate_artifacts,
)
from calm_forge.intake_requirements import (
    PREDICATE_REALIZES,
    intake_requirements,
    realized_by,
)
from calm_forge.kg_plane import PLANE_REQUIREMENTS, PREDICATE_GOVERNS

REQ = "kg://requirements/requirement/pay-record"
TARGET_STATE = "kg://requirements/target-state/zero-trust"
CONTROL = "kg://oscal/control/AC-2/imp-req-1"
AS_READ = "a" * 64
MOVED = "sha256:" + "b" * 64


def statement(*uris, name="app.py"):
    return {
        "subject": [{"name": name}],
        "predicate": {"buildDefinition": {"resolvedDependencies": [
            {"uri": uri, "digest": {"sha256": AS_READ}} for uri in uris
        ]}},
    }


# ---------------------------------------------------------------------------
# The routing
# ---------------------------------------------------------------------------

def test_a_changed_requirement_is_governed_not_autonomic():
    (finding,) = evaluate_artifacts([statement(REQ)], {REQ: MOVED})
    assert finding.finding_type == REQUIREMENTS_NEWER_THAN_CODE
    assert finding.authority_class == GOVERNED
    assert finding.remediation == REMEDIATION_REGENERATE
    assert finding.plane == PLANE_REQUIREMENTS


def test_a_changed_control_stays_autonomic():
    # The routing must not have widened into "everything is governed now".
    (finding,) = evaluate_artifacts([statement(CONTROL)], {CONTROL: MOVED})
    assert finding.finding_type == CONTROLS_NEWER_THAN_POLICY
    assert finding.authority_class == AUTONOMIC
    assert finding.remediation == REMEDIATION_RECOMPILE


def test_a_changed_target_state_routes_the_same_way_as_a_requirement():
    # Both are requirements-plane intent; generating from either changes software.
    (finding,) = evaluate_artifacts([statement(TARGET_STATE)], {TARGET_STATE: MOVED})
    assert finding.finding_type == REQUIREMENTS_NEWER_THAN_CODE
    assert finding.authority_class == GOVERNED


def test_one_artifact_can_raise_both_findings_with_different_authorities():
    findings = evaluate_artifacts([statement(REQ, CONTROL)], {REQ: MOVED, CONTROL: MOVED})
    by_type = {f.finding_type: f for f in findings}
    assert by_type[REQUIREMENTS_NEWER_THAN_CODE].authority_class == GOVERNED
    assert by_type[CONTROLS_NEWER_THAN_POLICY].authority_class == AUTONOMIC


def test_an_unchanged_requirement_raises_nothing():
    assert evaluate_artifacts([statement(REQ)], {REQ: f"sha256:{AS_READ}"}) == []


def test_the_finding_carries_both_digests_as_evidence():
    (finding,) = evaluate_artifacts([statement(REQ)], {REQ: MOVED})
    assert finding.evidence == {"version_as_read": f"sha256:{AS_READ}",
                                "current_version": MOVED}


def test_comparison_is_by_content_not_by_order_or_clock():
    # Nothing in the finding depends on when it was evaluated.
    first = evaluate_artifacts([statement(REQ)], {REQ: MOVED})
    second = evaluate_artifacts([statement(REQ)], {REQ: MOVED})
    assert [f.to_dict() for f in first] == [f.to_dict() for f in second]


def test_a_deleted_requirement_still_lands_in_the_governed_orphan_branch():
    # ADR-015 names only REQUIREMENTS_NEWER_THAN_CODE, so the deleted case keeps the
    # generic finding rather than inventing a name outside an ADR. The behaviour is
    # right either way: governed, escalate — code outliving the intent that begat it.
    (finding,) = evaluate_artifacts([statement(REQ)], {})
    assert finding.finding_type == ORPHANED_POLICY
    assert finding.authority_class == GOVERNED


@pytest.mark.parametrize("uri", [
    "kg://oscal/control/AC-2/imp-1",
    "kg://tosca/policy/t/p",
    "kg://openlineage/dataset/wh/tbl",
    "kg://odcs/contract/c",
])
def test_no_other_plane_is_captured_by_the_requirements_route(uri):
    (finding,) = evaluate_artifacts([statement(uri)], {uri: MOVED})
    assert finding.finding_type == CONTROLS_NEWER_THAN_POLICY


def test_file_dependencies_are_not_cross_plane_subjects():
    stmt = {"subject": [{"name": "app.py"}], "predicate": {"buildDefinition": {
        "resolvedDependencies": [{"uri": "file://spec.yaml", "digest": {"sha256": AS_READ}}]}}}
    assert evaluate_artifacts([stmt], {}) == []


# ---------------------------------------------------------------------------
# The predicate
# ---------------------------------------------------------------------------

def test_realizes_is_in_the_typed_predicate_vocabulary_beside_governs():
    # ADR-015 §2 makes it an MP-08 amendment, not an intake-local string.
    assert PREDICATE_REALIZES == "realizes"
    assert PREDICATE_GOVERNS == "governs"
    assert PREDICATE_REALIZES != PREDICATE_GOVERNS


def test_realizes_edges_store_no_plane():
    # An edge's plane is its authoring node's. Storing one creates a derivable value
    # that can disagree with its source.
    result = intake_requirements({
        "requirements_schema": "0.1",
        "target_states": [{"id": "ts:x", "node_class": "authored", "plane": "requirements",
                           "assertions": {"a": 1}, "realizes": ["kg://odcs/contract/c"]}],
    })
    (edge,) = result["edges"]
    assert set(edge) == {"@type", "from", "to"}
    assert edge["@type"] == PREDICATE_REALIZES


def test_the_generative_chain_joins_intent_to_artifact():
    # requirement --realizes--> contract, and the artifact's provenance names the
    # requirement. "Why does this code exist" and "why does this edge exist" meet here.
    result = intake_requirements({
        "requirements_schema": "0.1",
        "actors": [{"id": "actor:c", "node_class": "authored", "plane": "requirements",
                    "name": "C", "kind": "human"}],
        "requirements": [{"id": "req:pay/record", "node_class": "authored",
                          "plane": "requirements", "actor": "actor:c", "story": "s",
                          "status": "draft", "realizes": ["kg://odcs/contract/c"]}],
    })
    (node,) = result["requirement_nodes"]
    assert realized_by(node, result["edges"]) == ["kg://odcs/contract/c"]

    (finding,) = evaluate_artifacts([statement(node["@id"])], {node["@id"]: MOVED})
    assert finding.finding_type == REQUIREMENTS_NEWER_THAN_CODE
