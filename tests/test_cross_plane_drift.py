"""Cross-plane drift — MP-10..MP-15 (ADR-005 follow-ups, ADR-007 §4).

The failure class under test is compositional: every artifact individually valid while
the estate is wrong. Two authority-class inversions are pinned hard because both are
what a competent implementer reaches for and gets backwards:

* ``ORPHANED_POLICY`` is a **governed** contraction — removal looks autonomic and isn't.
* ``STALE_ATTESTATION`` resolves by **re-issue**, not revoke — different subject.
"""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.cross_plane_drift import (
    AUTONOMIC,
    CONTROLS_NEWER_THAN_POLICY,
    GOVERNED,
    ORPHANED_POLICY,
    PLANE_MISSING,
    REMEDIATION_ESCALATE,
    REMEDIATION_RECOMPILE,
    REMEDIATION_REISSUE,
    STALE_ATTESTATION,
    evaluate,
    evaluate_artifacts,
    evaluate_passports,
)
from calm_forge.kg_plane import node_versions, plane_node_version
from calm_forge.passport import build_passport, generate_keypair
from calm_forge.provenance import build_provenance, subject

CONTROL_ID = "kg://oscal/control/AC-3/imp-req-ac3-e7f2"

_EDGE = {
    "source_workload": "web", "source_workload_urn": "wl:app/web",
    "destination_workload": "api", "destination_workload_urn": "wl:app/api",
    "source_spiffe_id": "spiffe://prod.fsi/ns/app/sa/web",
    "transport": "tcp", "direction": "egress", "port": 8443,
}
_INTENT = {
    "business_justification": "web calls api",
    "environment": "development",
    "requested_by": "spiffe://prod.fsi/ns/app/sa/web",
}


def _control_node(strength="AES-256"):
    return {
        "@id": CONTROL_ID, "@type": "Policy",
        "node_class": "authored", "plane": "controls",
        "allowed_encryption_algorithms": [strength],
    }


def _doc(*nodes):
    return {"@id": "workload:app:v1", "node_class": "authored",
            "plane": "architecture", "policies": list(nodes)}


def _artifact_provenance(node, name="sentinel/policies.sentinel"):
    """Provenance for an artifact compiled against ``node`` at its current version."""
    version = plane_node_version(node)
    return build_provenance(
        [subject(name, "policy text")],
        [{"uri": node["@id"], "digest": {"sha256": version.split(":", 1)[1]}}],
        external_parameters={"policy_framework": "sentinel"},
    )


def _v2_passport(plane_refs, plane_nodes=None, environment="development", validate=True):
    return build_passport(
        _EDGE, {**_INTENT, "environment": environment},
        generate_keypair(), "spiffe://prod.fsi/ns/platform/sa/calm-forge",
        issued_at=1, expires_at=2, version="0.2",
        plane_refs=plane_refs, plane_nodes=plane_nodes, validate=validate,
    )


# ---------------------------------------------------------------------------
# MP-10 — CONTROLS_NEWER_THAN_POLICY
# ---------------------------------------------------------------------------

def test_no_drift_when_the_node_has_not_changed():
    node = _control_node()
    report = evaluate([_doc(node)], [_artifact_provenance(node)], [])
    assert report.findings == []


def test_touched_but_unchanged_node_is_not_drift():
    """The no-op-edit case. A clock comparison fires here and floods the estate with
    false recompile findings; a content comparison does not."""
    node = _control_node()
    prov = _artifact_provenance(node)

    reserialized = json.loads(json.dumps(node))  # same content, new object
    report = evaluate([_doc(reserialized)], [prov], [])

    assert report.findings == []


def test_tightened_catalog_produces_a_recompile_finding():
    """The §4 parameter-injection case: one catalog edit, enforcement not yet followed."""
    prov = _artifact_provenance(_control_node("AES-256"))
    tightened = _control_node("AES-128")

    findings = evaluate_artifacts([prov], node_versions([_doc(tightened)]))

    assert [f.finding_type for f in findings] == [CONTROLS_NEWER_THAN_POLICY]
    assert findings[0].node_id == CONTROL_ID
    assert findings[0].evidence["version_as_read"] != findings[0].evidence["current_version"]


def test_recompile_is_autonomic():
    """Converges enforcement toward current authoring: reversible, low authority."""
    prov = _artifact_provenance(_control_node("AES-256"))
    finding = evaluate_artifacts([prov], node_versions([_doc(_control_node("AES-128"))]))[0]

    assert finding.authority_class == AUTONOMIC
    assert finding.remediation == REMEDIATION_RECOMPILE


# ---------------------------------------------------------------------------
# MP-11 — ORPHANED_POLICY, the governed contraction
# ---------------------------------------------------------------------------

def test_revoked_source_produces_an_orphan_finding():
    prov = _artifact_provenance(_control_node())
    findings = evaluate_artifacts([prov], node_versions([_doc()]))  # control removed

    assert [f.finding_type for f in findings] == [ORPHANED_POLICY]
    assert findings[0].node_id == CONTROL_ID


def test_orphaned_policy_is_governed_not_autonomic():
    """The inversion. Removal *looks* like a contraction and contractions are normally
    autonomic — but the enforcement may be load-bearing even though its authorization
    lapsed, and the catalog revocation may itself be the error. If this test is failing
    because someone made it autonomic, that someone reasoned 'contraction is always
    autonomic' and was wrong."""
    prov = _artifact_provenance(_control_node())
    finding = evaluate_artifacts([prov], node_versions([_doc()]))[0]

    assert finding.authority_class == GOVERNED
    assert finding.remediation == REMEDIATION_ESCALATE


def test_file_inputs_are_not_cross_plane_subjects():
    """The crawl-stage CALM/decorator/catalog inputs ride as file:// URIs. They are
    compile inputs, not plane nodes, and must not be reported as orphaned just because
    the graph has no node for them."""
    prov = build_provenance(
        [subject("a.hcl", "x")],
        [{"uri": "file:///tmp/instantiation.json", "digest": {"sha256": "a" * 64}}],
        external_parameters={},
    )
    assert evaluate_artifacts([prov], {}) == []


# ---------------------------------------------------------------------------
# MP-13 — STALE_ATTESTATION, re-issue not revoke
# ---------------------------------------------------------------------------

def test_moved_referent_produces_a_stale_attestation():
    node = _control_node("AES-256")
    passport = _v2_passport(
        {"controls": {"node_id": CONTROL_ID, "source": "declared", "confidence": 1.0}},
        plane_nodes={CONTROL_ID: node},
    )
    findings, _ = evaluate_passports([passport], node_versions([_doc(_control_node("AES-128"))]))

    assert [f.finding_type for f in findings] == [STALE_ATTESTATION]
    assert findings[0].plane == "controls"


def test_stale_attestation_resolves_by_reissue_not_revoke():
    """The passport was never wrong; it is now *about the past*. Revoke asserts the
    edge lost authorization — a claim about a different subject. Routing staleness
    there turns routine re-attestation into spurious loss of a valid grant."""
    node = _control_node("AES-256")
    passport = _v2_passport(
        {"controls": {"node_id": CONTROL_ID, "source": "declared", "confidence": 1.0}},
        plane_nodes={CONTROL_ID: node},
    )
    finding = evaluate_passports(
        [passport], node_versions([_doc(_control_node("AES-128"))])
    )[0][0]

    assert finding.remediation == REMEDIATION_REISSUE
    assert finding.remediation != "revoke"
    assert finding.authority_class == AUTONOMIC


def test_unchanged_referent_is_not_stale():
    node = _control_node()
    passport = _v2_passport(
        {"controls": {"node_id": CONTROL_ID, "source": "declared", "confidence": 1.0}},
        plane_nodes={CONTROL_ID: node},
    )
    findings, _ = evaluate_passports([passport], node_versions([_doc(node)]))
    assert findings == []


def test_reference_without_a_node_version_is_not_reported_as_stale():
    """A passport issued before the emitter captured digests has no evidence either
    way. Reporting it stale would manufacture drift out of missing evidence.

    As of MP-43 (controls) and MP-46 (business_intent) the v0.2 schema requires
    node_version on those authored refs, so this shape no longer validates on emit — hence
    ``validate=False``. The evaluator's no-evidence rule is not thereby dead code: it is the
    ADR-006 §5 safety net that must keep holding for v0.2 passports issued before the
    tightening and for architecture, which stays optional (its node_id is the edge_id,
    already a content hash). An absent digest must never be read as freshness, whatever the
    schema now demands of new authored claims."""
    passport = _v2_passport(
        {"controls": {"node_id": CONTROL_ID, "source": "declared", "confidence": 1.0}},
        validate=False,
    )
    findings, _ = evaluate_passports([passport], node_versions([_doc(_control_node("X"))]))
    assert findings == []


def test_v0_1_passports_are_evaluated_for_staleness_only():
    """Asking a v0.1 passport for its controls plane would report every one of them as
    missing a plane the wire format cannot express."""
    v1 = build_passport(
        _EDGE, {**_INTENT, "environment": "production"},
        generate_keypair(), "spiffe://prod.fsi/ns/platform/sa/calm-forge",
        issued_at=1, expires_at=2,
    )
    findings, waivers = evaluate_passports([v1], {})
    assert findings == [] and waivers == []


# ---------------------------------------------------------------------------
# MP-12 / MP-15 — missing versus waived, kept distinct end to end
# ---------------------------------------------------------------------------

def test_missing_required_plane_is_a_governed_finding():
    passport = _v2_passport({}, environment="production")
    findings, _ = evaluate_passports([passport], {})

    missing = [f for f in findings if f.finding_type == PLANE_MISSING]
    assert {f.plane for f in missing} == {"controls", "business_intent"}
    assert all(f.authority_class == GOVERNED for f in missing)


def test_waived_plane_is_not_a_finding():
    """'Not here on purpose' is a governed statement, not a violation."""
    passport = _v2_passport(
        {"business_intent": {"absent": "policy", "waived_by": "platform/rule#1"}},
        environment="development",
    )
    findings, waivers = evaluate_passports([passport], {})

    assert [f.finding_type for f in findings] == []
    assert len(waivers) == 1
    assert waivers[0].plane == "business_intent"
    assert waivers[0].waived_by == "platform/rule#1"


def test_waivers_and_missing_planes_never_share_a_list():
    """MP-15: the two states must stay distinguishable everywhere an operator looks.
    Collapsing them at the reporting layer undoes ADR-005 §5 at exactly the surface
    where the distinction is supposed to do its work.

    Staged below production, where a waiver is legal — the emitter refuses to build a
    production passport carrying one at all (MP-04), so that combination cannot arise
    from this pipeline."""
    passport = _v2_passport(
        {"controls": {"absent": "policy", "waived_by": "platform/rule#1"}},
        environment="development",
    )
    policy = {"development": frozenset({"architecture", "controls", "business_intent"})}
    findings, waivers = evaluate_passports([passport], {}, required_planes=policy)

    waived_planes = {w.plane for w in waivers}
    missing_planes = {f.plane for f in findings if f.finding_type == PLANE_MISSING}
    assert waived_planes == {"controls"}
    assert missing_planes == {"business_intent"}
    assert not (waived_planes & missing_planes)


def test_report_partitions_by_authority_class():
    prov = _artifact_provenance(_control_node("AES-256"))
    report = evaluate([_doc(_control_node("AES-128"))], [prov], [])

    assert [f.finding_type for f in report.autonomic] == [CONTROLS_NEWER_THAN_POLICY]
    assert report.governed == []


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------

@pytest.fixture
def drift_tree(tmp_path):
    kg = tmp_path / "kg"
    kg.mkdir()
    (kg / "tightened.json").write_text(json.dumps({
        "@context": "c", "@type": "Workload", "@id": "workload:app:v1",
        "node_class": "authored", "plane": "architecture",
        "version": "1", "name": "app", "purpose": "p", "owner": "o",
        "_provenance": {"authored_by": "t", "authored_at": "2026-01-01T00:00:00Z"},
        "policies": [_control_node("AES-128")],
    }))
    prov = tmp_path / "provenance.slsa.json"
    prov.write_text(json.dumps(_artifact_provenance(_control_node("AES-256"))))
    return kg, prov


def test_cli_reports_drift_and_exits_zero_when_only_autonomic(drift_tree):
    kg, prov = drift_tree
    res = CliRunner().invoke(cli, [
        "kg", "drift", "--kg-dir", str(kg), "--provenance", str(prov),
    ])
    assert res.exit_code == 0, res.output
    assert CONTROLS_NEWER_THAN_POLICY in res.output
    assert "autonomic" in res.output


def test_cli_exits_nonzero_on_a_governed_finding(tmp_path):
    """Governed findings assert something is unauthorized or unauthored; acting on them
    changes what the fabric permits, so they fail a gate."""
    kg = tmp_path / "kg"
    kg.mkdir()
    (kg / "empty.json").write_text(json.dumps({
        "@context": "c", "@type": "Workload", "@id": "workload:app:v1",
        "node_class": "authored", "plane": "architecture",
        "version": "1", "name": "app", "purpose": "p", "owner": "o",
        "_provenance": {"authored_by": "t", "authored_at": "2026-01-01T00:00:00Z"},
        "policies": [],
    }))
    prov = tmp_path / "p.json"
    prov.write_text(json.dumps(_artifact_provenance(_control_node())))

    res = CliRunner().invoke(cli, [
        "kg", "drift", "--kg-dir", str(kg), "--provenance", str(prov),
    ])
    assert res.exit_code == 1
    assert ORPHANED_POLICY in res.output
    assert "GOVERNED" in res.output


def test_cli_clean_tree_says_so(tmp_path):
    kg = tmp_path / "kg"
    kg.mkdir()
    res = CliRunner().invoke(cli, ["kg", "drift", "--kg-dir", str(kg)])
    assert res.exit_code == 0
    assert "No cross-plane drift" in res.output


def test_cli_json_output_keeps_waivers_out_of_findings(drift_tree):
    kg, prov = drift_tree
    res = CliRunner().invoke(cli, [
        "kg", "drift", "--kg-dir", str(kg), "--provenance", str(prov), "--json",
    ])
    payload = json.loads(res.output)
    assert "findings" in payload and "waivers" in payload
    assert payload["counts"]["total"] == len(payload["findings"])


def test_report_helpers_serialize_and_select():
    prov = _artifact_provenance(_control_node("AES-256"))
    passport = _v2_passport(
        {"business_intent": {"absent": "policy", "waived_by": "platform/rule#1"}},
    )
    report = evaluate([_doc(_control_node("AES-128"))], [prov], [passport])

    assert [f.finding_type for f in report.of_type(CONTROLS_NEWER_THAN_POLICY)] == [
        CONTROLS_NEWER_THAN_POLICY
    ]
    assert report.of_type(ORPHANED_POLICY) == []

    payload = report.to_dict()
    assert payload["waivers"][0]["waived_by"] == "platform/rule#1"
    assert payload["counts"]["waivers"] == 1
