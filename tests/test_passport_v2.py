"""Passport v0.2 — wire-version dispatch, emission, and the production waiver rule.

MP-02 / MP-03 / MP-04 / MP-05 (ADR-006). The property the whole bump rests on is that
**edge identity does not move**: v0.2 relocates the architecture edge id from
``graph_ref.edge_id`` to ``graph_refs.architecture.node_id`` and changes nothing about
its value, so every join built on it survives.
"""
from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from calm_forge.passport import (
    PASSPORT_VERSION,
    PASSPORT_VERSION_V2,
    PlaneWaiverError,
    UnknownPassportVersion,
    build_passport,
    build_passport_body,
    edge_id_of,
    edges_from_calm_architecture,
    generate_keypair,
    graph_ref_for_plane,
    validate_passport,
    verify_passport,
)
from calm_forge.passport_diff import diff

ROOT = Path(__file__).parent.parent
APP_DIR = ROOT / "examples" / "attested-policy-passport"
V1_REF = APP_DIR / "payments-portal-web-to-api.passport.json"
V2_REF = APP_DIR / "payments-portal-web-to-api.v0.2.passport.json"

_EDGE = {
    "source_workload": "web", "source_workload_urn": "wl:app/web",
    "destination_workload": "api", "destination_workload_urn": "wl:app/api",
    "source_spiffe_id": "spiffe://prod.fsi/ns/app/sa/web",
    "destination_spiffe_id": "spiffe://prod.fsi/ns/app/sa/api",
    "transport": "tcp", "direction": "egress", "port": 8443,
    "port_source": "declared-interface",
}
_INTENT = {
    "business_justification": "web calls api",
    "environment": "production",
    "requested_by": "spiffe://prod.fsi/ns/app/sa/web",
}


def _body(**kw):
    return build_passport_body(_EDGE, _INTENT, issued_at=1, expires_at=2, **kw)


# ---------------------------------------------------------------------------
# MP-02 — dispatch, and the refusal to guess
# ---------------------------------------------------------------------------

def test_unknown_version_raises_rather_than_falling_back_to_v0_1():
    """The failure this guards is silent and expensive: a reader that defaults to the
    v0.1 branch sees no graph_ref on a v0.2 passport, reads the edge as unclaimed, and
    converts a valid grant into a phantom contraction candidate — an authorization
    quietly becoming a deletion recommendation."""
    future = {**_body(), "passport_version": "0.3"}
    with pytest.raises(UnknownPassportVersion, match="refusing to guess"):
        edge_id_of(future)
    with pytest.raises(UnknownPassportVersion, match="refusing to guess"):
        validate_passport(future)


def test_missing_version_is_unknown_not_assumed():
    """A real passport always carries passport_version — the schema requires it — so a
    body without one is malformed, not implicitly v0.1."""
    with pytest.raises(UnknownPassportVersion):
        edge_id_of({"graph_ref": {"edge_id": "kg://edges/v1/abc"}})


def test_edge_id_of_reads_both_versions():
    v1, v2 = _body(), _body(version=PASSPORT_VERSION_V2)
    assert edge_id_of(v1) == v1["graph_ref"]["edge_id"]
    assert edge_id_of(v2) == v2["graph_refs"]["architecture"]["node_id"]
    assert edge_id_of(v1) == edge_id_of(v2)


def test_graph_ref_for_plane_reads_both_versions():
    v1, v2 = _body(), _body(version=PASSPORT_VERSION_V2)
    assert graph_ref_for_plane(v1)["edge_id"] == edge_id_of(v1)
    assert graph_ref_for_plane(v2)["node_id"] == edge_id_of(v2)
    # v0.1 has no controls plane to report — and says so by absence, not by error
    assert graph_ref_for_plane(v1, "controls") == {}


def test_graph_ref_for_plane_reports_a_waived_plane_as_absent():
    """A waiver is not a reference. The accessor returns {} for both waived and
    unauthored planes; callers that need the distinction read graph_refs directly,
    because collapsing it here would undo ADR-005 §5."""
    body = _body(
        version=PASSPORT_VERSION_V2,
        plane_refs={"controls": {"absent": "policy", "waived_by": "platform/rule#1"}},
    )
    assert graph_ref_for_plane(body, "controls") == {}
    assert body["graph_refs"]["controls"]["absent"] == "policy"


def test_reverse_diff_joins_v0_1_and_v0_2_claims_on_the_same_edge():
    """The join key survives the bump: a v0.2 claim and a v0.1 claim for one edge are
    the same edge to the evaluator."""
    v2 = _body(version=PASSPORT_VERSION_V2)
    v2["claim"]["claim_type"] = "grant"
    flow = {
        "source": "wl:app/web", "destination": "wl:app/api",
        "transport": "tcp", "port": 8443,
    }
    report = diff([v2], [flow], now=1)
    assert [e.edge_id for e in report.conformant] == [edge_id_of(v2)]
    assert report.shadow == []


# ---------------------------------------------------------------------------
# MP-03 — emission
# ---------------------------------------------------------------------------

def test_v0_2_relocates_the_edge_id_without_changing_it():
    """ADR-006 §4: a wire-format relocation, not a re-identification."""
    assert _body()["graph_ref"]["edge_id"] == (
        _body(version=PASSPORT_VERSION_V2)["graph_refs"]["architecture"]["node_id"]
    )


def test_v0_2_body_has_no_singular_graph_ref_and_v0_1_has_no_plural():
    v1, v2 = _body(), _body(version=PASSPORT_VERSION_V2)
    assert "graph_refs" not in v1 and "graph_ref" in v1
    assert "graph_ref" not in v2 and "graph_refs" in v2


def test_emitter_refuses_an_unknown_target_version():
    with pytest.raises(UnknownPassportVersion, match="cannot emit"):
        _body(version="0.9")


def test_emitter_never_invents_an_absence_marker():
    """A plane the emitter was not told about is *missing* — a drift finding — not
    absent-by-policy. Filling the gap with a waiver would launder ignorance into a
    governed statement, which is the ADR-005 §5 collapse."""
    body = _body(version=PASSPORT_VERSION_V2)
    assert set(body["graph_refs"]) == {"architecture"}


def test_build_passport_signs_and_validates_a_v0_2_passport():
    p = build_passport(
        _EDGE, {**_INTENT, "environment": "development"},
        generate_keypair(), "spiffe://prod.fsi/ns/platform/sa/calm-forge",
        issued_at=1, expires_at=2, version=PASSPORT_VERSION_V2,
        plane_refs={"controls": {"absent": "policy", "waived_by": "platform/rule#1"}},
    )
    assert p["passport_version"] == PASSPORT_VERSION_V2
    assert verify_passport(p) is True


def test_signature_covers_the_whole_graph_refs_map():
    """Per-plane provenance is inside the signed envelope (ADR-006 §1), so tampering
    with a controls reference must break verification the same way tampering with the
    edge would."""
    p = build_passport(
        _EDGE, {**_INTENT, "environment": "development"},
        generate_keypair(), "spiffe://prod.fsi/ns/platform/sa/calm-forge",
        issued_at=1, expires_at=2, version=PASSPORT_VERSION_V2,
        plane_refs={"controls": {
            "node_id": "kg://oscal/control/AC-3/imp-req-ac3-e7f2",
            "source": "declared", "confidence": 1.0,
            "node_version": "sha256:" + "e7" * 32,
        }},
    )
    p["graph_refs"]["controls"]["node_id"] = "kg://oscal/control/AC-6/imp-req-other"
    assert verify_passport(p) is False


# ---------------------------------------------------------------------------
# MP-04 — the rule JSON Schema cannot express
# ---------------------------------------------------------------------------

def _signed(environment, plane_refs):
    return build_passport(
        _EDGE, {**_INTENT, "environment": environment},
        generate_keypair(), "spiffe://prod.fsi/ns/platform/sa/calm-forge",
        issued_at=1, expires_at=2, version=PASSPORT_VERSION_V2, plane_refs=plane_refs,
    )


def test_production_may_not_waive_a_plane():
    """ADR-005 §5: production has no governance requirement to relax, so the waiver
    does not exist there. The document is well-formed against the schema and still
    wrong, which is why the check cannot live in the schema."""
    waived = {"business_intent": {"absent": "policy", "waived_by": "p/r#1"}}

    body = _body(version=PASSPORT_VERSION_V2, plane_refs=waived)
    jsonschema.validate(  # the schema itself accepts the shape
        {**body, "proof": {"issuer": "spiffe://a/b", "algorithm": "ed25519",
                           "canonicalization": "jcs", "signature_b64": "x"}},
        json.loads((ROOT / "src" / "calm_forge" / "schemas"
                    / "passport-v0.2.schema.json").read_text()),
    )

    with pytest.raises(PlaneWaiverError, match="production requires every plane"):
        _signed("production", waived)


def test_lower_environments_may_waive():
    p = _signed("development", {"business_intent": {"absent": "policy", "waived_by": "p/r#1"}})
    assert p["graph_refs"]["business_intent"]["absent"] == "policy"


def test_production_with_every_plane_authored_is_fine():
    p = _signed("production", {"controls": {
        "node_id": "kg://oscal/control/AC-3/imp-req-ac3-e7f2",
        "source": "declared", "confidence": 1.0,
        "node_version": "sha256:" + "e7" * 32,
    }})
    assert verify_passport(p) is True


def test_the_waiver_rule_names_every_offending_plane():
    with pytest.raises(PlaneWaiverError) as exc:
        _signed("production", {
            "controls": {"absent": "policy", "waived_by": "p/r#1"},
            "business_intent": {"absent": "policy", "waived_by": "p/r#2"},
        })
    assert "business_intent" in str(exc.value) and "controls" in str(exc.value)


# ---------------------------------------------------------------------------
# MP-43 / MP-46 — node_version required on the authored-node planes
# (controls, then business_intent), and not on architecture
# ---------------------------------------------------------------------------

_V2_SCHEMA = json.loads(
    (ROOT / "src" / "calm_forge" / "schemas" / "passport-v0.2.schema.json").read_text()
)
_ARCH_REF = {"node_id": "kg://edges/v1/" + "a" * 64, "source": "declared", "confidence": 1.0}
_CTRL_REF = {
    "node_id": "kg://oscal/control/AC-3/imp-req-ac3-e7f2",
    "source": "declared", "confidence": 1.0,
}
_BI_REF = {
    "node_id": "kg://tosca/policy/payments-portal/web-to-api-availability",
    "source": "declared", "confidence": 1.0,
}


def _validate_graph_refs(graph_refs):
    """Schema-only check of a v0.2 body carrying ``graph_refs`` (stub proof).

    Deliberately uses jsonschema, not validate_passport, so the assertion is about the
    schema's per-plane shape alone — not the production-waiver rule that lives in the
    validator.
    """
    body = _body(version=PASSPORT_VERSION_V2)
    body["graph_refs"] = graph_refs
    body["proof"] = {"issuer": "spiffe://a/b", "algorithm": "ed25519",
                     "canonicalization": "jcs", "signature_b64": "x"}
    jsonschema.validate(body, _V2_SCHEMA)


def test_controls_requires_node_version():
    """MP-43: OSCAL intake (MP-16) authored controls-plane nodes, so a controls ref with
    no node_version is a defect the schema now rejects — STALE_ATTESTATION must be
    computable by content for every valid controls claim."""
    with pytest.raises(jsonschema.ValidationError):
        _validate_graph_refs({"architecture": _ARCH_REF, "controls": _CTRL_REF})
    _validate_graph_refs({
        "architecture": _ARCH_REF,
        "controls": {**_CTRL_REF, "node_version": "sha256:" + "b" * 64},
    })


def test_business_intent_requires_node_version():
    """MP-46: TOSCA intake (MP-21) authored business_intent-plane nodes, so a business_intent
    ref with no node_version is a defect the schema now rejects — the MP-43 change one plane
    over. STALE_ATTESTATION must be computable by content for every valid business_intent
    claim, exactly as for controls."""
    with pytest.raises(jsonschema.ValidationError):
        _validate_graph_refs({"architecture": _ARCH_REF, "business_intent": _BI_REF})
    _validate_graph_refs({
        "architecture": _ARCH_REF,
        "business_intent": {**_BI_REF, "node_version": "sha256:" + "c" * 64},
    })


def test_the_node_version_requirement_is_per_plane_not_schema_wide():
    """The boundary is per-plane by design (ADR-006 §5): a plane joins plane_ref_versioned
    only once its intake authors real nodes — controls (MP-16/MP-43) and business_intent
    (MP-21/MP-46) both require node_version now. Architecture stays optional because its ref
    carries the edge_id itself, already a content hash; there is no separate node digest to
    require. Tightening a plane before it has authored nodes would force a fabricated digest,
    and a fabricated digest makes a stale passport look fresh — the failure the field
    prevents."""
    # architecture alone, no node_version — still valid
    _validate_graph_refs({"architecture": _ARCH_REF})
    # both authored-node planes carrying node_version — valid
    _validate_graph_refs({
        "architecture": _ARCH_REF,
        "controls": {**_CTRL_REF, "node_version": "sha256:" + "b" * 64},
        "business_intent": {**_BI_REF, "node_version": "sha256:" + "c" * 64},
    })


def test_a_waived_controls_plane_needs_no_node_version():
    """The requirement is on the authored branch only. An absence marker references no
    node, so it has nothing to digest."""
    _validate_graph_refs({
        "architecture": _ARCH_REF,
        "controls": {"absent": "policy", "waived_by": "platform/rule#1"},
    })


# ---------------------------------------------------------------------------
# MP-05 — the checked-in v0.2 reference
# ---------------------------------------------------------------------------

def test_v0_2_reference_is_real_and_is_the_same_edge_as_the_v0_1_reference():
    """Held to the standard the v0.1 pair set: schema-validates, signature verifies,
    and it is the *same edge* — so the relocation claim is demonstrable by diffing two
    checked-in files rather than taken on faith."""
    v1 = json.loads(V1_REF.read_text())
    v2 = json.loads(V2_REF.read_text())

    validate_passport(v2)
    assert verify_passport(v2) is True
    assert v2["passport_version"] == PASSPORT_VERSION_V2
    assert edge_id_of(v2) == edge_id_of(v1) == v1["graph_ref"]["edge_id"]


def test_v0_2_reference_is_production_and_therefore_authors_every_plane():
    v2 = json.loads(V2_REF.read_text())
    assert v2["intent_metadata"]["environment"] == "production"
    assert set(v2["graph_refs"]) == {"architecture", "controls", "business_intent"}
    assert not any(
        ref.get("absent") for ref in v2["graph_refs"].values()
    ), "a production reference must not model a waiver"


def test_v0_2_reference_still_describes_what_the_emitter_produces():
    """A reference that quietly lags the emitter documents a passport we no longer
    issue — the same guard the v0.1 pair carries."""
    v2 = json.loads(V2_REF.read_text())
    live = next(
        e for e in edges_from_calm_architecture(
            json.loads((ROOT / "examples" / "fsi-3tier" / "instantiation.json").read_text()),
            trust_domain="prod.fsi", system="payments-portal",
        )
        if e["destination_workload"] == "api-service"
    )
    from calm_forge.passport import build_network_binding
    assert set(build_network_binding(live)) <= set(v2["network_binding"])


def test_both_reference_versions_coexist_in_one_directory():
    """Two wire versions in one passport directory is the steady state until v0.1
    emission is retired, so the loader must not choke on the mix."""
    from calm_forge.passport_diff import load_passports

    loaded = load_passports(str(APP_DIR))
    versions = {p["passport_version"] for p in loaded}
    assert versions == {PASSPORT_VERSION, PASSPORT_VERSION_V2}
    for p in loaded:
        assert edge_id_of(p).startswith("kg://edges/v1/")


# ---------------------------------------------------------------------------
# CLI surface — the two wirings deferred from MP-03 / MP-07
# ---------------------------------------------------------------------------

def test_cli_emits_v0_2_passports_on_request(tmp_path):
    from click.testing import CliRunner

    from calm_forge.cli import cli

    res = CliRunner().invoke(cli, [
        "passport", "emit",
        "--calm", str(ROOT / "examples" / "fsi-3tier" / "instantiation.json"),
        "--output-dir", str(tmp_path), "--key", str(tmp_path / "k.pem"),
        "--trust-domain", "prod.fsi", "--passport-version", "0.2",
    ])
    assert res.exit_code == 0, res.output

    emitted = [json.loads(p.read_text()) for p in sorted(tmp_path.glob("*.passport.json"))]
    assert emitted
    for p in emitted:
        assert p["passport_version"] == PASSPORT_VERSION_V2
        validate_passport(p)
        assert verify_passport(p) is True
        # only the architecture plane: the CLI has no plane intake, and inventing an
        # absence marker for a plane it merely has not read would launder ignorance
        # into a governed statement
        assert set(p["graph_refs"]) == {"architecture"}


def test_cli_default_stays_v0_1(tmp_path):
    """The bump is opt-in until the golden corpus carries both versions."""
    from click.testing import CliRunner

    from calm_forge.cli import cli

    res = CliRunner().invoke(cli, [
        "passport", "emit",
        "--calm", str(ROOT / "examples" / "fsi-3tier" / "instantiation.json"),
        "--output-dir", str(tmp_path), "--key", str(tmp_path / "k.pem"),
    ])
    assert res.exit_code == 0, res.output
    for p in tmp_path.glob("*.passport.json"):
        assert json.loads(p.read_text())["passport_version"] == PASSPORT_VERSION


def test_generate_signs_provenance_only_when_asked(tmp_path):
    from click.testing import CliRunner

    from calm_forge.cli import cli
    from calm_forge.passport import load_private_key, public_key_b64
    from calm_forge.provenance import (
        PROVENANCE_ENVELOPE_FILENAME,
        PROVENANCE_FILENAME,
        verify_envelope,
    )

    ex = ROOT / "examples" / "fsi-3tier"
    base = [
        "generate", "--calm", str(ex / "instantiation.json"),
        "--decorator", str(ex / "decorator.json"), "--catalog", str(ex / "catalog.json"),
    ]
    runner = CliRunner()

    plain = tmp_path / "plain"
    res = runner.invoke(cli, [*base, "--output-dir", str(plain)])
    assert res.exit_code == 0, res.output
    assert (plain / PROVENANCE_FILENAME).exists()
    assert not (plain / PROVENANCE_ENVELOPE_FILENAME).exists()
    assert "unsigned" in res.output, "an unsigned run must say so"

    signed = tmp_path / "signed"
    key = signed / "k.pem"
    res = runner.invoke(cli, [
        *base, "--output-dir", str(signed), "--sign-provenance", "--key", str(key),
    ])
    assert res.exit_code == 0, res.output
    env = json.loads((signed / PROVENANCE_ENVELOPE_FILENAME).read_text())
    assert verify_envelope(env, public_key_b64(load_private_key(key))) is True
