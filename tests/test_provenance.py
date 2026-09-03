"""SLSA v1.0 build provenance — ADR-007 / MP-01.

The load-bearing property is that drift comparison is *by content, never by clock*.
These tests pin that: digests-as-read are recorded, a no-op touch does not change the
record, and provenance that names no sources is a build failure rather than a warning.
"""
from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from calm_forge.cli import cli
from calm_forge.generator import generate_stack
from calm_forge.passport import generate_keypair, public_key_b64
from calm_forge.provenance import (
    IN_TOTO_STATEMENT_TYPE,
    PAYLOAD_TYPE,
    PROVENANCE_ENVELOPE_FILENAME,
    PROVENANCE_FILENAME,
    SLSA_PREDICATE_TYPE,
    ProvenanceError,
    build_provenance,
    dependency_from_path,
    dsse_envelope,
    keyid_for,
    node_version,
    pae,
    provenance_for_generated_files,
    resolved_dependency,
    sha256_hex,
    statement_from_envelope,
    subject,
    verify_envelope,
)

ROOT = Path(__file__).parent.parent
EXAMPLE = ROOT / "examples" / "fsi-3tier"


def _generate(tmp_path, *extra):
    result = CliRunner().invoke(cli, [
        "generate",
        "--calm", str(EXAMPLE / "instantiation.json"),
        "--decorator", str(EXAMPLE / "decorator.json"),
        "--catalog", str(EXAMPLE / "catalog.json"),
        "--output-dir", str(tmp_path),
        *extra,
    ])
    assert result.exit_code == 0, result.output
    return json.loads((tmp_path / PROVENANCE_FILENAME).read_text())


# ---------------------------------------------------------------------------
# The gate check — empty dependencies is a failure, not a warning
# ---------------------------------------------------------------------------

def test_empty_resolved_dependencies_is_a_build_failure():
    """ADR-007 Risks: a soft check here degrades to no check within two sprints.

    Provenance naming no sources cannot support a cross-plane drift comparison, so
    emitting it would be worse than emitting nothing — it looks like coverage."""
    with pytest.raises(ProvenanceError, match="no resolvedDependencies"):
        build_provenance(
            [subject("a.hcl", "x")], [], external_parameters={},
        )


def test_dependency_without_a_digest_is_a_build_failure():
    """A uri with no digest reopens the timestamp-comparison hole silently."""
    with pytest.raises(ProvenanceError, match="missing a sha256 digest"):
        build_provenance(
            [subject("a.hcl", "x")],
            [{"uri": "kg://oscal/control/AC-3/imp-req-ac3-e7f2"}],
            external_parameters={},
        )


# ---------------------------------------------------------------------------
# Content, not clock
# ---------------------------------------------------------------------------

def test_comparison_basis_is_content_not_clock(tmp_path):
    """The whole point of MP-01: a source touched but not changed must not look
    changed. A clock-based record would fire a false recompile finding here."""
    src = tmp_path / "catalog.json"
    src.write_text('{"a": 1}')
    before = dependency_from_path(src)

    # touch without changing content — mtime moves, bytes do not
    src.touch()
    after = dependency_from_path(src)

    assert before == after, "a no-op touch changed the recorded dependency"

    src.write_text('{"a": 2}')
    assert dependency_from_path(src) != before, "a real edit did not move the digest"


def test_timestamps_are_recorded_but_are_not_the_comparison_basis():
    """startedOn/finishedOn are audit narrative. Two builds of identical inputs at
    different times differ *only* in runDetails — the buildDefinition is stable, and
    that is the half a drift finding reads."""
    t1 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    t2 = t1 + timedelta(days=30)
    args = ([subject("a.hcl", "x")], [resolved_dependency("kg://n/1", "src")])
    kwargs = {"external_parameters": {"full": True}}

    a = build_provenance(*args, started_on=t1, **kwargs)
    b = build_provenance(*args, started_on=t2, **kwargs)

    assert a["predicate"]["buildDefinition"] == b["predicate"]["buildDefinition"]
    assert a["predicate"]["runDetails"] != b["predicate"]["runDetails"]


def test_node_version_and_in_toto_digest_are_the_same_bytes():
    """graph_refs[*].node_version (ADR-006 §5) and the in-toto digest map are one
    value in two spellings. If they ever diverge, a passport and a provenance record
    would disagree about whether the same node moved."""
    content = '{"control": "AC-3"}'
    assert node_version(content) == f"sha256:{sha256_hex(content)}"
    assert resolved_dependency("kg://n/1", content)["digest"]["sha256"] == sha256_hex(content)


# ---------------------------------------------------------------------------
# Shape — a stock SLSA verifier must recognise this
# ---------------------------------------------------------------------------

def test_statement_is_a_well_formed_in_toto_slsa_v1_statement(tmp_path):
    prov = _generate(tmp_path, "--full")

    assert prov["_type"] == IN_TOTO_STATEMENT_TYPE
    assert prov["predicateType"] == SLSA_PREDICATE_TYPE
    assert prov["predicate"]["buildDefinition"]["buildType"]
    assert prov["predicate"]["runDetails"]["builder"]["id"]
    assert prov["predicate"]["runDetails"]["metadata"]["startedOn"].endswith("Z")
    # internalParameters is omitted rather than emitted hollow — the KG state
    # reference lands with plane intake, and a hollow field would imply it exists
    assert "internalParameters" not in prov["predicate"]["buildDefinition"]


def test_internal_parameters_land_when_there_is_something_to_record():
    """Omitted while empty, carried when populated — this is the slot the graph root /
    KG state reference occupies once plane intake exists (ADR-007 §1)."""
    prov = build_provenance(
        [subject("a.hcl", "x")],
        [resolved_dependency("kg://n/1", "src")],
        external_parameters={},
        internal_parameters={"kg_state": "kg://graph/v1/abc123"},
    )
    assert prov["predicate"]["buildDefinition"]["internalParameters"] == {
        "kg_state": "kg://graph/v1/abc123"
    }


def test_every_generated_artifact_is_a_subject(tmp_path):
    prov = _generate(tmp_path, "--full")
    names = {s["name"] for s in prov["subject"]}

    for expected in (
        "components.tfstack.hcl", "variables.tfstack.hcl", "deployments.tfdeploy.hcl",
        "vault/policies.hcl", "vault/pki-config.hcl", "sentinel/policies.sentinel",
        "ansible/inventory.yml", "ansible/eda-rulebook.yml", "dcm/application.json",
    ):
        assert expected in names, f"{expected} generated but not attested"


def test_subject_digests_match_the_files_on_disk(tmp_path):
    """A subject digest that does not match its artifact is worse than no provenance:
    it attests the wrong bytes."""
    prov = _generate(tmp_path, "--full")
    for s in prov["subject"]:
        actual = sha256_hex((tmp_path / s["name"]).read_bytes())
        assert s["digest"]["sha256"] == actual, f"digest mismatch for {s['name']}"


def test_provenance_is_not_a_subject_of_itself(tmp_path):
    prov = _generate(tmp_path, "--full")
    assert PROVENANCE_FILENAME not in {s["name"] for s in prov["subject"]}


def test_sources_are_resolved_dependencies_with_digests(tmp_path):
    prov = _generate(tmp_path, "--full")
    deps = prov["predicate"]["buildDefinition"]["resolvedDependencies"]

    assert deps, "resolvedDependencies must never be empty"
    uris = " ".join(d["uri"] for d in deps)
    for source in ("instantiation.json", "decorator.json", "catalog.json"):
        assert source in uris, f"{source} was read but not recorded as a dependency"
    for d in deps:
        assert d["digest"]["sha256"]


def test_external_parameters_record_the_invocation(tmp_path):
    prov = _generate(tmp_path, "--full", "--policy-framework", "tfpolicy")
    params = prov["predicate"]["buildDefinition"]["externalParameters"]

    assert params["full"] is True
    assert params["policy_framework"] == "tfpolicy"


def test_provenance_emitted_for_the_default_non_full_path(tmp_path):
    """Every artifact Forge generates carries provenance — not only --full runs."""
    prov = _generate(tmp_path)
    assert {s["name"] for s in prov["subject"]} == {
        "components.tfstack.hcl", "variables.tfstack.hcl", "deployments.tfdeploy.hcl",
    }


def test_identical_inputs_produce_identical_build_definitions(tmp_path):
    """Determinism where it matters: same inputs, same buildDefinition, so a diff
    between two runs points at a real change rather than at the clock."""
    a = _generate(tmp_path / "a", "--full")
    b = _generate(tmp_path / "b", "--full")
    assert a["predicate"]["buildDefinition"] == b["predicate"]["buildDefinition"]
    assert a["subject"] == b["subject"]


def test_provenance_for_generated_files_rejects_a_sourceless_build(tmp_path):
    with pytest.raises(ProvenanceError):
        provenance_for_generated_files(
            {"a.hcl": "x"}, {}, external_parameters={},
        )


# ---------------------------------------------------------------------------
# DSSE envelope — ADR-007 §2 / MP-07
# ---------------------------------------------------------------------------

def _statement():
    return build_provenance(
        [subject("a.hcl", "x")],
        [resolved_dependency("kg://n/1", "src")],
        external_parameters={},
        started_on=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def test_envelope_round_trips_and_verifies_ed25519():
    key = generate_keypair()
    env = dsse_envelope(_statement(), key)

    assert env["payloadType"] == PAYLOAD_TYPE
    assert verify_envelope(env, public_key_b64(key)) is True
    assert statement_from_envelope(env) == _statement()


def test_envelope_verifies_ecdsa_p256():
    """Provenance rides the same algorithm agility as passport proofs, so a SPIRE
    P-256 SVID can sign a build record."""
    key = ec.generate_private_key(ec.SECP256R1())
    env = dsse_envelope(_statement(), key)
    assert verify_envelope(env, public_key_b64(key)) is True


def test_tampered_payload_fails_verification():
    """The point of signing: an edited statement must not verify."""
    key = generate_keypair()
    env = dsse_envelope(_statement(), key)

    tampered = json.loads(base64.b64decode(env["payload"]))
    tampered["subject"][0]["digest"]["sha256"] = "0" * 64
    env["payload"] = base64.b64encode(
        (json.dumps(tampered, indent=2) + "\n").encode()
    ).decode()

    assert verify_envelope(env, public_key_b64(key)) is False


def test_wrong_key_fails_verification():
    env = dsse_envelope(_statement(), generate_keypair())
    assert verify_envelope(env, public_key_b64(generate_keypair())) is False


def test_signature_covers_the_payload_type_not_just_the_payload():
    """DSSE PAE is length-prefixed so a payload cannot be reinterpreted under a
    different type. Swapping payloadType must break the signature."""
    key = generate_keypair()
    env = dsse_envelope(_statement(), key)
    env["payloadType"] = "application/vnd.something-else+json"
    assert verify_envelope(env, public_key_b64(key)) is False


def test_pae_is_length_prefixed():
    assert pae("t", b"body") == b"DSSEv1 1 t 4 body"


def test_malformed_envelope_is_false_not_an_exception():
    """Verification is a predicate; callers branch on it."""
    key = generate_keypair()
    assert verify_envelope({}, public_key_b64(key)) is False
    assert verify_envelope({"payload": "!!not-base64!!"}, public_key_b64(key)) is False
    assert verify_envelope(
        {"payload": base64.b64encode(b"{}").decode(), "signatures": [{}]},
        public_key_b64(key),
    ) is False


def test_envelope_does_not_carry_the_public_key():
    """The envelope must not be self-describing about trust: verification has to reach
    a trust source, which keeps the trust-bundle question visible rather than letting
    the artifact answer it for itself."""
    key = generate_keypair()
    env = dsse_envelope(_statement(), key)
    serialized = json.dumps(env)

    assert public_key_b64(key) not in serialized
    assert env["signatures"][0]["keyid"] == keyid_for(key)


def test_generate_emits_a_signed_envelope_only_when_a_key_is_supplied(tmp_path):
    unsigned = tmp_path / "unsigned"
    _generate(unsigned, "--full")
    assert (unsigned / PROVENANCE_FILENAME).exists()
    assert not (unsigned / PROVENANCE_ENVELOPE_FILENAME).exists(), (
        "an unsigned run must not leave something that looks like an attestation"
    )

    signed = tmp_path / "signed"
    key = generate_keypair()
    generate_stack(
        str(EXAMPLE / "instantiation.json"), str(EXAMPLE / "decorator.json"),
        str(EXAMPLE / "catalog.json"), str(signed), full=True, signing_key=key,
    )
    env = json.loads((signed / PROVENANCE_ENVELOPE_FILENAME).read_text())
    assert verify_envelope(env, public_key_b64(key)) is True
    assert statement_from_envelope(env) == json.loads(
        (signed / PROVENANCE_FILENAME).read_text()
    ), "the signed envelope and the unsigned statement must be the same record"


def test_non_ec_der_key_is_rejected_by_the_ecdsa_verifier():
    """A DER key that parses but is not an EC key must fail closed, not crash."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    from calm_forge.provenance import _verify_ecdsa_p256

    rsa_der = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    ).public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert _verify_ecdsa_p256(rsa_der, b"sig", b"msg") is False


def test_a_no_op_regenerate_produces_byte_identical_artifacts(tmp_path, monkeypatch):
    """MP-44. Generated artifacts must carry no wall clock.

    A `# GENERATED: <now>` line in components.tfstack.hcl made every no-op regenerate
    produce a new content digest, so two runs agreed only when they landed in the same
    second. That surfaced as a rare, unreproducible failure in the determinism test
    below — and the golden-file tests never caught it at all, because they scrubbed the
    line before comparing.

    The build time belongs in provenance's runDetails, where it is signed and where
    nothing digests it as part of the artifact. In the artifact it silently breaks the
    comparison basis every cross-plane finding rests on: content, never clock.

    This test forces the clock forward between runs, so it fails deterministically if
    anyone reintroduces a timestamp instead of failing once a month.
    """
    import calm_forge.hcl_writer as hcl_writer

    real_datetime = datetime

    class _Advancing:
        """Every call reports a different second."""
        _n = 0

        @classmethod
        def now(cls, tz=None):
            cls._n += 1
            return real_datetime(2026, 1, 1, 0, 0, cls._n, tzinfo=timezone.utc)

    monkeypatch.setattr(hcl_writer, "datetime", _Advancing, raising=False)

    a = _generate(tmp_path / "a", "--full")
    b = _generate(tmp_path / "b", "--full")
    assert a["subject"] == b["subject"]

    for artifact in ("components.tfstack.hcl", "variables.tfstack.hcl"):
        left = (tmp_path / "a" / artifact)
        if left.exists():
            assert left.read_bytes() == (tmp_path / "b" / artifact).read_bytes()


def test_no_generated_artifact_embeds_a_wall_clock(tmp_path):
    """The general form of MP-44: an artifact that stamps the time cannot be compared
    by content, and every drift signal downstream is comparing content."""
    _generate(tmp_path, "--full")
    stamped = [
        p.name for p in sorted(tmp_path.rglob("*"))
        if p.is_file() and p.name != PROVENANCE_FILENAME
        and re.search(r"GENERATED:\s+\d{4}-\d{2}-\d{2}T", p.read_text(errors="ignore"))
    ]
    assert stamped == []
