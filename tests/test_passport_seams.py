"""Tests for the walk/run seams (APP-080…084).

These assert the stubs are *honest*: crawl implementations do what they claim, and
walk/run implementations refuse clearly rather than silently doing nothing.
"""
from __future__ import annotations

import pytest

from calm_forge.passport import generate_keypair
from calm_forge.passport_seams import (
    EmitOnlyAdapter,
    EnforcementRefused,
    FileEdgeSource,
    FortiOSPushAdapter,
    SeamNotAvailable,
    SpireWorkloadApiProvider,
    StaticKeypairProvider,
    Svid,
    WorkloadApiClient,
    enforcement_decision,
    expired,
    renewal_due,
    zone_of,
)

_ISSUER = "spiffe://prod.fsi/ns/platform/sa/calm-forge"
_NOW = 1_800_000_000


def _grant(expires, claim="grant"):
    return {"claim": {"claim_type": claim}, "lifecycle": {"issued_at": 0, "expires_at": expires}}


# ---------------------------------------------------------------------------
# APP-080 — identity
# ---------------------------------------------------------------------------

def test_static_provider_is_usable_and_honest_about_attestation():
    key = generate_keypair()
    provider = StaticKeypairProvider(key, _ISSUER)
    assert provider.signing_key() is key
    assert provider.spiffe_id() == _ISSUER
    assert provider.attestation_level == "static-key"  # not pretending to be attested


class _MockWorkloadApi(WorkloadApiClient):
    """A stand-in SPIRE Workload API — returns a canned SVID, counts fetches (rotation)."""

    def __init__(self, svid: Svid):
        self._svid = svid
        self.fetches = 0

    def set_svid(self, svid: Svid) -> None:
        self._svid = svid

    def fetch_x509_svid(self) -> Svid:
        self.fetches += 1
        return self._svid


def _ed25519_svid(spiffe_id="spiffe://lab.starfly/ns/app/sa/forge"):
    return Svid(private_key=generate_keypair(), spiffe_id=spiffe_id)


def test_spire_provider_serves_identity_from_the_svid():
    svid = _ed25519_svid()
    provider = SpireWorkloadApiProvider(_MockWorkloadApi(svid))

    assert provider.signing_key() is svid.private_key
    assert provider.spiffe_id() == svid.spiffe_id
    assert provider.attestation_level == "spire-svid"  # attested, unlike static-key


def test_spire_svid_is_fetched_once_and_cached():
    """signing_key and spiffe_id must describe the *same* SVID within one passport."""
    api = _MockWorkloadApi(_ed25519_svid())
    provider = SpireWorkloadApiProvider(api)
    provider.signing_key()
    provider.spiffe_id()
    assert api.fetches == 1
    provider.refresh()  # rotation → re-fetch
    provider.signing_key()
    assert api.fetches == 2


def test_spire_ec_p256_svid_signs_an_ecdsa_passport():
    """SPIRE issues EC P-256 SVIDs (home-lab confirmed). The workload signs with its own SVID
    key → an `ecdsa-p256` passport that verifies. This is the real lab path."""
    from cryptography.hazmat.primitives.asymmetric import ec

    from calm_forge.passport import build_passport, verify_passport

    ec_svid = Svid(private_key=ec.generate_private_key(ec.SECP256R1()),
                   spiffe_id="spiffe://home-lab.local/ns/calm-forge/sa/forge")
    provider = SpireWorkloadApiProvider(_MockWorkloadApi(ec_svid))
    edge = {"source_workload": "web", "source_workload_urn": "wl:demo/web",
            "destination_workload": "api", "destination_workload_urn": "wl:demo/api",
            "protocol": "https", "port": 8443}
    intent = {"business_justification": "x", "environment": "production",
              "requested_by": provider.spiffe_id()}
    passport = build_passport(edge, intent, provider.signing_key(), provider.spiffe_id(),
                              issued_at=_NOW, expires_at=_NOW + 4 * 3600)
    assert passport["proof"]["algorithm"] == "ecdsa-p256"
    assert verify_passport(passport)


def test_unsupported_svid_key_type_is_rejected_at_signing():
    """An RSA SVID key (or any type that isn't Ed25519 / EC P-256) must be refused, not
    mis-signed under a scheme the verifier can't check."""
    from cryptography.hazmat.primitives.asymmetric import rsa

    from calm_forge.passport import build_passport

    rsa_svid = Svid(private_key=rsa.generate_private_key(public_exponent=65537, key_size=2048),
                    spiffe_id="spiffe://home-lab.local/ns/app/sa/forge")
    provider = SpireWorkloadApiProvider(_MockWorkloadApi(rsa_svid))
    edge = {"source_workload": "a", "source_workload_urn": "wl:x/a",
            "destination_workload": "b", "destination_workload_urn": "wl:x/b",
            "protocol": "https", "port": 8443}
    intent = {"business_justification": "x", "environment": "production", "requested_by": "spiffe://home-lab.local/ns/app/sa/forge"}
    with pytest.raises(ValueError, match="unsupported signing key"):
        build_passport(edge, intent, provider.signing_key(), provider.spiffe_id(),
                       issued_at=_NOW, expires_at=_NOW + 4 * 3600)


def test_spire_refuses_an_svid_outside_the_expected_trust_domain():
    api = _MockWorkloadApi(_ed25519_svid("spiffe://evil.example/ns/x/sa/y"))
    provider = SpireWorkloadApiProvider(api, trust_domain="lab.starfly")
    with pytest.raises(SeamNotAvailable, match="trust domain"):
        provider.spiffe_id()


def test_spire_identity_signs_a_verifiable_passport():
    """End-to-end: a passport signed with the SPIRE-provided key verifies. This is the whole
    point — issuance depends on the IdentityProvider interface, not a concrete key."""
    from calm_forge.passport import build_passport, verify_passport

    svid = _ed25519_svid()
    provider = SpireWorkloadApiProvider(_MockWorkloadApi(svid))
    edge = {
        "source_workload": "web", "source_workload_urn": "wl:demo/web",
        "destination_workload": "api", "destination_workload_urn": "wl:demo/api",
        "protocol": "https", "port": 8443,
    }
    intent = {"business_justification": "x", "environment": "production",
              "requested_by": provider.spiffe_id()}
    passport = build_passport(
        edge, intent, provider.signing_key(), provider.spiffe_id(),
        issued_at=_NOW, expires_at=_NOW + 90 * 86400,
    )
    assert verify_passport(passport)


# ---------------------------------------------------------------------------
# APP-081 — renewal reporting
# ---------------------------------------------------------------------------

def test_renewal_due_reports_within_window_only():
    soon = _grant(_NOW + 10 * 86400)
    later = _grant(_NOW + 200 * 86400)
    gone = _grant(_NOW - 1)
    due = renewal_due([soon, later, gone], _NOW, within_days=30)
    assert due == [soon]  # already-expired and far-future both excluded


def test_renewal_due_sorted_and_ignores_revokes():
    a = _grant(_NOW + 20 * 86400)
    b = _grant(_NOW + 5 * 86400)
    revoke = _grant(_NOW + 1 * 86400, claim="revoke")
    assert renewal_due([a, b, revoke], _NOW, within_days=30) == [b, a]


def test_expired_grants():
    assert expired([_grant(_NOW - 1), _grant(_NOW + 1)], _NOW) == [_grant(_NOW - 1)]


# ---------------------------------------------------------------------------
# APP-081 — the re-attestation loop (renew_due_passports)
#
# renewal_due only *reports*; renew_due_passports is the action it feeds. A renewed
# grant keeps its edge_id (so it supersedes the lapsing one) and carries a fresh window.
# ---------------------------------------------------------------------------

_EDGE = {
    "source_workload": "web", "source_workload_urn": "wl:demo/web",
    "destination_workload": "api", "destination_workload_urn": "wl:demo/api",
    "protocol": "https", "port": 8443,
}
_INTENT = {
    "business_justification": "web→api", "environment": "production",
    "requested_by": "spiffe://demo/web",
}


def _real_grant(expires_at, issued_at=0):
    from calm_forge.passport import build_passport

    key = generate_keypair()
    return build_passport(
        _EDGE, _INTENT, key, _ISSUER, issued_at=issued_at, expires_at=expires_at
    )


def test_renew_due_only_touches_grants_in_the_window():
    from calm_forge.passport_seams import renew_due_passports

    key = generate_keypair()
    soon = _real_grant(_NOW + 10 * 86400)
    later = _real_grant(_NOW + 200 * 86400)
    renewed = renew_due_passports([soon, later], key, _ISSUER, now=_NOW, within_days=30)
    assert len(renewed) == 1  # only `soon` was due


def test_renewed_grant_supersedes_the_lapsing_one():
    """Same edge_id, later window, still verifiable — the whole point of renewal."""
    from calm_forge.passport import verify_passport
    from calm_forge.passport_seams import renew_due_passports

    key = generate_keypair()
    grant = _real_grant(_NOW + 5 * 86400)
    (renewed,) = renew_due_passports([grant], key, _ISSUER, now=_NOW, within_days=30, ttl_days=90)

    assert renewed["graph_ref"]["edge_id"] == grant["graph_ref"]["edge_id"]
    assert renewed["lifecycle"]["expires_at"] == _NOW + 90 * 86400
    assert renewed["lifecycle"]["expires_at"] > grant["lifecycle"]["expires_at"]
    assert verify_passport(renewed)
    # A renewed grant is no longer due — the loop converges.
    assert renewal_due([renewed], _NOW, within_days=30) == []


def test_renew_due_on_nothing_due_is_empty():
    from calm_forge.passport_seams import renew_due_passports

    key = generate_keypair()
    fresh = _real_grant(_NOW + 200 * 86400)
    assert renew_due_passports([fresh], key, _ISSUER, now=_NOW, within_days=30) == []


# ---------------------------------------------------------------------------
# APP-082 — edge sources
# ---------------------------------------------------------------------------

def test_file_edge_source_is_the_degenerate_join_case():
    src = FileEdgeSource([{"a": 1}], provenance="declared")
    assert src.provenance == "declared"
    assert src.edges() == [{"a": 1}]
    src.edges().append({"b": 2})  # returns a copy — callers can't mutate the source
    assert len(src.edges()) == 1


# ---------------------------------------------------------------------------
# APP-083 — enforcement (emit-only enforced by the type)
# ---------------------------------------------------------------------------

def test_emit_only_adapter_writes(tmp_path):
    written = EmitOnlyAdapter().emit({"a.conf": "x", "b.tf": "y"}, tmp_path)
    assert len(written) == 2
    assert (tmp_path / "a.conf").read_text() == "x"


def test_emit_only_adapter_refuses_push():
    with pytest.raises(EnforcementRefused, match="emit-only"):
        EmitOnlyAdapter().push({"a.conf": "x"})


def test_fortios_push_adapter_refuses_until_walk(tmp_path):
    adapter = FortiOSPushAdapter("https://fw.internal")
    assert adapter.emit({"a.conf": "x"}, tmp_path)  # emitting is fine
    with pytest.raises(SeamNotAvailable, match="walk-stage"):
        adapter.push({"a.conf": "x"})


# ---------------------------------------------------------------------------
# APP-084 — blast-radius zones + the safety matrix
# ---------------------------------------------------------------------------

def _pp(**intent):
    """A passport-shaped dict carrying just the intent_metadata zone_of reads."""
    return {"intent_metadata": intent}


def test_zone_unclassifiable_passport_is_unzoned():
    assert zone_of({"anything": True}) == "unzoned"
    assert zone_of(_pp()) == "unzoned"


def test_zone_compliance_scope_is_regulated():
    assert zone_of(_pp(environment="production", compliance_scope=["PCI-DSS-v4:req-1"])) == "regulated"


def test_zone_sensitive_data_is_regulated_even_in_nonprod():
    """Data sensitivity outranks environment — confidential data in staging is still regulated."""
    assert zone_of(_pp(environment="staging", data_classification="confidential")) == "regulated"
    assert zone_of(_pp(environment="test", data_classification="restricted")) == "regulated"


def test_zone_plain_production_and_nonprod():
    assert zone_of(_pp(environment="production", data_classification="internal")) == "production"
    assert zone_of(_pp(environment="staging")) == "nonprod"
    assert zone_of(_pp(environment="development")) == "nonprod"


def test_unzoned_never_auto_acts_the_fail_safe():
    assert enforcement_decision("unzoned", "autonomic-contraction") == "propose"
    assert enforcement_decision("unzoned", "governed-expansion") == "propose"
    # An unknown zone string is treated like unzoned, never auto-acted on.
    assert enforcement_decision("something-unrecognised", "autonomic-contraction") == "propose"


def test_matrix_grades_autonomy_by_blast_radius():
    # nonprod: move fast both ways
    assert enforcement_decision("nonprod", "autonomic-contraction") == "auto-enforce"
    assert enforcement_decision("nonprod", "governed-expansion") == "auto-enforce"
    # production: auto-enforce reversible contraction; expansion → human
    assert enforcement_decision("production", "autonomic-contraction") == "auto-enforce"
    assert enforcement_decision("production", "governed-expansion") == "governed-review"
    # regulated: human review either way (conservative default — see the matrix note)
    assert enforcement_decision("regulated", "autonomic-contraction") == "governed-review"
    assert enforcement_decision("regulated", "governed-expansion") == "governed-review"


def test_higher_blast_radius_is_never_more_autonomous():
    """Monotonicity: for a fixed authority_class, a higher-blast zone is never *more* willing
    to auto-act than a lower one. A regression here means the safety gradient inverted."""
    rank = {"propose": 0, "governed-review": 1, "auto-enforce": 2}
    # zones from low to high blast radius
    order = ["nonprod", "production", "regulated"]
    for ac in ("autonomic-contraction", "governed-expansion"):
        autonomy = [rank[enforcement_decision(z, ac)] for z in order]
        assert autonomy == sorted(autonomy, reverse=True), f"{ac}: {autonomy} not monotonic"
