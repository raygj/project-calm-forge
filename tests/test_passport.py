"""Tests for the passport builder + signing (APP-002/010/011)."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import jsonschema
import pytest

from calm_forge.passport import (
    build_passport,
    build_passport_body,
    build_renew_body,
    build_revoke_body,
    canonicalize,
    context_from_calm,
    edges_from_calm_architecture,
    edges_from_kg_workload,
    generate_keypair,
    load_private_key,
    ownership_from_kg,
    renew_passport,
    save_private_key,
    sign_passport,
    transport_for,
    verify_passport,
    write_passport,
)

_CALM = {
    "title": "Digital Banking",
    "metadata": {
        "application-name": "digital-banking-platform",
        "team": "dbe",
        "cost-center": "CC-7830",
        "data-classification": "confidential",
        "compliance-scope": "pci-dss",
        "sla-tier": "platinum",
    },
    "nodes": [{"unique-id": "api-gateway"}, {"unique-id": "account-service"}],
    "relationships": [
        {
            "unique-id": "gw-to-acct",
            "description": "gateway to account via mTLS",
            "relationship-type": {
                "connects": {
                    "source": {"node": "api-gateway", "interfaces": ["https-8443"]},
                    "destination": {"node": "account-service", "interfaces": ["https-8443"]},
                }
            },
            "protocol": "HTTPS",
            "authentication": "mTLS-vault-pki",
        }
    ],
}

_KG = json.loads(
    (Path(__file__).resolve().parents[1] / "src" / "calm_forge" / "knowledge_graph" / "3-tier-pci.json").read_text()
)
_ISSUER = "spiffe://prod.fsi/ns/platform/sa/calm-forge"
_PINNED = "kg://edges/v1/83c1619b769aae79d8c6b4ae127a3fafe2e0f47728095b5ed5d278e2cc182364"

_EDGE = {
    "source_workload": "web-tier",
    "source_workload_urn": "wl:3tier-pci/web-tier",
    "source_spiffe_id": "spiffe://prod.fsi/ns/3tier-pci/sa/web-tier",
    "destination_workload": "api-tier",
    "destination_workload_urn": "wl:3tier-pci/api-tier",
    "destination_spiffe_id": "spiffe://prod.fsi/ns/3tier-pci/sa/api-tier",
    "transport": "tcp",
    "port": 8443,
    "app_protocol": ["mTLS"],
    "authentication": "vault-pki",
    "direction": "egress",
}
_INTENT = {
    "business_justification": "web-tier calls api-tier over mTLS",
    "environment": "production",
    "requested_by": _ISSUER,
    "ticket_id": "SEC-8841",
    "compliance_scope": ["PCI-DSS-v4:req-1"],
    "data_classification": "confidential",
}


def _build(**kw):
    return build_passport(
        _EDGE, _INTENT, generate_keypair(), _ISSUER,
        issued_at=1784246400, expires_at=1815782400, **kw,
    )


# ---------------------------------------------------------------------------
# Build + sign + validate + verify
# ---------------------------------------------------------------------------

def test_build_produces_schema_valid_signed_passport():
    p = _build()  # build_passport validates by default
    assert verify_passport(p) is True
    assert p["graph_ref"]["edge_id"] == _PINNED


def test_defaults_are_the_safe_crawl_posture():
    p = _build()
    assert p["claim"] == {
        "claim_type": "grant",
        "tense": "should-be",
        "authority_class": "governed-expansion",
    }
    assert p["network_binding"]["port"] == 8443
    assert p["spiffe_id"] == _EDGE["source_spiffe_id"]


def test_promoted_metadata_carried_through():
    p = _build(ownership={"owner": "platform-engineering", "team": "dbe"})
    assert p["intent_metadata"]["compliance_scope"] == ["PCI-DSS-v4:req-1"]
    assert p["intent_metadata"]["data_classification"] == "confidential"
    assert p["ownership"]["owner"] == "platform-engineering"


def test_tamper_fails_verification():
    p = _build()
    tampered = copy.deepcopy(p)
    tampered["network_binding"]["port"] = 9999
    assert verify_passport(tampered) is False


def test_verify_with_wrong_key_fails():
    p = _build()
    other = generate_keypair()
    from calm_forge.passport import public_key_b64
    assert verify_passport(p, public_key_b64_override=public_key_b64(other)) is False


def test_edge_id_recomputes_after_reserialization():
    p = _build()
    round_tripped = json.loads(json.dumps(p))
    assert verify_passport(round_tripped) is True


def test_canonicalize_is_order_independent():
    a = {"b": 1, "a": {"y": 2, "x": 1}}
    b = {"a": {"x": 1, "y": 2}, "b": 1}
    assert canonicalize(a) == canonicalize(b)


def test_transport_inference():
    assert transport_for("HTTPS") == "tcp"
    assert transport_for("dns") == "udp"
    assert transport_for(None) == "tcp"


# ---------------------------------------------------------------------------
# graph_ref guardrail — a body without edge_id cannot validate
# ---------------------------------------------------------------------------

def test_missing_graph_ref_rejected_by_validation():
    body = build_passport_body(_EDGE, _INTENT, issued_at=1, expires_at=2)
    del body["graph_ref"]
    signed = sign_passport(body, generate_keypair(), _ISSUER)
    with pytest.raises(jsonschema.ValidationError):
        from calm_forge.passport import validate_passport
        validate_passport(signed)


# ---------------------------------------------------------------------------
# Key persistence
# ---------------------------------------------------------------------------

def test_keypair_roundtrip_via_pem(tmp_path):
    key = generate_keypair()
    pem = tmp_path / "issuer.pem"
    save_private_key(key, pem)
    loaded = load_private_key(pem)
    body = build_passport_body(_EDGE, _INTENT, issued_at=1, expires_at=2)
    p1 = sign_passport(body, key, _ISSUER)
    p2 = sign_passport(body, loaded, _ISSUER)
    assert p1["proof"]["signature_b64"] == p2["proof"]["signature_b64"]


# ---------------------------------------------------------------------------
# KG Workload adapter — reproduces the pinned edge + lifts metadata from the KG
# ---------------------------------------------------------------------------

def test_kg_adapter_reproduces_pinned_edge():
    edges = edges_from_kg_workload(
        _KG, trust_domain="prod.fsi",
        port_overrides={("workload:3tier-pci:web-tier", "workload:3tier-pci:api-tier"): 8443},
    )
    web_api = edges[0]
    assert web_api["source_spiffe_id"] == "spiffe://prod.fsi/ns/3tier-pci/sa/web-tier"
    assert web_api["app_protocol"] == ["mTLS"]
    assert web_api["authored_by"] == "calm-forge/adr-004-reference-pattern"

    p = build_passport(
        web_api,
        {**_INTENT, "compliance_scope": _KG["compliance_scope"]},
        generate_keypair(), _ISSUER,
        issued_at=1784246400, expires_at=1815782400,
        ownership=ownership_from_kg(_KG),
    )
    assert p["graph_ref"]["edge_id"] == _PINNED
    assert p["graph_ref"]["authored_by"] == "calm-forge/adr-004-reference-pattern"
    assert p["ownership"]["owner"] == "platform-engineering"
    assert verify_passport(p) is True


def test_kg_adapter_unresolved_port_marks_unspecified():
    edges = edges_from_kg_workload(_KG, trust_domain="prod.fsi")  # no overrides, mTLS/TLS have no default
    assert all(e.get("port_unspecified") for e in edges)
    p = build_passport(edges[0], _INTENT, generate_keypair(), _ISSUER, issued_at=1, expires_at=2)
    assert p["network_binding"]["port_unspecified"] is True
    expected = hashlib.sha256(  # port=any is a distinct id from any real port
        b"edge/v1|src=wl:3tier-pci/web-tier|dst=wl:3tier-pci/api-tier|l4=tcp|port=any"
    ).hexdigest()
    assert p["graph_ref"]["edge_id"].endswith(expected)


def test_write_passport(tmp_path):
    p = _build()
    path = write_passport(p, tmp_path)
    assert path.exists()
    assert json.loads(path.read_text())["graph_ref"]["edge_id"] == _PINNED


# ---------------------------------------------------------------------------
# Revoke / tombstone (APP-050)
# ---------------------------------------------------------------------------

def test_revoke_shares_edge_id_and_flips_posture():
    grant = _build()
    body = build_revoke_body(grant, issued_at=100, expires_at=200)
    # same edge → same id, which is how the tombstone supersedes the grant
    assert body["graph_ref"]["edge_id"] == grant["graph_ref"]["edge_id"]
    assert body["claim"] == {
        "claim_type": "revoke",
        "tense": "will-be",
        "authority_class": "autonomic-contraction",
    }
    assert body["lifecycle"] == {"issued_at": 100, "expires_at": 200}
    assert body["passport_id"] != grant["passport_id"]
    assert "revoked" in body["intent_metadata"]["business_justification"]


def test_revoke_signs_and_validates():
    grant = _build()
    body = build_revoke_body(grant, issued_at=100, expires_at=200)
    tombstone = sign_passport(body, generate_keypair(), _ISSUER)
    from calm_forge.passport import validate_passport
    validate_passport(tombstone)
    assert verify_passport(tombstone) is True


def test_revoke_does_not_clobber_its_grant(tmp_path):
    grant = _build()
    body = build_revoke_body(grant, issued_at=100, expires_at=200)
    tombstone = sign_passport(body, generate_keypair(), _ISSUER)
    grant_path = write_passport(grant, tmp_path)
    revoke_path = write_passport(tombstone, tmp_path)
    assert grant_path != revoke_path
    assert revoke_path.name.endswith(".revoke.passport.json")
    assert grant_path.exists() and revoke_path.exists()


# ---------------------------------------------------------------------------
# Signature algorithms (APP-080) — Ed25519 default + ECDSA P-256 for SPIRE SVIDs
# ---------------------------------------------------------------------------

def test_ecdsa_p256_passport_signs_verifies_and_is_labelled():
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    passport = build_passport(
        _EDGE, _INTENT, key, _ISSUER, issued_at=1784246400, expires_at=1784260800
    )
    assert passport["proof"]["algorithm"] == "ecdsa-p256"
    assert verify_passport(passport)


def test_ecdsa_passport_tamper_fails_verification():
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    passport = build_passport(
        _EDGE, _INTENT, key, _ISSUER, issued_at=1784246400, expires_at=1784260800
    )
    passport["network_binding"]["port"] = 9999
    assert not verify_passport(passport)


def test_ed25519_default_is_unchanged_by_the_ecdsa_addition():
    """The Ed25519 path must be byte-identical — existing passports/goldens still verify."""
    passport = _build()
    assert passport["proof"]["algorithm"] == "ed25519"
    assert verify_passport(passport)


def test_an_ecdsa_key_does_not_verify_an_ed25519_proof():
    """Cross-algorithm independence: a proof is checked under its stated algorithm only."""
    from cryptography.hazmat.primitives.asymmetric import ec

    ed = _build()  # ed25519
    # Swap in an ECDSA public key but keep algorithm=ed25519 → must fail, not crash.
    from calm_forge.passport import public_key_b64
    ed["proof"]["public_key_b64"] = public_key_b64(ec.generate_private_key(ec.SECP256R1()))
    assert not verify_passport(ed)


def test_unsupported_key_type_is_rejected():
    from cryptography.hazmat.primitives.asymmetric import rsa

    from calm_forge.passport import sign_passport

    body = build_passport_body(_EDGE, _INTENT, issued_at=1, expires_at=2)
    with pytest.raises(ValueError, match="unsupported signing key"):
        sign_passport(body, rsa.generate_private_key(public_exponent=65537, key_size=2048), _ISSUER)


# ---------------------------------------------------------------------------
# Renewal (APP-081) — re-attest a grant with a fresh lifecycle window
# ---------------------------------------------------------------------------

def test_renew_preserves_identity_and_extends_the_window():
    grant = _build()
    body = build_renew_body(grant, issued_at=2_000_000_000, expires_at=2_000_000_000 + 90 * 86400)

    # Identity and the whole claim are preserved; only the window and id move.
    assert body["graph_ref"]["edge_id"] == grant["graph_ref"]["edge_id"]
    assert body["network_binding"] == grant["network_binding"]
    assert body["claim"] == grant["claim"]  # renewal restates nothing
    assert body["lifecycle"]["expires_at"] > grant["lifecycle"]["expires_at"]
    assert body["passport_id"] != grant["passport_id"]
    assert "proof" not in body


def test_renew_signs_verifies_and_supersedes_by_edge_id():
    grant = _build()
    key = generate_keypair()
    renewed = renew_passport(
        grant, key, _ISSUER, issued_at=2_000_000_000, expires_at=2_000_000_000 + 90 * 86400
    )
    assert verify_passport(renewed)
    assert renewed["graph_ref"]["edge_id"] == grant["graph_ref"]["edge_id"]


def test_renew_writes_over_the_grant_it_renews(tmp_path):
    """A renewed grant is still a grant — same filename, so it supersedes in place
    (unlike a revoke, which lands under a .revoke suffix to preserve the tombstone)."""
    grant = _build()
    grant_path = write_passport(grant, tmp_path)
    renewed = renew_passport(
        grant, generate_keypair(), _ISSUER,
        issued_at=2_000_000_000, expires_at=2_000_000_000 + 90 * 86400,
    )
    renewed_path = write_passport(renewed, tmp_path)
    assert renewed_path == grant_path  # same edge_id, grant claim → same file


def test_only_a_grant_can_be_renewed():
    grant = _build()
    tombstone = sign_passport(
        build_revoke_body(grant, issued_at=100, expires_at=200), generate_keypair(), _ISSUER
    )
    with pytest.raises(ValueError, match="grant"):
        build_renew_body(tombstone, issued_at=300, expires_at=400)


def test_renew_rejects_a_window_that_does_not_extend():
    grant = _build()
    with pytest.raises(ValueError, match="after issued_at"):
        build_renew_body(grant, issued_at=500, expires_at=400)


# ---------------------------------------------------------------------------
# CALM architecture adapter
# ---------------------------------------------------------------------------

def test_calm_adapter_resolves_port_from_interface_and_qualifies_urn():
    edges = edges_from_calm_architecture(_CALM, trust_domain="prod.fsi")
    assert len(edges) == 1
    e = edges[0]
    assert e["port"] == 8443  # from https-8443
    assert e["source_workload_urn"] == "wl:digital-banking-platform/api-gateway"
    assert e["source_spiffe_id"] == "spiffe://prod.fsi/ns/digital-banking-platform/sa/api-gateway"
    assert e["app_protocol"] == ["HTTPS"]
    assert e["description"] == "gateway to account via mTLS"


def test_calm_adapter_system_override():
    edges = edges_from_calm_architecture(_CALM, trust_domain="prod.fsi", system="Custom System")
    assert edges[0]["source_workload_urn"] == "wl:custom-system/api-gateway"


def test_context_from_calm_lifts_metadata():
    ctx = context_from_calm(_CALM)
    assert ctx["intent"]["data_classification"] == "confidential"
    assert ctx["intent"]["compliance_scope"] == ["pci-dss"]
    assert ctx["ownership"]["cost_center"] == "CC-7830"
    assert ctx["ownership"]["sla_tier"] == "platinum"


def test_calm_edge_builds_valid_passport():
    edges = edges_from_calm_architecture(_CALM, trust_domain="prod.fsi")
    ctx = context_from_calm(_CALM)
    p = build_passport(
        edges[0],
        {"business_justification": "x", "environment": "production", "requested_by": _ISSUER,
         **ctx["intent"]},
        generate_keypair(), _ISSUER, issued_at=1, expires_at=2, ownership=ctx["ownership"],
    )
    assert verify_passport(p) is True
    assert p["intent_metadata"]["data_classification"] == "confidential"
