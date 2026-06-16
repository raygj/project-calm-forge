"""Tests for coherence_auth — SPIFFE/mTLS enforcement on the coherence endpoint.

ADR-P3-001 §5: auth modes "none" (dev) and "spiffe" (prod).
ADR-0024 Federation Authority: cleartext federation rejected in production.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi import HTTPException  # noqa: E402

from calm_forge.coherence_auth import (  # noqa: E402
    allowed_trust_domains,
    auth_mode,
    extract_spiffe_id,
    require_coherence_auth,
    spiffe_trust_domain,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _FakeSSLObject:
    def __init__(self, peer_cert):
        self._peer_cert = peer_cert

    def getpeercert(self):
        return self._peer_cert


class _FakeTransport:
    def __init__(self, ssl_object):
        self._ssl_object = ssl_object

    def get_extra_info(self, name):
        if name == "ssl_object":
            return self._ssl_object
        return None


def _request_with_cert(peer_cert) -> "fastapi.Request":
    from fastapi import Request
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/graph/coherence",
        "headers": [],
        "query_string": b"",
        "transport": _FakeTransport(_FakeSSLObject(peer_cert)),
    }
    return Request(scope)


def _request_without_tls() -> "fastapi.Request":
    from fastapi import Request
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/graph/coherence",
        "headers": [],
        "query_string": b"",
    }
    return Request(scope)


def _spiffe_cert(spiffe_id: str) -> dict:
    return {"subjectAltName": (("URI", spiffe_id),)}


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# auth_mode
# ---------------------------------------------------------------------------

def test_auth_mode_defaults_to_none(monkeypatch):
    monkeypatch.delenv("CALM_FORGE_COHERENCE_AUTH", raising=False)
    assert auth_mode() == "none"


def test_auth_mode_spiffe(monkeypatch):
    monkeypatch.setenv("CALM_FORGE_COHERENCE_AUTH", "spiffe")
    assert auth_mode() == "spiffe"


def test_auth_mode_normalizes_case_and_whitespace(monkeypatch):
    monkeypatch.setenv("CALM_FORGE_COHERENCE_AUTH", " SPIFFE ")
    assert auth_mode() == "spiffe"


# ---------------------------------------------------------------------------
# allowed_trust_domains
# ---------------------------------------------------------------------------

def test_allowed_from_env_var(monkeypatch):
    monkeypatch.setenv("CALM_FORGE_COHERENCE_PEERS", "prod.fsi, peer.prod")
    assert allowed_trust_domains() == {"prod.fsi", "peer.prod"}


def test_allowed_env_strips_trust_domain_prefix(monkeypatch):
    monkeypatch.setenv("CALM_FORGE_COHERENCE_PEERS", "trust_domain:prod.fsi")
    assert allowed_trust_domains() == {"prod.fsi"}


def test_allowed_empty_when_nothing_configured(monkeypatch, tmp_path):
    monkeypatch.delenv("CALM_FORGE_COHERENCE_PEERS", raising=False)
    assert allowed_trust_domains(tmp_path) == set()


def test_allowed_from_trust_domain_nodes(monkeypatch, tmp_path):
    monkeypatch.delenv("CALM_FORGE_COHERENCE_PEERS", raising=False)
    td_dir = tmp_path / "trust_domains"
    td_dir.mkdir()
    (td_dir / "prod_fsi.json").write_text(json.dumps({
        "@id": "trust_domain:prod.fsi",
        "@type": "TrustDomain",
        "spiffe_uri_prefix": "spiffe://prod.fsi",
        "commune": "forge",
        "peer_trust_domains": ["trust_domain:peer.prod"],
    }))
    assert allowed_trust_domains(tmp_path) == {"peer.prod"}


def test_allowed_env_takes_precedence_over_nodes(monkeypatch, tmp_path):
    monkeypatch.setenv("CALM_FORGE_COHERENCE_PEERS", "override.domain")
    td_dir = tmp_path / "trust_domains"
    td_dir.mkdir()
    (td_dir / "prod_fsi.json").write_text(json.dumps({
        "@id": "trust_domain:prod.fsi",
        "@type": "TrustDomain",
        "peer_trust_domains": ["trust_domain:peer.prod"],
    }))
    assert allowed_trust_domains(tmp_path) == {"override.domain"}


# ---------------------------------------------------------------------------
# SPIFFE ID parsing
# ---------------------------------------------------------------------------

def test_extract_spiffe_id_from_uri_san():
    cert = _spiffe_cert("spiffe://prod.fsi/workload/reasoner")
    assert extract_spiffe_id(cert) == "spiffe://prod.fsi/workload/reasoner"


def test_extract_spiffe_id_ignores_non_spiffe_uri():
    cert = {"subjectAltName": (("URI", "https://example.com"), ("DNS", "example.com"))}
    assert extract_spiffe_id(cert) is None


def test_extract_spiffe_id_none_cert():
    assert extract_spiffe_id(None) is None


def test_spiffe_trust_domain_parses_domain():
    assert spiffe_trust_domain("spiffe://prod.fsi/workload/reasoner") == "prod.fsi"


def test_spiffe_trust_domain_bare_domain():
    assert spiffe_trust_domain("spiffe://prod.fsi") == "prod.fsi"


# ---------------------------------------------------------------------------
# require_coherence_auth dependency
# ---------------------------------------------------------------------------

def test_none_mode_passes_without_tls(monkeypatch):
    monkeypatch.delenv("CALM_FORGE_COHERENCE_AUTH", raising=False)
    _run(require_coherence_auth(_request_without_tls()))  # no raise


def test_spiffe_mode_rejects_missing_cert_401(monkeypatch):
    monkeypatch.setenv("CALM_FORGE_COHERENCE_AUTH", "spiffe")
    with pytest.raises(HTTPException) as exc:
        _run(require_coherence_auth(_request_without_tls()))
    assert exc.value.status_code == 401


def test_spiffe_mode_rejects_cert_without_spiffe_san_403(monkeypatch):
    monkeypatch.setenv("CALM_FORGE_COHERENCE_AUTH", "spiffe")
    monkeypatch.setenv("CALM_FORGE_COHERENCE_PEERS", "prod.fsi")
    cert = {"subjectAltName": (("DNS", "reasoner.internal"),)}
    with pytest.raises(HTTPException) as exc:
        _run(require_coherence_auth(_request_with_cert(cert)))
    assert exc.value.status_code == 403


def test_spiffe_mode_rejects_unallowed_trust_domain_403(monkeypatch):
    monkeypatch.setenv("CALM_FORGE_COHERENCE_AUTH", "spiffe")
    monkeypatch.setenv("CALM_FORGE_COHERENCE_PEERS", "prod.fsi")
    cert = _spiffe_cert("spiffe://evil.domain/workload/mallory")
    with pytest.raises(HTTPException) as exc:
        _run(require_coherence_auth(_request_with_cert(cert)))
    assert exc.value.status_code == 403


def test_spiffe_mode_allows_peer_trust_domain(monkeypatch):
    monkeypatch.setenv("CALM_FORGE_COHERENCE_AUTH", "spiffe")
    monkeypatch.setenv("CALM_FORGE_COHERENCE_PEERS", "prod.fsi")
    cert = _spiffe_cert("spiffe://prod.fsi/workload/reasoner")
    _run(require_coherence_auth(_request_with_cert(cert)))  # no raise


def test_spiffe_mode_no_peers_configured_503(monkeypatch):
    monkeypatch.setenv("CALM_FORGE_COHERENCE_AUTH", "spiffe")
    monkeypatch.delenv("CALM_FORGE_COHERENCE_PEERS", raising=False)
    monkeypatch.delenv("CALM_FORGE_KG_DIR", raising=False)
    import calm_forge.kg_coherence_api as kca
    monkeypatch.setattr(kca, "_kg_dir", None)
    cert = _spiffe_cert("spiffe://prod.fsi/workload/reasoner")
    with pytest.raises(HTTPException) as exc:
        _run(require_coherence_auth(_request_with_cert(cert)))
    assert exc.value.status_code == 503


def test_spiffe_mode_peers_from_kg_trust_domain_nodes(monkeypatch, tmp_path):
    monkeypatch.setenv("CALM_FORGE_COHERENCE_AUTH", "spiffe")
    monkeypatch.delenv("CALM_FORGE_COHERENCE_PEERS", raising=False)
    td_dir = tmp_path / "trust_domains"
    td_dir.mkdir()
    (td_dir / "prod_fsi.json").write_text(json.dumps({
        "@id": "trust_domain:prod.fsi",
        "@type": "TrustDomain",
        "peer_trust_domains": ["trust_domain:peer.prod"],
    }))
    import calm_forge.kg_coherence_api as kca
    monkeypatch.setattr(kca, "_kg_dir", Path(tmp_path))
    cert = _spiffe_cert("spiffe://peer.prod/agent/reasoner")
    _run(require_coherence_auth(_request_with_cert(cert)))  # no raise


# ---------------------------------------------------------------------------
# Endpoint integration — router dependency wired
# ---------------------------------------------------------------------------

def test_coherence_endpoint_open_in_none_mode(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from calm_forge.api import app
    from calm_forge.kg_coherence_api import configure_coherence_kg_dir

    monkeypatch.delenv("CALM_FORGE_COHERENCE_AUTH", raising=False)
    configure_coherence_kg_dir(tmp_path)
    client = TestClient(app)
    resp = client.get("/graph/coherence", params={"workload_id": "workload:x"})
    assert resp.status_code == 200


def test_coherence_endpoint_rejects_cleartext_in_spiffe_mode(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from calm_forge.api import app
    from calm_forge.kg_coherence_api import configure_coherence_kg_dir

    monkeypatch.setenv("CALM_FORGE_COHERENCE_AUTH", "spiffe")
    monkeypatch.setenv("CALM_FORGE_COHERENCE_PEERS", "prod.fsi")
    configure_coherence_kg_dir(tmp_path)
    client = TestClient(app)
    resp = client.get("/graph/coherence", params={"workload_id": "workload:x"})
    assert resp.status_code == 401


def test_shadow_endpoint_rejects_cleartext_in_spiffe_mode(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from calm_forge.api import app
    from calm_forge.kg_coherence_api import configure_coherence_kg_dir

    monkeypatch.setenv("CALM_FORGE_COHERENCE_AUTH", "spiffe")
    monkeypatch.setenv("CALM_FORGE_COHERENCE_PEERS", "prod.fsi")
    configure_coherence_kg_dir(tmp_path)
    client = TestClient(app)
    resp = client.post("/graph/shadow", json={"agent_workload_ids": []})
    assert resp.status_code == 401
