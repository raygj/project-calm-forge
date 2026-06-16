"""SPIFFE/mTLS authentication for the coherence endpoint.

Per ADR-P3-001 §5 and ADR-0024 Federation Authority:
  - Prod federation requires SPIFFE/mTLS — SPIFFE-issued peer certificates
    on both sides. Cleartext federation is rejected at the TLS layer.
  - Dev mode runs without mTLS, explicitly not supported in production.

Configuration (environment variables):
  CALM_FORGE_COHERENCE_AUTH   "none" (dev, default) | "spiffe" (prod)
  CALM_FORGE_COHERENCE_PEERS  Comma-separated trust domains allowed to call
                              (e.g. "prod.fsi,peer.prod"). When unset in
                              spiffe mode, peers are derived from TrustDomain
                              nodes in the KG (union of peer_trust_domains).

TLS termination happens in uvicorn (`calm-forge serve --ssl-certfile ...
--ssl-keyfile ... --ssl-ca-certs ...`). This module validates the verified
peer certificate's SPIFFE URI SAN against the allowed trust domain set.
uvicorn must be started with client cert verification (ssl_cert_reqs =
CERT_REQUIRED) for the peer certificate to be present — `serve` does this
automatically when --ssl-ca-certs is given.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import HTTPException, Request

_AUTH_MODE_ENV = "CALM_FORGE_COHERENCE_AUTH"
_PEERS_ENV = "CALM_FORGE_COHERENCE_PEERS"


def auth_mode() -> str:
    """Return the configured coherence auth mode: "none" or "spiffe"."""
    return os.environ.get(_AUTH_MODE_ENV, "none").strip().lower() or "none"


def allowed_trust_domains(kg_dir: Path | None = None) -> set[str]:
    """Resolve the set of trust domains allowed to call the coherence endpoint.

    CALM_FORGE_COHERENCE_PEERS takes precedence. Otherwise, TrustDomain nodes
    in <kg_dir>/trust_domains/ contribute the union of their peer_trust_domains
    (per ADR-0024: federation handshake validates symmetric peer agreement).
    Values are normalized by stripping the canonical "trust_domain:" prefix.
    """
    env = os.environ.get(_PEERS_ENV, "")
    if env.strip():
        return {
            _norm(p) for p in env.split(",") if p.strip()
        }

    if kg_dir is None:
        return set()

    peers: set[str] = set()
    td_dir = Path(kg_dir) / "trust_domains"
    if not td_dir.exists():
        return peers
    for path in sorted(td_dir.glob("*.json")):
        try:
            node = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if node.get("@type") != "TrustDomain":
            continue
        for peer in node.get("peer_trust_domains", []):
            peers.add(_norm(peer))
    return peers


def extract_spiffe_id(peer_cert: dict[str, Any] | None) -> str | None:
    """Extract the SPIFFE ID from a verified peer certificate's URI SAN.

    peer_cert is the dict returned by ssl_object.getpeercert() — only
    populated when the TLS layer verified the client cert (CERT_REQUIRED).
    """
    if not peer_cert:
        return None
    for san_type, san_value in peer_cert.get("subjectAltName", ()):
        if san_type == "URI" and san_value.startswith("spiffe://"):
            return san_value
    return None


def spiffe_trust_domain(spiffe_id: str) -> str:
    """Return the trust domain component of a SPIFFE ID.

    spiffe://prod.fsi/workload/payments → "prod.fsi"
    """
    rest = spiffe_id.removeprefix("spiffe://")
    return rest.split("/", 1)[0]


async def require_coherence_auth(request: Request) -> None:
    """FastAPI dependency enforcing the coherence endpoint auth policy.

    Mode "none": pass-through (dev).
    Mode "spiffe": require a TLS-verified client certificate carrying a
    SPIFFE URI SAN whose trust domain is in the allowed peer set.
    """
    if auth_mode() != "spiffe":
        return

    peer_cert = _peer_certificate(request)
    if peer_cert is None:
        raise HTTPException(
            status_code=401,
            detail=(
                "Coherence endpoint requires SPIFFE/mTLS "
                "(CALM_FORGE_COHERENCE_AUTH=spiffe) but no verified client "
                "certificate was presented. Serve with --ssl-ca-certs and "
                "connect with a SPIFFE-issued SVID."
            ),
        )

    spiffe_id = extract_spiffe_id(peer_cert)
    if spiffe_id is None:
        raise HTTPException(
            status_code=403,
            detail="Client certificate has no SPIFFE URI SAN.",
        )

    domain = spiffe_trust_domain(spiffe_id)
    allowed = allowed_trust_domains(_coherence_kg_dir())
    if not allowed:
        raise HTTPException(
            status_code=503,
            detail=(
                "No allowed peer trust domains configured. Set "
                "CALM_FORGE_COHERENCE_PEERS or author TrustDomain nodes "
                "with peer_trust_domains in the KG."
            ),
        )
    if domain not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Trust domain {domain!r} is not an allowed federation peer.",
        )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _peer_certificate(request: Request) -> dict[str, Any] | None:
    """Pull the verified peer certificate off the ASGI transport, if any."""
    transport = request.scope.get("transport")
    if transport is None:
        return None
    ssl_object = transport.get_extra_info("ssl_object")
    if ssl_object is None:
        return None
    return ssl_object.getpeercert()


def _coherence_kg_dir() -> Path | None:
    """Best-effort KG dir resolution for TrustDomain-derived peers."""
    from . import kg_coherence_api
    if kg_coherence_api._kg_dir is not None:
        return kg_coherence_api._kg_dir
    env = os.environ.get("CALM_FORGE_KG_DIR")
    return Path(env) if env else None


def _norm(value: str) -> str:
    return value.strip().removeprefix("trust_domain:")
