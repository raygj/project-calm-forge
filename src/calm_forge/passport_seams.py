"""Walk/run seams — interfaces now, live bodies later (APP-080…084).

Crawl deliberately ships *shapes* for the things walk and run will need, each with an
implementation that is honest about being a stub. The point is that going live is a
**provider/adapter swap, not a rewrite** — nothing here fakes capability we don't have.

  APP-080  IdentityProvider + WorkloadApiClient  static keypair → SPIRE (provider built + mock-tested; live socket adapter pending lab)
  APP-081  renewal_due() + renew_due_passports()  reporter + re-attestation loop ✅ walk-landed
  APP-082  EdgeSource            file-based single source   → live 3-way federated join
  APP-093  InventoryEdgeSource   file-backed listener table → live ACM / k8s / tfstate feed
  APP-083  EnforcementAdapter    emit-only (refuses push)   → FortiOS REST push
  APP-084  zone_of() + enforcement_decision()  blast-radius classification + safety matrix ✅ walk-landed (advisory; push still stubbed)
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .passport import SigningKey


class SeamNotAvailable(NotImplementedError):
    """Raised by a walk/run seam that has no crawl-stage implementation."""


class EnforcementRefused(RuntimeError):
    """Raised when something tries to push in an emit-only posture."""


# ---------------------------------------------------------------------------
# APP-080 — identity / attestation
# ---------------------------------------------------------------------------

class IdentityProvider(ABC):
    """Where a passport's signing identity comes from.

    Passport issuance depends on this interface, never on a concrete key, so adopting
    SPIRE is a provider swap that never touches emit code.
    """

    @abstractmethod
    def signing_key(self) -> SigningKey: ...

    @abstractmethod
    def spiffe_id(self) -> str: ...

    @property
    @abstractmethod
    def attestation_level(self) -> str:
        """How strongly the identity is attested — recorded, not assumed."""


class StaticKeypairProvider(IdentityProvider):
    """Crawl: a local keypair standing in for an SVID. **Not attested.**"""

    def __init__(self, key: SigningKey, issuer: str):
        self._key = key
        self._issuer = issuer

    def signing_key(self) -> SigningKey:
        return self._key

    def spiffe_id(self) -> str:
        return self._issuer

    @property
    def attestation_level(self) -> str:
        return "static-key"  # honest: no workload attestation happened


@dataclass(frozen=True)
class Svid:
    """An X.509-SVID reduced to what passport issuance needs.

    ``private_key`` is the workload key SPIRE delivered — an EC P-256 key in the standard SPIRE
    config, though Ed25519 is also accepted; ``spiffe_id`` is the URI SAN of the leaf
    certificate. The trust bundle and cert chain aren't needed to *sign* a passport (the
    verifier trusts the embedded public key / a JWKS), so they're intentionally omitted.
    """

    private_key: SigningKey
    spiffe_id: str


class WorkloadApiClient(ABC):
    """The seam to a SPIRE Workload API. Injected so the provider is testable without a socket.

    Crawl/tests supply a mock. The live adapter (pyspiffe / grpc over the agent's unix socket)
    is a thin implementation written once the endpoint + trust domain are known — it does not
    change ``SpireWorkloadApiProvider``.
    """

    @abstractmethod
    def fetch_x509_svid(self) -> Svid:
        """Return the current X.509-SVID for this workload (may rotate between calls)."""


class SpireWorkloadApiProvider(IdentityProvider):
    """Walk: signing identity fetched from a live SPIRE Workload API (APP-080).

    Depends on a :class:`WorkloadApiClient`, never a concrete socket, so the same provider
    runs against a mock in tests and the lab agent in production. The SVID is fetched once and
    cached (identity must be consistent within one passport); :meth:`refresh` re-fetches after
    rotation.

    **Key type.** The passport proof scheme is algorithm-aware (APP-080): the SVID's own key
    signs the passport — EC P-256 → ``ecdsa-p256`` (ES256), Ed25519 → ``ed25519``. The standard
    SPIRE config issues EC P-256 SVIDs (confirmed against the home-lab trust domain). An
    unsupported key type (e.g. RSA) is rejected by ``sign_passport`` rather than mis-signed.
    """

    def __init__(self, client: WorkloadApiClient, *, trust_domain: str | None = None):
        self._client = client
        self._trust_domain = trust_domain
        self._cached: Svid | None = None

    def refresh(self) -> None:
        """Drop the cached SVID so the next call re-fetches (SVID rotation)."""
        self._cached = None

    def _svid(self) -> Svid:
        if self._cached is None:
            svid = self._client.fetch_x509_svid()
            if self._trust_domain and not svid.spiffe_id.startswith(
                f"spiffe://{self._trust_domain}/"
            ):
                raise SeamNotAvailable(
                    f"SVID {svid.spiffe_id!r} is not in the expected trust domain "
                    f"{self._trust_domain!r} — refusing to sign under an unexpected identity."
                )
            self._cached = svid
        return self._cached

    def signing_key(self) -> SigningKey:
        return self._svid().private_key

    def spiffe_id(self) -> str:
        return self._svid().spiffe_id

    @property
    def attestation_level(self) -> str:
        return "spire-svid"


# ---------------------------------------------------------------------------
# APP-081 — renewal / re-attestation
# ---------------------------------------------------------------------------

def renewal_due(
    passports: list[dict[str, Any]], now: int, within_days: int = 30
) -> list[dict[str, Any]]:
    """Report passports whose grant lapses within the window — **reports only**.

    Crawl does not renew anything; it tells you what *would* renew. Walk turns this into
    the re-attestation loop, where renewal == re-attestation (the staged-crypto auto-pardon)
    and expiry — not a grace timer — is what drives contraction.
    """
    horizon = now + within_days * 86400
    due = [
        p for p in passports
        if p.get("claim", {}).get("claim_type") == "grant"
        and now < p["lifecycle"]["expires_at"] <= horizon
    ]
    return sorted(due, key=lambda p: p["lifecycle"]["expires_at"])


def expired(passports: list[dict[str, Any]], now: int) -> list[dict[str, Any]]:
    """Grants already lapsed at ``now`` — contraction candidates by expiry."""
    return [
        p for p in passports
        if p.get("claim", {}).get("claim_type") == "grant"
        and p["lifecycle"]["expires_at"] <= now
    ]


def renew_due_passports(
    passports: list[dict[str, Any]],
    private_key: Ed25519PrivateKey,
    issuer: str,
    *,
    now: int,
    within_days: int = 30,
    ttl_days: int = 90,
) -> list[dict[str, Any]]:
    """The re-attestation loop: renew every grant lapsing within ``within_days``.

    This is the *action* ``renewal_due`` was built to feed — walk turns the report into a
    control loop. Each due grant is re-signed with a lifecycle window of ``ttl_days`` from
    ``now``; the renewed passport keeps the original's ``edge_id`` and so supersedes it in
    the reverse diff. Grants not yet due are left untouched (renewal is not re-issue).

    ``private_key``/``issuer`` are passed explicitly — the same signing path emit uses.
    Swapping in a live SPIRE-backed identity is the separate APP-080 seam, not this loop.
    """
    from .passport import renew_passport

    expires_at = now + ttl_days * 86400
    return [
        renew_passport(grant, private_key, issuer, issued_at=now, expires_at=expires_at)
        for grant in renewal_due(passports, now, within_days=within_days)
    ]


# ---------------------------------------------------------------------------
# APP-082 — edge sources / the federated join
# ---------------------------------------------------------------------------

class EdgeSource(ABC):
    """One contributor to the edge set. Run joins Forge / SPIRE / inventory across these."""

    @property
    @abstractmethod
    def provenance(self) -> str:
        """`declared` | `observed` | `inventory` — matches graph_ref.source."""

    @abstractmethod
    def edges(self) -> list[dict[str, Any]]: ...


class InventoryEdgeSource(EdgeSource):
    """A record of what the running fabric actually listens on (APP-093).

    The first *real* second source in the join, and the shape the fabric actually
    hands us: inventory knows **listeners per workload** (a Kubernetes Service, a
    Terraform ``aws_lb_listener``, a CMDB port register), not edges. One listener
    record therefore resolves every declared edge pointing at that workload.

    Explicit per-edge records are also accepted and win over a listener, because
    an operator who wrote down *this* path meant *this* path.

    Inventory is evidence about the fabric, never a substitute for intent. A port
    learned here is stamped ``port_source="inventory"`` so a reader can always
    tell a declared port from an observed one, and so "declare this properly"
    stays a visible piece of work rather than being quietly closed.
    """

    def __init__(self, records: list[dict[str, Any]]):
        self._records = list(records)

    @property
    def provenance(self) -> str:
        return "inventory"

    def edges(self) -> list[dict[str, Any]]:
        return list(self._records)

    def listeners(self) -> dict[tuple[str, str], list[int]]:
        """``(workload_urn, transport) -> sorted distinct ports it listens on``."""
        table: dict[tuple[str, str], set[int]] = {}
        for rec in self._records:
            urn = rec.get("workload_urn") or rec.get("destination_workload_urn")
            port = rec.get("port")
            if not urn or port is None:
                continue
            key = (str(urn).lower(), str(rec.get("transport", "tcp")).lower())
            table.setdefault(key, set()).add(int(port))
        return {k: sorted(v) for k, v in table.items()}

    def edge_ports(self) -> dict[tuple[str, str, str], int]:
        """``(src_urn, dst_urn, transport) -> port`` for explicit per-edge records."""
        table: dict[tuple[str, str, str], int] = {}
        for rec in self._records:
            src, dst, port = (
                rec.get("source_workload_urn"),
                rec.get("destination_workload_urn"),
                rec.get("port"),
            )
            if not src or not dst or port is None:
                continue
            table[(str(src).lower(), str(dst).lower(),
                   str(rec.get("transport", "tcp")).lower())] = int(port)
        return table


def load_inventory(path: str | Path) -> InventoryEdgeSource:
    """Read an inventory file — a JSON list, or ``{"listeners": [...]}``."""
    data = json.loads(Path(path).read_text())
    if isinstance(data, dict):
        records = data.get("listeners") or data.get("records") or data.get("edges") or []
    else:
        records = data
    return InventoryEdgeSource(records)


def resolve_ports_from_inventory(
    edges: list[dict[str, Any]], inventory: InventoryEdgeSource
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Fill unresolved ports from inventory. Returns ``(edges, unresolved)``.

    Only edges the compiler could not resolve from intent are touched — inventory
    never overrides a declared port, because intent is the contract and inventory
    is a report about the fabric. Where the two disagree, that is drift for the
    reverse diff to surface, not something to silently reconcile here.

    **Ambiguity is left unresolved on purpose.** A workload listening on three
    ports does not tell us which one this edge uses; picking one would fabricate a
    precise claim out of imprecise evidence. The edge stays a reported gap.
    """
    listeners = inventory.listeners()
    edge_ports = inventory.edge_ports()
    resolved: list[dict[str, Any]] = []
    still_unresolved: list[dict[str, Any]] = []

    for edge in edges:
        if not edge.get("port_unspecified"):
            resolved.append(edge)
            continue
        src = str(edge.get("source_workload_urn", "")).lower()
        dst = str(edge.get("destination_workload_urn", "")).lower()
        transport = str(edge.get("transport", "tcp")).lower()

        port = edge_ports.get((src, dst, transport))
        if port is None:
            candidates = listeners.get((dst, transport), [])
            if len(candidates) == 1:
                port = candidates[0]
            elif len(candidates) > 1:
                edge = {**edge, "port_ambiguous": candidates}

        if port is None:
            still_unresolved.append(edge)
            resolved.append(edge)
            continue

        filled = {k: v for k, v in edge.items() if k not in ("port_unspecified", "port_ambiguous")}
        filled["port"] = port
        filled["port_source"] = "inventory"
        resolved.append(filled)

    return resolved, still_unresolved


class FileEdgeSource(EdgeSource):
    """Crawl: the degenerate single-source case of the same interface.

    Run performs a live 3-way join across several EdgeSources. **Flag for walk:** a
    fail-closed join needs a floor — "any edge breaks → block" over a *federated query*
    turns a network blip into an outage. Moot while offline; wire the floor before the
    join goes live.
    """

    def __init__(self, edges: list[dict[str, Any]], provenance: str = "declared"):
        self._edges = edges
        self._provenance = provenance

    @property
    def provenance(self) -> str:
        return self._provenance

    def edges(self) -> list[dict[str, Any]]:
        return list(self._edges)


# ---------------------------------------------------------------------------
# APP-083 — enforcement / push
# ---------------------------------------------------------------------------

class EnforcementAdapter(ABC):
    """How a candidate config reaches (or deliberately does not reach) a device."""

    @abstractmethod
    def emit(self, artifacts: dict[str, str], out_dir: str | Path) -> list[Path]: ...

    @abstractmethod
    def push(self, artifacts: dict[str, str]) -> None: ...


class EmitOnlyAdapter(EnforcementAdapter):
    """Crawl: writes files and **structurally refuses to push**.

    Emit-only is enforced by the type, not by a promise in a doc.
    """

    def emit(self, artifacts: dict[str, str], out_dir: str | Path) -> list[Path]:
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        written = []
        for name, content in artifacts.items():
            path = out / name
            path.write_text(content)
            written.append(path)
        return written

    def push(self, artifacts: dict[str, str]) -> None:
        raise EnforcementRefused(
            "Crawl is emit-only — nothing is pushed to a device. Push is a walk/run "
            "capability (APP-083); it will validate against the same FortiOS payload "
            "schema this config already emits."
        )


class FortiOSPushAdapter(EnforcementAdapter):
    """Walk: pushes via the FortiOS REST API. Not implemented in crawl."""

    def __init__(self, endpoint: str, token: str | None = None):
        self.endpoint = endpoint
        self.token = token

    def emit(self, artifacts: dict[str, str], out_dir: str | Path) -> list[Path]:
        return EmitOnlyAdapter().emit(artifacts, out_dir)

    def push(self, artifacts: dict[str, str]) -> None:
        raise SeamNotAvailable(
            "Live push is a walk-stage capability (APP-083). The contract is already "
            "defined by the emitted FortiOS objects; going live is an adapter swap."
        )


# ---------------------------------------------------------------------------
# APP-084 — blast radius / zones
# ---------------------------------------------------------------------------

# Blast-radius zones, ordered high → low. A zone is *how much damage a wrong
# enforcement action does* — the higher the blast radius, the more human-in-the-loop.
# Derived from signal the passport already carries (intent_metadata); no new field.
ZONE_REGULATED = "regulated"    # compliance-scoped or sensitive data — regulatory blast radius
ZONE_PRODUCTION = "production"  # prod, no special sensitivity — availability blast radius
ZONE_NONPROD = "nonprod"        # staging / dev / test — low blast radius
ZONE_UNZONED = "unzoned"        # unclassifiable — the fail-safe; never auto-acts

_SENSITIVE_DATA_CLASSES = frozenset({"restricted", "confidential"})
_NONPROD_ENVIRONMENTS = frozenset({"staging", "development", "test"})


def zone_of(passport: dict[str, Any]) -> str:
    """Classify a passport into a blast-radius zone from its intent metadata (APP-084).

    Rules, highest blast radius wins:
      - ``regulated``  — a non-empty ``compliance_scope`` OR a sensitive ``data_classification``
                         (``restricted``/``confidential``). A wrong action here is a compliance
                         event.
      - ``production`` — ``environment == production`` with no special sensitivity.
      - ``nonprod``    — ``environment`` in {staging, development, test}.
      - ``unzoned``    — no usable signal. The fail-safe: it never auto-acts (see the matrix).

    Reads the same ``intent_metadata`` the emitter already stamps, so classification needs no
    new field and no second source of truth. A dict without that metadata → ``unzoned``.
    """
    meta = passport.get("intent_metadata", {})
    if meta.get("compliance_scope") or meta.get("data_classification") in _SENSITIVE_DATA_CLASSES:
        return ZONE_REGULATED
    env = meta.get("environment")
    if env == "production":
        return ZONE_PRODUCTION
    if env in _NONPROD_ENVIRONMENTS:
        return ZONE_NONPROD
    return ZONE_UNZONED


# The safety model, as data — (zone, authority_class) → what Run *would* do.
#
# Two axes: blast radius (the zone) and reversibility (authority_class — contraction is
# autonomic and reversible; expansion is a grant and governed). Blast radius modulates how
# much autonomy each gets:
#   - unzoned    → propose only. Unknown blast radius ⇒ never act. The fail-safe.
#   - nonprod    → auto both ways. Low blast radius; move fast.
#   - production → auto-enforce reversible contraction; expansion goes to human review.
#   - regulated  → human review either way. ⚠ RATIFY: this is the conservative choice — it
#                  sends even reversible contraction to review. If tightening an over-grant
#                  in a regulated zone should be auto (contraction only ever *removes* access,
#                  which improves compliance), flip the ``(regulated, contraction)`` cell to
#                  ``auto-enforce``. Left conservative pending sign-off.
#
# Nothing here *executes* — enforcement (push) is still the APP-083 stub, which refuses. These
# are the decision labels the graph carries; they become live when the push adapter does.
_ENFORCEMENT_MATRIX: dict[tuple[str, str], str] = {
    (ZONE_UNZONED, "autonomic-contraction"): "propose",
    (ZONE_UNZONED, "governed-expansion"): "propose",
    (ZONE_NONPROD, "autonomic-contraction"): "auto-enforce",
    (ZONE_NONPROD, "governed-expansion"): "auto-enforce",
    (ZONE_PRODUCTION, "autonomic-contraction"): "auto-enforce",
    (ZONE_PRODUCTION, "governed-expansion"): "governed-review",
    (ZONE_REGULATED, "autonomic-contraction"): "governed-review",
    (ZONE_REGULATED, "governed-expansion"): "governed-review",
}


def enforcement_decision(zone: str, authority_class: str) -> str:
    """What Run *would* do for this ``(zone, authority_class)`` pair (APP-084).

    A lookup into ``_ENFORCEMENT_MATRIX``. An unknown zone falls back to ``propose`` — an
    unclassifiable edge is treated like ``unzoned``, never auto-acted on. Still advisory:
    the push seam (APP-083) refuses, so no decision here executes yet.
    """
    return _ENFORCEMENT_MATRIX.get((zone, authority_class), "propose")
