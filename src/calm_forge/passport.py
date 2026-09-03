"""Attested Policy Passport — builder, signing, verification (APP-002/010/011).

A passport is the signed, identity-anchored, graph-referenced projection of a KG
edge. This module turns a normalized edge + intent into a passport body, signs it
(Ed25519 over the JCS-canonicalized body with ``proof`` excluded), and verifies
it. Edge identity comes from :mod:`calm_forge.edge_id` — the single source of
truth shared with the reverse diff, so a claim and an observation of the same L4
edge hash identically.

Crawl-stage posture: static local keypair (mock SVID; no live SPIRE), stubbed
single-key JWKS. SPIFFE ids are constructed as *should-be* identities from the
workload's namespace/component, not read from a live Workload API.
"""
from __future__ import annotations

import base64
import json
import uuid
from importlib import resources
from pathlib import Path
from typing import Any

import jsonschema
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .edge_id import (
    PORT_SOURCE_INTERFACE,
    PORT_SOURCE_OVERRIDE,
    PORT_SOURCE_PROTOCOL_DEFAULT,
    PORT_SOURCE_UNRESOLVED,
    PORT_SOURCE_WILDCARD,
    default_port_for,
    edge_id_for_binding,
    port_from_interface,
    workload_urn,
)

# Signing keys a passport proof can be produced with. Ed25519 is the crawl/demo
# default (deterministic, byte-stable goldens); ECDSA P-256 is what SPIRE issues
# as X509-SVID leaf keys (APP-080), so an attested workload signs with its own SVID.
SigningKey = Ed25519PrivateKey | ec.EllipticCurvePrivateKey

ALGORITHM_ED25519 = "ed25519"
ALGORITHM_ECDSA_P256 = "ecdsa-p256"

PASSPORT_VERSION = "0.1"
PASSPORT_VERSION_V2 = "0.2"


class UnknownPassportVersion(ValueError):
    """Raised when a passport declares a wire version this build does not know (MP-02).

    Deliberately fatal rather than a fallback. A reader that dispatches on
    ``passport_version`` but defaults to the v0.1 branch reads a v0.2 passport as having
    no ``graph_ref``, treats the edge as unclaimed, and turns a valid grant into a
    phantom contraction candidate — a silent conversion of authorization into a
    deletion recommendation. Fail loudly instead (ADR-006 Risks).
    """


class PlaneWaiverError(ValueError):
    """Raised when a production passport waives a plane (ADR-005 §5, MP-04)."""


# L4 transport inference. Everything enterprise here rides TCP; the handful of
# UDP protocols are enumerated so the common case stays a safe default.
_UDP_PROTOCOLS = {"dns", "ntp", "syslog", "dhcp", "quic"}

_SCHEMA: dict[str, Any] = json.loads(
    resources.files("calm_forge.schemas").joinpath("passport.schema.json").read_text()
)
_SCHEMA_V2: dict[str, Any] = json.loads(
    resources.files("calm_forge.schemas").joinpath("passport-v0.2.schema.json").read_text()
)


# ---------------------------------------------------------------------------
# Canonicalization, keys, schema
# ---------------------------------------------------------------------------

def canonicalize(body: dict[str, Any]) -> bytes:
    """RFC 8785 (JCS) canonical JSON for the passport body.

    The passport body's values are only str / int / float / bool / list / dict,
    so sorted keys + compact separators reproduce JCS for this subset.
    """
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def validate_passport(passport: dict[str, Any]) -> None:
    """Raise ``jsonschema.ValidationError`` if the passport violates its schema.

    Dispatches on ``passport_version`` (MP-02). Unknown versions raise
    :class:`UnknownPassportVersion` rather than falling back to v0.1 — see that class.

    v0.2 adds a governance rule JSON Schema cannot express: production admits no plane
    waiver (ADR-005 §5). A production passport carrying ``absent: policy`` is
    well-formed and still wrong, so the check lives here.
    """
    version = passport.get("passport_version")
    if version == PASSPORT_VERSION:
        jsonschema.validate(passport, _SCHEMA)
        return
    if version == PASSPORT_VERSION_V2:
        jsonschema.validate(passport, _SCHEMA_V2)
        _validate_plane_waivers(passport)
        return
    raise UnknownPassportVersion(
        f"unknown passport_version {version!r} — refusing to guess. Known versions: "
        f"{PASSPORT_VERSION}, {PASSPORT_VERSION_V2}"
    )


def _validate_plane_waivers(passport: dict[str, Any]) -> None:
    """Production admits no ``absent: policy`` marker (ADR-005 §5, ADR-006 §3, MP-04).

    Below production a waiver is a governed statement about *this environment's*
    requirements; production has none to relax, so the marker is meaningless there and
    a schema that passes it is the easiest thing to mistake for a document that is right.
    """
    if passport.get("intent_metadata", {}).get("environment") != "production":
        return
    waived = sorted(
        plane
        for plane, ref in passport.get("graph_refs", {}).items()
        if isinstance(ref, dict) and ref.get("absent") == "policy"
    )
    if waived:
        raise PlaneWaiverError(
            f"production passport waives plane(s) {waived} — production requires every "
            f"plane and admits no waiver above staging (ADR-005 §5)"
        )


def graph_ref_for_plane(passport: dict[str, Any], plane: str = "architecture") -> dict[str, Any]:
    """The provenance reference for one plane, across wire versions (MP-02).

    v0.1 has a single ``graph_ref`` and it is the architecture plane's by construction;
    v0.2 keys them by plane under ``graph_refs``. Returns ``{}`` when the plane is
    absent-by-policy or unauthored — callers distinguish those via ``graph_refs``
    directly, because collapsing them here would undo the distinction ADR-005 §5 exists
    to preserve.
    """
    version = _require_known_version(passport)
    if version == PASSPORT_VERSION:
        return passport.get("graph_ref", {}) if plane == "architecture" else {}
    ref = passport.get("graph_refs", {}).get(plane, {})
    return ref if "node_id" in ref else {}


def edge_id_of(passport: dict[str, Any]) -> str:
    """The architecture-plane edge id — the join key for diff, emit, and filenames.

    One accessor so the reverse diff, the Fortinet writer, and ``write_passport`` cannot
    drift apart on where the id lives. v0.1 spells it ``graph_ref.edge_id``; v0.2 spells
    it ``graph_refs.architecture.node_id``. Same value, and ADR-006 §4 requires it stay
    byte-identical across the bump.
    """
    version = _require_known_version(passport)
    if version == PASSPORT_VERSION:
        return str(passport["graph_ref"]["edge_id"])
    return str(passport["graph_refs"]["architecture"]["node_id"])


def _require_known_version(passport: dict[str, Any]) -> str:
    version = passport.get("passport_version")
    if version not in (PASSPORT_VERSION, PASSPORT_VERSION_V2):
        raise UnknownPassportVersion(
            f"unknown passport_version {version!r} — refusing to guess. Known versions: "
            f"{PASSPORT_VERSION}, {PASSPORT_VERSION_V2}"
        )
    return str(version)


def generate_keypair() -> Ed25519PrivateKey:
    """Generate a fresh Ed25519 signing key (dev / crawl mock SVID)."""
    return Ed25519PrivateKey.generate()


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} is not an Ed25519 private key")
    return key


def save_private_key(key: Ed25519PrivateKey, path: str | Path) -> None:
    """Write an unencrypted PEM. Dev/crawl only — real key custody is walk/run."""
    Path(path).write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


def algorithm_for_key(key: SigningKey) -> str:
    """The proof ``algorithm`` string for a signing key, or reject an unsupported type."""
    if isinstance(key, Ed25519PrivateKey):
        return ALGORITHM_ED25519
    if isinstance(key, ec.EllipticCurvePrivateKey):
        if not isinstance(key.curve, ec.SECP256R1):
            raise ValueError(f"unsupported EC curve {key.curve.name}; passports use P-256 (ES256)")
        return ALGORITHM_ECDSA_P256
    raise ValueError(f"unsupported signing key type {type(key).__name__}; use Ed25519 or EC P-256")


def public_key_b64(key: SigningKey) -> str:
    """Base64 public key for the proof. Ed25519 → raw 32 bytes (unchanged); EC P-256 → SPKI DER.

    Two encodings because Ed25519 has a canonical raw form and existing passports embed it;
    an EC public key has no single raw form, so it rides as DER SubjectPublicKeyInfo.
    """
    if isinstance(key, Ed25519PrivateKey):
        raw = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return base64.b64encode(raw).decode()
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(spki).decode()


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------

def sign_passport(body: dict[str, Any], private_key: SigningKey, issuer: str) -> dict[str, Any]:
    """Return a copy of ``body`` with a ``proof`` block over its canonical form.

    The proof records which ``algorithm`` produced it (``ed25519`` or ``ecdsa-p256``), so a
    verifier need not know the key type in advance. Ed25519 output is byte-identical to before.
    """
    unsigned = {k: v for k, v in body.items() if k != "proof"}
    canonical = canonicalize(unsigned)
    algorithm = algorithm_for_key(private_key)
    if isinstance(private_key, Ed25519PrivateKey):
        signature = private_key.sign(canonical)
    else:
        signature = private_key.sign(canonical, ec.ECDSA(hashes.SHA256()))
    return {
        **unsigned,
        "proof": {
            "issuer": issuer,
            "algorithm": algorithm,
            "canonicalization": "jcs",
            "public_key_b64": public_key_b64(private_key),
            "signature_b64": base64.b64encode(signature).decode(),
        },
    }


def verify_passport(passport: dict[str, Any], public_key_b64_override: str | None = None) -> bool:
    """Verify the signature over the canonical body (``proof`` excluded).

    Dispatches on ``proof.algorithm``: ``ed25519`` (raw key) or ``ecdsa-p256`` (SPKI DER key,
    ES256). Uses the embedded ``public_key_b64`` unless an override is supplied (e.g. a trusted
    key from a JWKS — walk/run). Returns True/False; does not raise on a bad signature.
    """
    proof = passport.get("proof")
    if not proof:
        return False
    pub_b64 = public_key_b64_override or proof.get("public_key_b64")
    if not pub_b64:
        return False
    algorithm = proof.get("algorithm", ALGORITHM_ED25519)
    body = {k: v for k, v in passport.items() if k != "proof"}
    canonical = canonicalize(body)
    signature = base64.b64decode(proof["signature_b64"])
    key_bytes = base64.b64decode(pub_b64)
    try:
        if algorithm == ALGORITHM_ED25519:
            Ed25519PublicKey.from_public_bytes(key_bytes).verify(signature, canonical)
        elif algorithm == ALGORITHM_ECDSA_P256:
            pub = serialization.load_der_public_key(key_bytes)
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                return False
            pub.verify(signature, canonical, ec.ECDSA(hashes.SHA256()))
        else:
            return False
        return True
    except (InvalidSignature, ValueError):
        # InvalidSignature: bad signature. ValueError: malformed key/signature bytes (wrong
        # length, bad base64, wrong curve). A verifier returns False on junk, never raises.
        return False


# ---------------------------------------------------------------------------
# Body assembly
# ---------------------------------------------------------------------------

def transport_for(app_protocol: str | None) -> str:
    return "udp" if app_protocol and app_protocol.lower() in _UDP_PROTOCOLS else "tcp"


def build_network_binding(edge: dict[str, Any]) -> dict[str, Any]:
    """Assemble a ``network_binding`` from a normalized edge dict.

    ``edge`` carries workload names + URNs, optional SPIFFE ids, ``transport``,
    exactly one of ``port`` / ``port_range`` / ``port_wildcard`` /
    ``port_unspecified``, an optional ``app_protocol`` list and
    ``authentication``, and ``direction``.

    ``port_source`` records *how* the port was arrived at, so a consumer can
    tell a port declared in intent from one inferred or learned from the running
    fabric (APP-090). It is descriptive, never part of edge identity.
    """
    binding: dict[str, Any] = {
        "source_workload": edge["source_workload"],
        "source_workload_urn": edge["source_workload_urn"],
        "destination_workload": edge["destination_workload"],
        "destination_workload_urn": edge["destination_workload_urn"],
        "transport": edge.get("transport", "tcp"),
        "direction": edge.get("direction", "egress"),
    }
    for opt in ("source_spiffe_id", "destination_spiffe_id", "app_protocol", "authentication"):
        if edge.get(opt):
            binding[opt] = edge[opt]
    if edge.get("port_wildcard"):
        binding["port_wildcard"] = True
        default_source = PORT_SOURCE_WILDCARD
    elif edge.get("port_unspecified"):
        binding["port_unspecified"] = True
        default_source = PORT_SOURCE_UNRESOLVED
    elif edge.get("port_range") is not None:
        binding["port_range"] = edge["port_range"]
        default_source = PORT_SOURCE_INTERFACE
    else:
        binding["port"] = int(edge["port"])
        default_source = PORT_SOURCE_INTERFACE
    binding["port_source"] = edge.get("port_source") or default_source
    return binding


def build_passport_body(
    edge: dict[str, Any],
    intent: dict[str, Any],
    *,
    issued_at: int,
    expires_at: int,
    claim: dict[str, Any] | None = None,
    ownership: dict[str, Any] | None = None,
    passport_id: str | None = None,
    version: str = PASSPORT_VERSION,
    plane_refs: dict[str, dict[str, Any]] | None = None,
    plane_nodes: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assemble an unsigned passport body from a normalized edge + intent.

    Defaults encode the safe crawl posture: a ``grant`` that is ``should-be`` and
    ``governed-expansion``. The architecture-plane edge id is derived from the binding,
    so it can never disagree with the reverse diff.

    ``version`` selects the wire format (MP-03). v0.1 emits a single ``graph_ref``;
    v0.2 emits ``graph_refs`` keyed by plane, with the *same* architecture edge id
    relocated to ``graph_refs.architecture.node_id`` — a relocation, not a
    re-identification (ADR-006 §4).

    ``plane_refs`` supplies non-architecture planes for v0.2: either a provenance
    reference or an ``{"absent": "policy", "waived_by": ...}`` marker. Omitting a plane
    entirely means *missing* — required-but-unauthored — which is a drift finding rather
    than a governed statement, so the emitter never invents an absence marker to fill a
    gap it merely does not know about.

    ``plane_nodes`` maps ``node_id`` → the plane node document as read from the graph.
    When supplied, each matching reference is stamped with ``node_version``, the node's
    content digest at signing time (ADR-006 §5, MP-14) — which is what makes
    ``STALE_ATTESTATION`` computable for this passport later. A reference whose node is
    not supplied is left without a version rather than given a fabricated one: a digest
    that does not correspond to real content would make a stale passport look fresh.
    """
    if version not in (PASSPORT_VERSION, PASSPORT_VERSION_V2):
        raise UnknownPassportVersion(
            f"cannot emit passport_version {version!r} — known versions: "
            f"{PASSPORT_VERSION}, {PASSPORT_VERSION_V2}"
        )
    binding = build_network_binding(edge)

    graph_ref: dict[str, Any] = {
        "edge_id": edge_id_for_binding(binding),
        "source": edge.get("graph_source", "declared"),
        "confidence": edge.get("confidence", 1.0),
    }
    if edge.get("authored_by"):
        graph_ref["authored_by"] = edge["authored_by"]
    if edge.get("authored_at"):
        graph_ref["authored_at"] = edge["authored_at"]

    intent_metadata: dict[str, Any] = {
        "business_justification": intent["business_justification"],
        "environment": intent["environment"],
        "requested_by": intent["requested_by"],
    }
    for opt in ("ticket_id", "compliance_scope", "data_classification"):
        if intent.get(opt):
            intent_metadata[opt] = intent[opt]

    body: dict[str, Any] = {
        "passport_version": version,
        "passport_id": passport_id or str(uuid.uuid4()),
        "spiffe_id": edge.get("source_spiffe_id") or intent["requested_by"],
        "intent_metadata": intent_metadata,
        "network_binding": binding,
        "claim": claim
        or {
            "claim_type": "grant",
            "tense": "should-be",
            "authority_class": "governed-expansion",
        },
        "lifecycle": {"issued_at": int(issued_at), "expires_at": int(expires_at)},
    }

    if version == PASSPORT_VERSION:
        body["graph_ref"] = graph_ref
    else:
        architecture = {"node_id": graph_ref.pop("edge_id"), **graph_ref}
        graph_refs = {"architecture": architecture, **(plane_refs or {})}
        if plane_nodes:
            _stamp_node_versions(graph_refs, plane_nodes)
        body["graph_refs"] = graph_refs

    # lifecycle sits after graph state in both versions; re-order so the emitted key
    # sequence matches the checked-in references rather than dict insertion accident
    ordered: dict[str, Any] = {}
    for key in ("passport_version", "passport_id", "spiffe_id", "intent_metadata",
                "network_binding", "claim", "graph_ref", "graph_refs", "lifecycle"):
        if key in body:
            ordered[key] = body[key]
    body = ordered

    if ownership:
        body["ownership"] = {k: v for k, v in ownership.items() if v}
    return body


def _stamp_node_versions(
    graph_refs: dict[str, dict[str, Any]],
    plane_nodes: dict[str, dict[str, Any]],
) -> None:
    """Stamp ``node_version`` on every reference whose node was supplied (MP-14).

    Absence markers are skipped — a waiver references no node, so it has no content to
    digest. A reference whose node is absent from ``plane_nodes`` is left unstamped:
    inventing a digest would make a stale passport look fresh, which is the one failure
    mode this field exists to prevent.
    """
    from .kg_plane import plane_node_version

    for ref in graph_refs.values():
        node_id = ref.get("node_id")
        if not node_id or node_id not in plane_nodes:
            continue
        ref["node_version"] = plane_node_version(plane_nodes[node_id])


def build_passport(
    edge: dict[str, Any],
    intent: dict[str, Any],
    private_key: Ed25519PrivateKey,
    issuer: str,
    *,
    issued_at: int,
    expires_at: int,
    claim: dict[str, Any] | None = None,
    ownership: dict[str, Any] | None = None,
    passport_id: str | None = None,
    validate: bool = True,
    version: str = PASSPORT_VERSION,
    plane_refs: dict[str, dict[str, Any]] | None = None,
    plane_nodes: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build, sign, and (by default) schema-validate a passport in one call.

    ``version`` / ``plane_refs`` are passed through to :func:`build_passport_body`.
    Validation dispatches on the emitted version, so a v0.2 body is checked against the
    v0.2 schema *and* the production-waiver rule.
    """
    body = build_passport_body(
        edge,
        intent,
        issued_at=issued_at,
        expires_at=expires_at,
        claim=claim,
        ownership=ownership,
        passport_id=passport_id,
        version=version,
        plane_refs=plane_refs,
        plane_nodes=plane_nodes,
    )
    passport = sign_passport(body, private_key, issuer)
    if validate:
        validate_passport(passport)
    return passport


# ---------------------------------------------------------------------------
# KG Workload adapter — normalize WorkloadRelationships into edges
# ---------------------------------------------------------------------------

def _system_component(node_id: str) -> tuple[str, str]:
    """Split ``workload:<system>:<component>`` → (system, component).

    The SPIFFE namespace is derived from the same ``system`` the workload URN uses,
    so the constructed SPIFFE id and the URN never disagree (the doc-level ``name``
    may be spelled differently, e.g. ``3-tier-pci`` vs the id's ``3tier-pci``).
    """
    parts = node_id.split(":")
    if parts[0] in ("workload", "service", "node") and len(parts) >= 3:
        return parts[1], parts[2]
    return "", node_id


def _spiffe_id(trust_domain: str, namespace: str, component: str) -> str:
    return f"spiffe://{trust_domain}/ns/{namespace}/sa/{component}"


def _resolve_port(
    protocol: str | None,
    interface: str | None,
    port_overrides: dict[tuple[str, str], int | str] | None,
    key: tuple[str, str],
) -> dict[str, Any]:
    """Resolution order (APP-000 §6): interface → override → protocol default → unresolved.

    Each outcome stamps ``port_source`` so the passport records the evidence
    behind its own port claim. Falling through to ``unresolved`` is an honest
    admission, not a wildcard grant — the diff refuses to adjudicate such an
    edge rather than inventing permission for it (APP-090/092).
    """
    if interface:
        port = port_from_interface(interface)
        if port is not None:
            return {"port": port, "port_source": PORT_SOURCE_INTERFACE}
    if port_overrides and key in port_overrides:
        override = port_overrides[key]
        # The sentinel "any" lets an operator author a *wildcard* — deliberate
        # permission for every port on this path — without it being mistaken
        # for the unresolved case they look identical to in the edge_id.
        if isinstance(override, str) and override.strip().lower() == "any":
            return {"port_wildcard": True, "port_source": PORT_SOURCE_WILDCARD}
        return {"port": int(override), "port_source": PORT_SOURCE_OVERRIDE}
    if protocol:
        default = default_port_for(protocol)
        if default is not None:
            return {"port": default, "port_source": PORT_SOURCE_PROTOCOL_DEFAULT}
    return {"port_unspecified": True, "port_source": PORT_SOURCE_UNRESOLVED}


def edges_from_kg_workload(
    kg_doc: dict[str, Any],
    *,
    trust_domain: str,
    port_overrides: dict[tuple[str, str], int | str] | None = None,
) -> list[dict[str, Any]]:
    """Normalize a KG Workload document's ``relationships`` into edge dicts.

    The workload ``name`` is the SPIFFE namespace and the graph source; compliance
    scope, owner, and provenance are lifted from the document so the resulting
    passports carry the promoted metadata (APP-001).
    """
    authored_by = kg_doc.get("_provenance", {}).get("authored_by")
    authored_at = kg_doc.get("_provenance", {}).get("authored_at")
    node_names = {n["@id"]: n.get("name", n["@id"]) for n in kg_doc.get("nodes", [])}

    edges: list[dict[str, Any]] = []
    for rel in kg_doc.get("relationships", []):
        src_id, dst_id = rel.get("from"), rel.get("to")
        if not src_id or not dst_id:
            continue
        src_name, dst_name = node_names.get(src_id, src_id), node_names.get(dst_id, dst_id)
        src_ns, src_comp = _system_component(src_id)
        dst_ns, dst_comp = _system_component(dst_id)
        protocol = rel.get("protocol")
        port_field = _resolve_port(protocol, None, port_overrides, (src_id, dst_id))

        edge: dict[str, Any] = {
            "source_workload": src_name,
            "source_workload_urn": workload_urn(src_id),
            "source_spiffe_id": _spiffe_id(trust_domain, src_ns, src_comp),
            "destination_workload": dst_name,
            "destination_workload_urn": workload_urn(dst_id),
            "destination_spiffe_id": _spiffe_id(trust_domain, dst_ns, dst_comp),
            "transport": transport_for(protocol),
            "direction": "egress",
            "graph_source": "declared",
            **port_field,
        }
        if protocol:
            edge["app_protocol"] = [protocol]
        if rel.get("authentication"):
            edge["authentication"] = rel["authentication"]
        if authored_by:
            edge["authored_by"] = authored_by
        if authored_at:
            edge["authored_at"] = authored_at
        edges.append(edge)
    return edges


def ownership_from_kg(kg_doc: dict[str, Any]) -> dict[str, Any]:
    """Lift the ownership block available in a KG Workload document."""
    return {"owner": kg_doc.get("owner"), "application_name": kg_doc.get("name")}


# ---------------------------------------------------------------------------
# CALM architecture adapter — normalize `connects` relationships into edges
# ---------------------------------------------------------------------------

def _slug(value: str) -> str:
    return "".join(c if c.isalnum() or c == "-" else "-" for c in value.strip().lower()).strip("-")


def _calm_endpoints(rel: dict[str, Any]) -> tuple[str, str, list[str], list[str]] | None:
    connects = rel.get("relationship-type", {}).get("connects")
    if not connects:
        return None
    src, dst = connects.get("source", {}), connects.get("destination", {})
    if not src.get("node") or not dst.get("node"):
        return None
    return src["node"], dst["node"], src.get("interfaces", []), dst.get("interfaces", [])


def edges_from_calm_architecture(
    architecture: dict[str, Any],
    *,
    trust_domain: str,
    system: str | None = None,
) -> list[dict[str, Any]]:
    """Normalize a CALM instantiation's ``connects`` relationships into edge dicts.

    CALM node ids are flat (``api-gateway``), so the workload URN and SPIFFE
    namespace are qualified by ``system`` — the application name (or an explicit
    override). The destination interface (``https-8443``) resolves the port.
    """
    metadata = architecture.get("metadata", {})
    system = _slug(system or metadata.get("application-name") or architecture.get("title", "app"))

    edges: list[dict[str, Any]] = []
    for rel in architecture.get("relationships", []):
        endpoints = _calm_endpoints(rel)
        if endpoints is None:
            continue
        src_node, dst_node, _src_ifaces, dst_ifaces = endpoints
        protocol = rel.get("protocol")
        interface = dst_ifaces[0] if dst_ifaces else None
        port_field = _resolve_port(protocol, interface, None, (src_node, dst_node))

        edge: dict[str, Any] = {
            "source_workload": src_node,
            "source_workload_urn": workload_urn(src_node, explicit=f"wl:{system}/{src_node}"),
            "source_spiffe_id": _spiffe_id(trust_domain, system, src_node),
            "destination_workload": dst_node,
            "destination_workload_urn": workload_urn(dst_node, explicit=f"wl:{system}/{dst_node}"),
            "destination_spiffe_id": _spiffe_id(trust_domain, system, dst_node),
            "transport": transport_for(protocol),
            "direction": "egress",
            "graph_source": "declared",
            **port_field,
        }
        if protocol:
            edge["app_protocol"] = [protocol]
        if rel.get("authentication"):
            edge["authentication"] = rel["authentication"]
        if rel.get("description"):
            edge["description"] = rel["description"]
        edges.append(edge)
    return edges


# CALM `metadata.data-classification` is free-form in the wild; the passport schema
# uses a fixed four-tier vocabulary. Map the domain terms we actually see, and omit
# the field for anything unrecognized rather than guessing — a data classification is
# a compliance claim, so a silent wrong answer is worse than an absent one.
_DATA_CLASSIFICATION_ALIASES = {
    "cardholder-data": "restricted",   # PCI CHD is the most sensitive tier
    "chd": "restricted",
    "pii": "restricted",
    "secret": "restricted",
    "sensitive": "confidential",
    "private": "confidential",
    "proprietary": "confidential",
}
_DATA_CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}


def normalize_data_classification(value: Any) -> str | None:
    """Coerce a CALM data-classification to the schema vocabulary, or None."""
    if not isinstance(value, str):
        return None
    key = value.strip().lower()
    if key in _DATA_CLASSIFICATIONS:
        return key
    return _DATA_CLASSIFICATION_ALIASES.get(key)


def _as_str_list(value: Any) -> list[str]:
    """CALM metadata fields are single-valued or list-valued depending on the author."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v]
    return []


def context_from_calm(architecture: dict[str, Any]) -> dict[str, Any]:
    """Extract ownership + intent context promoted from CALM ``metadata``."""
    md = architecture.get("metadata", {})
    intent: dict[str, Any] = {}
    classification = normalize_data_classification(md.get("data-classification"))
    if classification:
        intent["data_classification"] = classification
    scope = _as_str_list(md.get("compliance-scope"))
    if scope:
        intent["compliance_scope"] = scope
    return {
        "ownership": {
            "team": md.get("team"),
            "cost_center": md.get("cost-center"),
            "application_name": md.get("application-name"),
            "sla_tier": md.get("sla-tier"),
        },
        "intent": intent,
    }


def build_revoke_body(
    grant: dict[str, Any],
    *,
    issued_at: int,
    expires_at: int,
    justification: str | None = None,
    passport_id: str | None = None,
) -> dict[str, Any]:
    """Build a `revoke` tombstone for an existing grant (APP-050, Rung 5).

    The "DELETE AFTER <date>" edge becomes a *first-class signed object*. It reuses the
    grant's binding verbatim, so it carries the **same** ``graph_ref.edge_id`` and thus
    supersedes that grant in the reverse diff.

    Claim posture flips to the contraction side of the safety split: ``tense: will-be``
    (on death row) and ``authority_class: autonomic-contraction`` — contraction is
    low-authority and reversible, unlike governed expansion.
    """
    body = {k: v for k, v in grant.items() if k != "proof"}
    body["passport_id"] = passport_id or str(uuid.uuid4())
    body["claim"] = {
        "claim_type": "revoke",
        "tense": "will-be",
        "authority_class": "autonomic-contraction",
    }
    body["lifecycle"] = {"issued_at": int(issued_at), "expires_at": int(expires_at)}
    intent = dict(body.get("intent_metadata", {}))
    intent["business_justification"] = justification or (
        f"contraction: {intent.get('business_justification', 'edge')} — revoked, no renewal"
    )
    body["intent_metadata"] = intent
    return body


def build_renew_body(
    grant: dict[str, Any],
    *,
    issued_at: int,
    expires_at: int,
    passport_id: str | None = None,
) -> dict[str, Any]:
    """Re-attest an existing grant with a fresh lifecycle window (APP-081, walk).

    Renewal is the re-attestation half of the control loop that ``renewal_due`` reports
    on: the *same* claim, re-signed with a later ``expires_at`` so the edge does not lapse
    into contraction. The body is copied verbatim except for a new ``passport_id`` and
    ``lifecycle`` — crucially ``network_binding`` and ``graph_ref.edge_id`` are unchanged,
    so the renewed passport **supersedes** the one it renews (same edge identity, later
    ``issued_at``) rather than minting a second edge.

    The claim is preserved as-is. A renewal refreshes the window; it does not restate what
    is asserted, so it does not touch ``tense`` or ``authority_class``. (The seam table's
    ``will-be → is`` transition is a *separate* control-loop event — an in-flight edge going
    active — not lifecycle renewal; folding it in here would need a schema/state-machine
    decision this increment deliberately leaves open.)
    """
    if grant.get("claim", {}).get("claim_type") != "grant":
        raise ValueError("only a grant passport can be renewed")
    if int(expires_at) <= int(issued_at):
        raise ValueError("renewed expires_at must be after issued_at")
    body = {k: v for k, v in grant.items() if k != "proof"}
    body["passport_id"] = passport_id or str(uuid.uuid4())
    body["lifecycle"] = {"issued_at": int(issued_at), "expires_at": int(expires_at)}
    return body


def renew_passport(
    grant: dict[str, Any],
    private_key: Ed25519PrivateKey,
    issuer: str,
    *,
    issued_at: int,
    expires_at: int,
    passport_id: str | None = None,
    validate: bool = True,
) -> dict[str, Any]:
    """Build, sign, and (by default) schema-validate a renewed passport for ``grant``.

    Mirrors ``build_passport`` / signs with the same ``sign_passport`` path, so a renewed
    passport is indistinguishable from a freshly emitted one except for its stable
    ``edge_id`` and later lifecycle window.
    """
    body = build_renew_body(
        grant, issued_at=issued_at, expires_at=expires_at, passport_id=passport_id
    )
    passport = sign_passport(body, private_key, issuer)
    if validate:
        validate_passport(passport)
    return passport


def write_passport(passport: dict[str, Any], out_dir: str | Path) -> Path:
    """Write ``<edge-hash>[.<claim>].passport.json`` under ``out_dir``; return the path.

    A revoke shares its grant's ``edge_id`` (that's how it supersedes it), so the claim type
    is in the filename to keep the tombstone from clobbering the grant it revokes.
    """
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    edge_hash = edge_id_of(passport).rsplit("/", 1)[-1][:16]
    claim_type = passport.get("claim", {}).get("claim_type", "grant")
    suffix = "" if claim_type == "grant" else f".{claim_type}"
    path = out / f"{edge_hash}{suffix}.passport.json"
    path.write_text(json.dumps(passport, indent=2) + "\n")
    return path
