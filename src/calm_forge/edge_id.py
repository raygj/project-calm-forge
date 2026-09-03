"""Stable KG edge identity for the Attested Policy Passport (APP-000).

A passport's ``graph_ref.edge_id`` is what makes it a *projection of a graph
edge* rather than signed IaC. The identifier must survive IP churn, the
node-id -> SPIFFE identity migration, and KG-backend swaps — so it is a hash of
the **L4 identity tuple** over **identity-system-agnostic workload URNs**, never
IP, array index, or L7 app protocol.

    edge_id = kg://edges/v1/<sha256( edge/v1|src=..|dst=..|l4=..|port=.. )>

See docs/APP-edge-id-scheme.md for the full rationale (L4-not-L7, URN reduction,
port-range handling, versioning).
"""
from __future__ import annotations

import hashlib
import re

SCHEME_VERSION = "v1"

# Trailing port in an interface token, e.g. "https-8443" -> 8443, "port-5432" -> 5432.
_INTERFACE_PORT = re.compile(r"-(\d{1,5})$")

# Last-resort defaults when neither an interface nor an explicit port is given.
# Keys are lowercased app-protocol labels as they appear in CALM `protocol` fields.
_PROTOCOL_DEFAULT_PORT = {
    "https": 443,
    "http": 80,
    "postgres": 5432,
    "mysql": 3306,
    "redis": 6379,
    "mongodb": 27017,
    "grpc": 443,
    # Event-driven / messaging — the conventional listener port for each broker
    # protocol. SASL_SSL and PLAINTEXT are Kafka *security protocols*, and a
    # broker conventionally listens for each on its own port.
    "kafka": 9092,
    "plaintext": 9092,
    "sasl_plaintext": 9092,
    "sasl_ssl": 9093,
    "ssl": 9093,
    "amqp": 5672,
    "amqps": 5671,
    "mqtt": 1883,
    "nats": 4222,
    # Common enterprise data/back-office paths
    "ldaps": 636,
    "kafka-connect": 8083,
    "elasticsearch": 9200,
}

# How a binding's port was arrived at — evidence strength, recorded on the
# passport so a consumer can tell a declared port from an inferred one.
# Deliberately NOT part of edge_id: provenance is not identity, so learning a
# port from inventory must never churn the id of an edge already claimed.
PORT_SOURCE_INTERFACE = "declared-interface"   # authored in the CALM interface token
PORT_SOURCE_OVERRIDE = "declared-override"     # authored out-of-band by an operator
PORT_SOURCE_PROTOCOL_DEFAULT = "protocol-default"  # inferred from the L7 protocol
PORT_SOURCE_INVENTORY = "inventory"            # learned from the running fabric
PORT_SOURCE_WILDCARD = "wildcard"              # authored: any port is intended
PORT_SOURCE_UNRESOLVED = "unresolved"          # nothing said; we do not know

#: Port sources that carry enough evidence to adjudicate an edge against a flow.
ADJUDICABLE_PORT_SOURCES = frozenset({
    PORT_SOURCE_INTERFACE,
    PORT_SOURCE_OVERRIDE,
    PORT_SOURCE_PROTOCOL_DEFAULT,
    PORT_SOURCE_INVENTORY,
    PORT_SOURCE_WILDCARD,
})


def workload_urn(node_id: str, explicit: str | None = None) -> str:
    """Reduce a node/workload identifier to a canonical, identity-system-agnostic URN.

    ``workload:<system>:<component>`` -> ``wl:<system>/<component>``. An explicit
    URN declared on the node always wins. The SPIFFE id is deliberately *not*
    parsed here — it is an attestation about a workload, not the edge's identity,
    so adopting SPIFFE never churns an edge_id (APP-000 §4).
    """
    if explicit:
        return explicit.lower()
    parts = node_id.split(":")
    if parts[0] in ("workload", "service", "node") and len(parts) >= 3:
        return f"wl:{parts[1]}/{parts[2]}".lower()
    return f"wl:{node_id}".lower()


def port_from_interface(interface: str) -> int | None:
    """Extract a port encoded in an interface token, e.g. ``https-8443`` -> 8443."""
    match = _INTERFACE_PORT.search(interface)
    if not match:
        return None
    port = int(match.group(1))
    return port if 0 <= port <= 65535 else None


def default_port_for(app_protocol: str) -> int | None:
    """Last-resort port from a declared L7 protocol; returns None if unknown."""
    return _PROTOCOL_DEFAULT_PORT.get(app_protocol.lower())


def port_token(
    port: int | None = None,
    port_range: dict | None = None,
    unspecified: bool = False,
) -> str:
    """Canonical port component of the edge tuple.

    Single port -> ``"8443"``; range -> ``"8080-8090"`` (orientation normalized);
    a degenerate range collapses to the single-port form so there is exactly one
    id per logical edge; unresolved -> ``"any"`` (APP-000 §5-6).
    """
    if unspecified:
        return "any"
    if port_range is not None:
        lo, hi = int(port_range["from"]), int(port_range["to"])
        if lo > hi:
            lo, hi = hi, lo
        return str(lo) if lo == hi else f"{lo}-{hi}"
    if port is not None:
        return str(int(port))
    return "any"


def edge_id(
    src_urn: str,
    dst_urn: str,
    transport: str,
    *,
    port: int | None = None,
    port_range: dict | None = None,
    unspecified: bool = False,
) -> str:
    """Compute the stable ``kg://edges/v1/<sha256>`` identifier for an edge.

    ``transport`` is L4 (tcp/udp). App protocol and authentication are excluded
    by construction — two edges differing only at L7 share one id on purpose,
    because a firewall (and NetFlow) cannot tell them apart.
    """
    canonical = (
        f"edge/{SCHEME_VERSION}|src={src_urn.lower()}|dst={dst_urn.lower()}"
        f"|l4={transport.lower()}|port={port_token(port, port_range, unspecified)}"
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"kg://edges/{SCHEME_VERSION}/{digest}"


def edge_id_for_binding(binding: dict) -> str:
    """Compute the edge_id from a passport ``network_binding``-shaped dict.

    Single source of truth shared by the passport builder (APP-010) and the
    reverse diff (APP-031), so a claim and an observation of the same L4 edge
    hash identically.

    ``port_wildcard`` and ``port_unspecified`` both hash to ``port=any``: they
    describe the *same* L4 tuple and so must share one identity. They differ in
    what they *mean* — an authored wildcard is permission, an unresolved port is
    ignorance — and that difference is carried by ``port_source``, adjudicated
    in the reverse diff, not by the id (APP-090).
    """
    return edge_id(
        binding["source_workload_urn"],
        binding["destination_workload_urn"],
        binding["transport"],
        port=binding.get("port"),
        port_range=binding.get("port_range"),
        unspecified=bool(binding.get("port_unspecified") or binding.get("port_wildcard")),
    )


def edge_scope(src_urn: str, dst_urn: str, transport: str) -> str:
    """The port-independent key for an edge: ``<src>|<dst>|<l4>``.

    A wildcard claim grants a *scope*, not a 5-tuple, so it cannot be matched by
    edge_id equality — a concrete flow always hashes to its concrete port. The
    diff indexes wildcard claims by scope so an observed tcp/9092 flow is
    recognized as covered by an authored "any port to this broker" grant.
    """
    return f"{src_urn.lower()}|{dst_urn.lower()}|{transport.lower()}"


def edge_scope_for_binding(binding: dict) -> str:
    """``edge_scope`` from a ``network_binding``-shaped dict."""
    return edge_scope(
        binding["source_workload_urn"],
        binding["destination_workload_urn"],
        binding["transport"],
    )
