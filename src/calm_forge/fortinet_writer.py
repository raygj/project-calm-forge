"""FortiGate candidate config emission — Terraform HCL + FortiOS CLI (APP-020/021/022).

Emit-only (crawl). Two artifacts from one set of edges:
  * ``fortinet.tf`` — ``fortinetdev/fortios`` provider resources. ``terraform plan``
    is the candidate; nothing applies. This is the *pipeline* artifact.
  * ``candidate.conf`` — FortiOS CLI. The *device* artifact — "here's the rule."

Both are driven by the **same** normalized edges the passport adapter produces, so every
policy carries the passport's ``graph_ref.edge_id`` (APP-021) — the join key the reverse
diff (Rung 3) and the walk-stage push adapter rely on.

Identity-vs-IP is honest: a ``firewall address`` needs a subnet/fqdn, but crawl only knows
identity (SPIFFE = should-be). Addresses carry the SPIFFE id + URN and a placeholder subnet
flagged ``RESOLVED-AT: walk`` — we do not invent IPs.
"""
from __future__ import annotations

from typing import Any

from .edge_id import edge_id_for_binding

_PLACEHOLDER_SUBNET = "0.0.0.0 0.0.0.0"
_RESOLVED_AT = "RESOLVED-AT: walk (SPIRE/inventory join)"
_HEADER = (
    "CALM Forge — Fortinet candidate config (Attested Policy Passport, emit-only). "
    "Review as a candidate; do not auto-apply. Push is walk/run."
)


def _tf_name(*parts: str) -> str:
    """Terraform-safe identifier: lowercase, non-alnum → underscore."""
    raw = "__".join(parts)
    return "".join(c if c.isalnum() else "_" for c in raw).strip("_").lower()


def _service_token(edge: dict[str, Any]) -> str:
    transport = edge.get("transport", "tcp")
    if edge.get("port_unspecified"):
        return "ALL"
    rng = edge.get("port_range")
    if rng is not None:
        lo, hi = int(rng["from"]), int(rng["to"])
        if lo > hi:
            lo, hi = hi, lo
        return f"{transport}-{lo}-{hi}" if lo != hi else f"{transport}-{lo}"
    return f"{transport}-{int(edge['port'])}"


def _policy_comment(edge: dict[str, Any], edge_id: str, compliance: list[str] | None) -> str:
    bits = [f"graph_ref={edge_id}"]
    proto = (edge.get("app_protocol") or [None])[0]
    if proto:
        bits.append(f"app={proto}")
    if edge.get("authentication"):
        bits.append(f"auth={edge['authentication']}")
    if compliance:
        bits.append("compliance=" + ",".join(compliance))
    bits.append("claim=should-be")  # crawl posture
    return " | ".join(bits)


def _collect(edges: list[dict[str, Any]]) -> tuple[dict, dict, list]:
    """Dedup addresses + services across all edges; build the ordered policy list."""
    addresses: dict[str, dict[str, Any]] = {}
    services: dict[str, dict[str, Any]] = {}
    policies: list[dict[str, Any]] = []

    def _addr(workload: str, urn: str, spiffe: str | None) -> None:
        addresses.setdefault(workload, {"urn": urn, "spiffe_id": spiffe})

    for edge in edges:
        _addr(edge["source_workload"], edge["source_workload_urn"], edge.get("source_spiffe_id"))
        _addr(
            edge["destination_workload"],
            edge["destination_workload_urn"],
            edge.get("destination_spiffe_id"),
        )
        token = _service_token(edge)
        if token != "ALL" and token not in services:
            services[token] = {
                "transport": edge.get("transport", "tcp"),
                "port_range": edge.get("port_range"),
                "port": edge.get("port"),
            }
        policies.append(
            {
                "src": edge["source_workload"],
                "dst": edge["destination_workload"],
                "service": token,
                "edge_id": edge_id_for_binding(edge),
                "edge": edge,
            }
        )
    return addresses, services, policies


# ---------------------------------------------------------------------------
# Terraform HCL (fortinetdev/fortios provider)
# ---------------------------------------------------------------------------

def write_fortinet_hcl(edges: list[dict[str, Any]], compliance: list[str] | None = None) -> str:
    addresses, services, policies = _collect(edges)
    lines = [
        f"# {_HEADER}",
        "",
        "terraform {",
        "  required_providers {",
        "    fortios = {",
        '      source  = "fortinetdev/fortios"',
        '      version = ">= 1.20"',
        "    }",
        "  }",
        "}",
        "",
        "# provider config intentionally omitted — emit-only. Supplied at plan time.",
        "",
    ]

    for name, meta in addresses.items():
        comment = f"identity: {meta.get('spiffe_id') or meta['urn']} | urn: {meta['urn']} | {_RESOLVED_AT}"
        lines += [
            f'resource "fortios_firewall_address" "{_tf_name(name)}" {{',
            f'  name    = "{name}"',
            '  type    = "subnet"',
            f'  subnet  = "{_PLACEHOLDER_SUBNET}"  # PLACEHOLDER',
            f'  comment = "{comment}"',
            "}",
            "",
        ]

    for token, meta in services.items():
        portrange = _portrange_str(meta)
        key = "udp_portrange" if meta["transport"] == "udp" else "tcp_portrange"
        lines += [
            f'resource "fortios_firewall_service_custom" "{_tf_name(token)}" {{',
            f'  name          = "{token}"',
            f'  {key} = "{portrange}"',
            "}",
            "",
        ]

    for i, pol in enumerate(policies, start=1):
        service_name = pol["service"]  # "ALL" is a FortiOS built-in
        lines += [
            f'resource "fortios_firewall_policy" "{_tf_name(pol["src"], pol["dst"], service_name)}" {{',
            f'  # graph_ref: {pol["edge_id"]}',
            f"  policyid = {i}",
            f'  name     = "{_policy_label(pol)}"',
            '  srcintf { name = "any" }',
            '  dstintf { name = "any" }',
            f'  srcaddr {{ name = "{pol["src"]}" }}',
            f'  dstaddr {{ name = "{pol["dst"]}" }}',
            f'  service {{ name = "{service_name}" }}',
            '  action   = "accept"',
            '  schedule = "always"',
            f'  comments = "{_policy_comment(pol["edge"], pol["edge_id"], compliance)}"',
            "}",
            "",
        ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# FortiOS CLI candidate config
# ---------------------------------------------------------------------------

def write_fortinet_cli(edges: list[dict[str, Any]], compliance: list[str] | None = None) -> str:
    addresses, services, policies = _collect(edges)
    lines = [
        "# " + "=" * 60,
        f"# {_HEADER}",
        "# " + "=" * 60,
        "",
        "config firewall address",
    ]
    for name, meta in addresses.items():
        lines += [
            f'  edit "{name}"',
            "    set type subnet",
            f"    set subnet {_PLACEHOLDER_SUBNET}",
            f'    set comment "identity: {meta.get("spiffe_id") or meta["urn"]} | {_RESOLVED_AT}"',
            "  next",
        ]
    lines.append("end")

    if services:
        lines += ["", "config firewall service custom"]
        for token, meta in services.items():
            key = "udp-portrange" if meta["transport"] == "udp" else "tcp-portrange"
            lines += [f'  edit "{token}"', f"    set {key} {_portrange_str(meta)}", "  next"]
        lines.append("end")

    lines += ["", "config firewall policy"]
    for i, pol in enumerate(policies, start=1):
        lines += [
            f"  edit {i}",
            f'    set name "{_policy_label(pol)}"',
            f"    # graph_ref: {pol['edge_id']}",
            '    set srcintf "any"',
            '    set dstintf "any"',
            f'    set srcaddr "{pol["src"]}"',
            f'    set dstaddr "{pol["dst"]}"',
            f'    set service "{pol["service"]}"',
            "    set action accept",
            '    set schedule "always"',
            f'    set comments "{_policy_comment(pol["edge"], pol["edge_id"], compliance)}"',
            "  next",
        ]
    lines.append("end")
    return "\n".join(lines) + "\n"


def _portrange_str(meta: dict[str, Any]) -> str:
    rng = meta.get("port_range")
    if rng is not None:
        lo, hi = int(rng["from"]), int(rng["to"])
        if lo > hi:
            lo, hi = hi, lo
        return f"{lo}-{hi}" if lo != hi else str(lo)
    return str(int(meta["port"]))


def _policy_label(pol: dict[str, Any]) -> str:
    """FortiOS policy names are capped at 35 chars."""
    return f"{pol['src']}__{pol['dst']}"[:35]


def write_fortinet(edges: list[dict[str, Any]], compliance: list[str] | None = None) -> dict[str, str]:
    """Return both Fortinet artifacts keyed by filename."""
    return {
        "fortinet.tf": write_fortinet_hcl(edges, compliance),
        "candidate.conf": write_fortinet_cli(edges, compliance),
    }
