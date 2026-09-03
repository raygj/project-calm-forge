"""Tests for fortinet_writer — Fortinet candidate config (APP-020/021/022)."""
from __future__ import annotations

from calm_forge.edge_id import edge_id_for_binding
from calm_forge.fortinet_writer import (
    write_fortinet,
    write_fortinet_cli,
    write_fortinet_hcl,
)
from calm_forge.hcl_validator import validate_hcl_syntax


def _edge(src, dst, **extra):
    edge = {
        "source_workload": src,
        "source_workload_urn": f"wl:sys/{src}",
        "source_spiffe_id": f"spiffe://prod.fsi/ns/sys/sa/{src}",
        "destination_workload": dst,
        "destination_workload_urn": f"wl:sys/{dst}",
        "destination_spiffe_id": f"spiffe://prod.fsi/ns/sys/sa/{dst}",
        "transport": "tcp",
        "direction": "egress",
        "app_protocol": ["HTTPS"],
        "authentication": "mTLS-vault-pki",
    }
    edge.update(extra)
    return edge


_EDGES = [_edge("web", "api", port=8443), _edge("api", "db", port=5432, app_protocol=["TLS"])]


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------

def test_addresses_deduped_across_edges():
    hcl = write_fortinet_hcl(_EDGES)
    # web, api, db — api appears in both edges but only one address object
    assert hcl.count('resource "fortios_firewall_address"') == 3


def test_service_objects_per_port():
    hcl = write_fortinet_hcl(_EDGES)
    assert 'name          = "tcp-8443"' in hcl
    assert 'name          = "tcp-5432"' in hcl


def test_policy_per_edge_with_graph_ref():
    hcl = write_fortinet_hcl(_EDGES)
    assert hcl.count('resource "fortios_firewall_policy"') == 2
    for edge in _EDGES:
        assert f"# graph_ref: {edge_id_for_binding(edge)}" in hcl


def test_edge_id_parity_hcl_and_cli():
    """APP-021: the same edge_id appears in both artifacts (and it's the passport's id)."""
    hcl = write_fortinet_hcl(_EDGES)
    cli = write_fortinet_cli(_EDGES)
    for edge in _EDGES:
        eid = edge_id_for_binding(edge)
        assert eid in hcl and eid in cli


# ---------------------------------------------------------------------------
# Honesty: identity carried, IP not invented
# ---------------------------------------------------------------------------

def test_address_carries_identity_not_ip():
    hcl = write_fortinet_hcl(_EDGES)
    assert "spiffe://prod.fsi/ns/sys/sa/web" in hcl
    assert "RESOLVED-AT: walk" in hcl
    assert "0.0.0.0 0.0.0.0" in hcl  # placeholder, not a fabricated subnet


def test_compliance_in_policy_comment():
    hcl = write_fortinet_hcl(_EDGES, compliance=["PCI-DSS-v4:req-1"])
    assert "compliance=PCI-DSS-v4:req-1" in hcl


# ---------------------------------------------------------------------------
# Validation (APP-062 reuse point) + port variants
# ---------------------------------------------------------------------------

def test_hcl_passes_syntax_validator():
    assert validate_hcl_syntax(write_fortinet_hcl(_EDGES)) == []


def test_port_range_service():
    edges = [_edge("a", "b", port_range={"from": 8080, "to": 8090})]
    hcl = write_fortinet_hcl(edges)
    assert 'name          = "tcp-8080-8090"' in hcl
    assert 'tcp_portrange = "8080-8090"' in hcl


def test_unspecified_port_uses_builtin_all():
    edges = [_edge("a", "b", port_unspecified=True)]
    hcl = write_fortinet_hcl(edges)
    cli = write_fortinet_cli(edges)
    # ALL is a FortiOS built-in — no custom service object emitted for it
    assert 'resource "fortios_firewall_service_custom"' not in hcl
    assert 'service { name = "ALL" }' in hcl
    assert 'set service "ALL"' in cli


def test_write_fortinet_returns_both_artifacts():
    out = write_fortinet(_EDGES)
    assert set(out) == {"fortinet.tf", "candidate.conf"}
    assert out["candidate.conf"].startswith("# ")
    assert "config firewall policy" in out["candidate.conf"]
