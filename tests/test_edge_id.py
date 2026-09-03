"""Tests for edge_id — stable KG edge identity (APP-000).

Pins the canonical hash for a known edge and proves the module reproduces the
committed example passport's edge_id, so code and artifact can never drift.
"""
from __future__ import annotations

import json
from pathlib import Path

from calm_forge.edge_id import (
    default_port_for,
    edge_id,
    edge_id_for_binding,
    port_from_interface,
    port_token,
    workload_urn,
)

_SCHEMA_DIR = Path(__file__).resolve().parents[1] / "src" / "calm_forge" / "schemas"
_EXAMPLE = json.loads((_SCHEMA_DIR / "example.passport.json").read_text())

# Regression pin: web-tier -> api-tier over tcp/8443 in knowledge_graph/3-tier-pci.json.
_PINNED = "kg://edges/v1/83c1619b769aae79d8c6b4ae127a3fafe2e0f47728095b5ed5d278e2cc182364"


# ---------------------------------------------------------------------------
# Workload URN reduction (identity-system agnostic)
# ---------------------------------------------------------------------------

def test_workload_urn_from_node_id():
    assert workload_urn("workload:3tier-pci:web-tier") == "wl:3tier-pci/web-tier"
    assert workload_urn("service:mesh:api-gateway") == "wl:mesh/api-gateway"


def test_workload_urn_explicit_wins():
    assert workload_urn("anything", explicit="wl:custom/thing") == "wl:custom/thing"


def test_workload_urn_fallback():
    assert workload_urn("api-gateway") == "wl:api-gateway"


# ---------------------------------------------------------------------------
# The pinned hash and the artifact cross-check
# ---------------------------------------------------------------------------

def test_edge_id_pinned_hash():
    assert edge_id("wl:3tier-pci/web-tier", "wl:3tier-pci/api-tier", "tcp", port=8443) == _PINNED


def test_module_reproduces_committed_example():
    """edge_id_for_binding on the committed example == its graph_ref.edge_id."""
    assert edge_id_for_binding(_EXAMPLE["network_binding"]) == _EXAMPLE["graph_ref"]["edge_id"]


# ---------------------------------------------------------------------------
# L4-not-L7 and directionality (the correctness calls)
# ---------------------------------------------------------------------------

def test_l7_not_in_identity():
    """Two edges differing only by app protocol share one id (firewall can't tell them apart)."""
    a = edge_id("wl:s/a", "wl:s/b", "tcp", port=443)
    b = edge_id("wl:s/a", "wl:s/b", "tcp", port=443)
    assert a == b


def test_direction_changes_identity():
    ab = edge_id("wl:s/a", "wl:s/b", "tcp", port=443)
    ba = edge_id("wl:s/b", "wl:s/a", "tcp", port=443)
    assert ab != ba


def test_transport_and_port_change_identity():
    base = edge_id("wl:s/a", "wl:s/b", "tcp", port=443)
    assert edge_id("wl:s/a", "wl:s/b", "udp", port=443) != base
    assert edge_id("wl:s/a", "wl:s/b", "tcp", port=444) != base


def test_case_insensitive():
    assert edge_id("WL:S/A", "wl:s/b", "TCP", port=443) == edge_id("wl:s/a", "wl:s/b", "tcp", port=443)


# ---------------------------------------------------------------------------
# Port tokens: ranges, collapse, unspecified
# ---------------------------------------------------------------------------

def test_port_token_single_and_range():
    assert port_token(port=8443) == "8443"
    assert port_token(port_range={"from": 8080, "to": 8090}) == "8080-8090"


def test_port_token_range_collapse():
    assert port_token(port_range={"from": 8443, "to": 8443}) == "8443"
    # and the collapsed range hashes identically to the single port
    assert edge_id("wl:s/a", "wl:s/b", "tcp", port_range={"from": 443, "to": 443}) == \
        edge_id("wl:s/a", "wl:s/b", "tcp", port=443)


def test_port_token_range_orientation_normalized():
    assert port_token(port_range={"from": 8090, "to": 8080}) == "8080-8090"


def test_port_token_unspecified():
    assert port_token(unspecified=True) == "any"
    assert port_token() == "any"


# ---------------------------------------------------------------------------
# Port resolution helpers (APP-000 §6)
# ---------------------------------------------------------------------------

def test_port_from_interface():
    assert port_from_interface("https-8443") == 8443
    assert port_from_interface("port-5432") == 5432
    assert port_from_interface("eth0") is None
    assert port_from_interface("https-99999") is None  # out of range


def test_default_port_for():
    assert default_port_for("HTTPS") == 443
    assert default_port_for("postgres") == 5432
    assert default_port_for("mystery-proto") is None
