"""Tests for the reverse diff — observed flows × passport claims (APP-030/031/032)."""
from __future__ import annotations

import json

from calm_forge.edge_id import edge_id_for_binding
from calm_forge.passport_diff import (
    diff,
    flow_edge_id,
    load_observed_flows,
    load_passports,
)

_NOW = 1_800_000_000


def _passport(src, dst, port, *, claim="grant", expires=_NOW + 10_000, issued=_NOW - 10_000):
    binding = {
        "source_workload_urn": f"wl:sys/{src}",
        "destination_workload_urn": f"wl:sys/{dst}",
        "transport": "tcp",
        "port": port,
    }
    return {
        "passport_version": "0.1",
        "graph_ref": {"edge_id": edge_id_for_binding(binding)},
        "claim": {"claim_type": claim},
        "lifecycle": {"issued_at": issued, "expires_at": expires},
        "network_binding": binding,
    }


def _flow(src, dst, port, transport="tcp"):
    return {"source": f"wl:sys/{src}", "destination": f"wl:sys/{dst}",
            "transport": transport, "port": port}


# ---------------------------------------------------------------------------
# Identity: an observed L4 flow matches a claim regardless of L7
# ---------------------------------------------------------------------------

def test_flow_matches_claim_on_l4_identity():
    p = _passport("web", "api", 8443)
    f = _flow("web", "api", 8443)
    assert flow_edge_id(f) == p["graph_ref"]["edge_id"]


# ---------------------------------------------------------------------------
# The three verdicts
# ---------------------------------------------------------------------------

def test_conformant():
    r = diff([_passport("web", "api", 8443)], [_flow("web", "api", 8443)], _NOW)
    assert len(r.conformant) == 1 and not r.has_findings


def test_shadow_flow_no_claim():
    r = diff([_passport("web", "api", 8443)], [_flow("evil", "db", 5432)], _NOW)
    assert len(r.shadow) == 1
    assert r.shadow[0].source == "wl:sys/evil"
    # the granted web→api edge is not observed → also a contraction
    assert len(r.contraction) == 1


def test_contraction_when_not_observed():
    r = diff([_passport("web", "api", 8443)], [], _NOW)
    assert len(r.contraction) == 1
    assert "never observed" in r.contraction[0].detail
    assert not r.shadow


def test_contraction_when_expired_even_if_observed():
    """An expired-but-observed grant is a contraction, NOT a shadow (a claim did exist)."""
    p = _passport("web", "api", 8443, expires=_NOW - 1)
    r = diff([p], [_flow("web", "api", 8443)], _NOW)
    assert len(r.contraction) == 1
    assert "expired" in r.contraction[0].detail
    assert not r.shadow            # disjoint — not double-counted
    assert not r.conformant


def test_revoke_supersedes_grant_and_observed_traffic_is_shadow():
    grant = _passport("web", "api", 8443, claim="grant", issued=_NOW - 100)
    revoke = _passport("web", "api", 8443, claim="revoke", issued=_NOW - 10)
    r = diff([grant, revoke], [_flow("web", "api", 8443)], _NOW)
    assert len(r.shadow) == 1
    assert "revoke" in r.shadow[0].detail
    assert not r.conformant


def test_latest_grant_authoritative_for_expiry():
    stale = _passport("web", "api", 8443, issued=_NOW - 100, expires=_NOW - 50)
    fresh = _passport("web", "api", 8443, issued=_NOW - 10, expires=_NOW + 1000)
    r = diff([stale, fresh], [_flow("web", "api", 8443)], _NOW)
    assert len(r.conformant) == 1 and not r.has_findings


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def test_load_flows_json_and_csv(tmp_path):
    (tmp_path / "f.json").write_text(json.dumps([_flow("a", "b", 443)]))
    (tmp_path / "f.csv").write_text("source,destination,transport,port\nwl:sys/a,wl:sys/b,tcp,443\n")
    assert load_observed_flows(tmp_path / "f.json")[0]["port"] == 443
    csv_flow = load_observed_flows(tmp_path / "f.csv")[0]
    assert csv_flow["port"] == 443
    assert flow_edge_id(csv_flow) == flow_edge_id(_flow("a", "b", 443))


def test_load_flows_wrapped_object(tmp_path):
    (tmp_path / "w.json").write_text(json.dumps({"flows": [_flow("a", "b", 443)]}))
    assert len(load_observed_flows(tmp_path / "w.json")) == 1


def test_load_passports_from_dir(tmp_path):
    (tmp_path / "one.passport.json").write_text(json.dumps(_passport("web", "api", 8443)))
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "two.passport.json").write_text(json.dumps(_passport("api", "db", 5432)))
    assert len(load_passports(tmp_path)) == 2
