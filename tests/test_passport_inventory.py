"""Inventory join — filling ports the intent leaves undeclared (APP-093).

Inventory is evidence about the *fabric*; intent is the contract. The join exists to
close a declaration gap, and every test here pins one of the rules that keeps the two
from being confused: intent always wins, fills are labelled, and ambiguity is refused
rather than guessed.
"""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.passport_seams import (
    InventoryEdgeSource,
    load_inventory,
    resolve_ports_from_inventory,
)

EXAMPLES = Path(__file__).parent.parent / "examples"
FRAUD = EXAMPLES / "fraud-detection-workload-portability"


def _edge(src="wl:app/a", dst="wl:app/b", **kw):
    return {
        "source_workload": src.split("/")[-1],
        "source_workload_urn": src,
        "destination_workload": dst.split("/")[-1],
        "destination_workload_urn": dst,
        "transport": "tcp",
        **kw,
    }


def test_listener_resolves_every_edge_pointing_at_that_workload():
    """Inventory knows listeners, not edges — one record covers many callers."""
    inv = InventoryEdgeSource([{"workload_urn": "wl:app/b", "transport": "tcp", "port": 8500}])
    edges = [
        _edge("wl:app/a", "wl:app/b", port_unspecified=True, port_source="unresolved"),
        _edge("wl:app/c", "wl:app/b", port_unspecified=True, port_source="unresolved"),
    ]
    resolved, unresolved = resolve_ports_from_inventory(edges, inv)

    assert not unresolved
    assert [e["port"] for e in resolved] == [8500, 8500]
    assert {e["port_source"] for e in resolved} == {"inventory"}
    assert not any("port_unspecified" in e for e in resolved)


def test_inventory_never_overrides_a_declared_port():
    """Intent is the contract. Where inventory disagrees, that is drift for the
    reverse diff to surface — not something to silently reconcile at emit time."""
    inv = InventoryEdgeSource([{"workload_urn": "wl:app/b", "transport": "tcp", "port": 9999}])
    edges = [_edge(port=8443, port_source="declared-interface")]

    resolved, _ = resolve_ports_from_inventory(edges, inv)

    assert resolved[0]["port"] == 8443
    assert resolved[0]["port_source"] == "declared-interface"


def test_explicit_edge_record_beats_a_listener():
    """An operator who wrote down *this* path meant *this* path."""
    inv = InventoryEdgeSource([
        {"workload_urn": "wl:app/b", "transport": "tcp", "port": 8500},
        {"source_workload_urn": "wl:app/a", "destination_workload_urn": "wl:app/b",
         "transport": "tcp", "port": 8501},
    ])
    resolved, _ = resolve_ports_from_inventory(
        [_edge(port_unspecified=True, port_source="unresolved")], inv
    )
    assert resolved[0]["port"] == 8501


def test_ambiguous_listener_is_refused_not_guessed():
    """Two listeners do not tell us which one this edge uses. Picking one would
    fabricate a precise claim out of imprecise evidence — so the edge stays a gap,
    carrying the candidates that made it ambiguous."""
    inv = InventoryEdgeSource([
        {"workload_urn": "wl:app/b", "transport": "tcp", "port": 6379},
        {"workload_urn": "wl:app/b", "transport": "tcp", "port": 6380},
    ])
    resolved, unresolved = resolve_ports_from_inventory(
        [_edge(port_unspecified=True, port_source="unresolved")], inv
    )

    assert len(unresolved) == 1
    assert resolved[0].get("port") is None
    assert resolved[0]["port_unspecified"] is True
    assert unresolved[0]["port_ambiguous"] == [6379, 6380]


def test_transport_is_part_of_the_match():
    """A UDP listener does not resolve a TCP edge."""
    inv = InventoryEdgeSource([{"workload_urn": "wl:app/b", "transport": "udp", "port": 514}])
    _, unresolved = resolve_ports_from_inventory(
        [_edge(port_unspecified=True, port_source="unresolved")], inv
    )
    assert len(unresolved) == 1


def test_load_inventory_accepts_both_shapes(tmp_path):
    listeners = [{"workload_urn": "wl:app/b", "transport": "tcp", "port": 80}]
    wrapped = tmp_path / "w.json"
    wrapped.write_text(json.dumps({"listeners": listeners}))
    bare = tmp_path / "b.json"
    bare.write_text(json.dumps(listeners))

    assert load_inventory(wrapped).listeners() == load_inventory(bare).listeners()
    assert load_inventory(bare).provenance == "inventory"


def test_emit_with_inventory_closes_the_gap_and_says_so(tmp_path):
    """The end-to-end join against the real example: the two resolvable gaps close
    and are labelled `inventory`, the ambiguous one is reported and left open."""
    runner = CliRunner()
    out = tmp_path / "passports"
    res = runner.invoke(cli, [
        "passport", "emit", "--calm", str(FRAUD / "instantiation.json"),
        "--trust-domain", "prod.fsi", "--output-dir", str(out),
        "--key", str(tmp_path / "k.pem"),
        "--inventory", str(FRAUD / "inventory-listeners.json"),
    ])
    assert res.exit_code == 0, res.output
    assert "Inventory resolved 2 undeclared port(s)" in res.output
    assert "ambiguous" in res.output

    bindings = [
        json.loads(p.read_text())["network_binding"]
        for p in sorted(out.glob("*.passport.json"))
    ]
    by_source = {}
    for nb in bindings:
        by_source.setdefault(nb["port_source"], []).append(nb)

    assert len(by_source["inventory"]) == 2
    assert len(by_source["declared-interface"]) == 1   # the one CALM actually declares
    assert len(by_source["unresolved"]) == 1           # the ambiguous one, still honest


def test_inventory_filled_edges_adjudicate_normally(tmp_path):
    """A port learned from inventory is still a real port: the edge leaves the
    unadjudicable bucket and takes part in the reverse diff like any other."""
    runner = CliRunner()
    out = tmp_path / "passports"
    runner.invoke(cli, [
        "passport", "emit", "--calm", str(FRAUD / "instantiation.json"),
        "--trust-domain", "prod.fsi", "--output-dir", str(out),
        "--key", str(tmp_path / "k.pem"),
        "--inventory", str(FRAUD / "inventory-listeners.json"),
    ])
    flows = tmp_path / "flows.json"
    flows.write_text(json.dumps([{
        "source": "wl:fraud-detection-pipeline/transaction-ingest",
        "destination": "wl:fraud-detection-pipeline/ml-scoring",
        "transport": "tcp", "port": 8500,
    }]))

    res = runner.invoke(cli, [
        "passport", "diff", "--flows", str(flows), "--passports", str(out),
        "--now", "1771770600", "--json",
    ])
    payload = json.loads(res.output)

    conformant = payload["conformant"]
    assert len(conformant) == 1
    assert conformant[0]["port_source"] == "inventory"
    # ...and the report still says where that port came from, so "go declare it"
    # remains visible work rather than a closed ticket.
