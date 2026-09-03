"""Plane-filtered querying — MP-09 (ADR-005 §1, ADR-012 §1).

Two behaviours were ratified in design and are pinned here because both are the kind
of thing a later "simplification" would quietly invert:

1. **An unfiltered query returns every plane and labels each result.** Defaulting to
   ``architecture`` would make the multi-plane graph invisible to every existing caller.
2. **Reference nodes never appear in a plane-filtered result.** They have no plane, so
   their exclusion is correct — not a gap to be patched by giving them one.
"""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.kg_plane import PlaneError
from calm_forge.kg_query import kg_query


def _write(kg_dir, subdir, name, node):
    d = kg_dir / subdir
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.json").write_text(json.dumps(node))


@pytest.fixture
def kg(tmp_path):
    """A KG with two authored planes and one reference node."""
    _write(tmp_path, "workloads", "arch", {
        "@type": "Workload", "@id": "workload:app:web",
        "node_class": "authored", "plane": "architecture", "name": "web",
    })
    _write(tmp_path, "workloads", "ctrl", {
        "@type": "Workload", "@id": "workload:app:ctrl-governed",
        "node_class": "authored", "plane": "controls", "name": "ctrl",
    })
    _write(tmp_path, "workloads", "ref", {
        "@type": "Workload", "@id": "kg://fibo/InterestRateSwap",
        "node_class": "reference", "name": "swap",
    })
    return tmp_path


def _ids(results):
    return {r["node"]["@id"] for r in results}


# ---------------------------------------------------------------------------
# Unfiltered returns everything, labelled
# ---------------------------------------------------------------------------

def test_unfiltered_query_returns_every_plane(kg):
    """Not architecture-by-default: a plane dimension nobody sees is one nobody uses."""
    results = kg_query(kg, "Workload", [])
    assert _ids(results) == {
        "workload:app:web", "workload:app:ctrl-governed", "kg://fibo/InterestRateSwap",
    }


def test_every_result_carries_a_plane_label(kg):
    by_id = {r["node"]["@id"]: r for r in kg_query(kg, "Workload", [])}
    assert by_id["workload:app:web"]["plane"] == "architecture"
    assert by_id["workload:app:ctrl-governed"]["plane"] == "controls"
    # a reference node is labelled None, not mislabelled into a plane
    assert by_id["kg://fibo/InterestRateSwap"]["plane"] is None


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def test_plane_filter_selects_one_plane(kg):
    assert _ids(kg_query(kg, "Workload", [], plane="architecture")) == {"workload:app:web"}
    assert _ids(kg_query(kg, "Workload", [], plane="controls")) == {
        "workload:app:ctrl-governed"
    }


def test_reference_nodes_are_absent_from_every_plane_filter(kg):
    """Their exclusion is correct, not a gap. A reference node surfacing under --plane
    would read as authoring, which is the taxonomy collapse the two-field design of
    ADR-012 §1 exists to prevent."""
    for plane in ("architecture", "controls", "business_intent",
                  "data_management", "supply_chain"):
        assert "kg://fibo/InterestRateSwap" not in _ids(
            kg_query(kg, "Workload", [], plane=plane)
        )


def test_plane_filter_composes_with_where_predicates(kg):
    assert _ids(kg_query(kg, "Workload", ["name=web"], plane="architecture")) == {
        "workload:app:web"
    }
    assert kg_query(kg, "Workload", ["name=web"], plane="controls") == []


def test_unknown_plane_raises_rather_than_returning_empty(kg):
    """An empty result and a bad query must not look the same — silence would read as
    'no nodes in that plane' when it actually means the plane does not exist."""
    with pytest.raises(PlaneError, match="added by ADR"):
        kg_query(kg, "Workload", [], plane="vibes")


# ---------------------------------------------------------------------------
# CLI + MCP surface
# ---------------------------------------------------------------------------

def test_cli_plane_filter(kg):
    res = CliRunner().invoke(cli, [
        "kg", "query", "--kg-dir", str(kg), "--type", "Workload",
        "--plane", "controls", "--json",
    ])
    assert res.exit_code == 0, res.output
    assert _ids(json.loads(res.output)) == {"workload:app:ctrl-governed"}


def test_cli_labels_the_plane_in_human_output(kg):
    res = CliRunner().invoke(cli, [
        "kg", "query", "--kg-dir", str(kg), "--type", "Workload",
    ])
    assert res.exit_code == 0, res.output
    assert "architecture" in res.output and "controls" in res.output


def test_cli_rejects_an_unknown_plane_at_the_option_level(kg):
    res = CliRunner().invoke(cli, [
        "kg", "query", "--kg-dir", str(kg), "--type", "Workload", "--plane", "vibes",
    ])
    assert res.exit_code != 0
    assert "vibes" in res.output


def test_cli_refuses_plane_with_federated_rather_than_ignoring_it(kg):
    """Federation queries member roots through a path with no plane filter. Accepting
    the flag and silently ignoring it would return unfiltered results that look
    filtered — worse than refusing."""
    res = CliRunner().invoke(cli, [
        "kg", "query", "--kg-dir", str(kg), "--type", "Workload",
        "--plane", "controls", "--federated",
    ])
    assert res.exit_code != 0
    assert "not supported with --federated" in res.output


def test_mcp_tool_filters_and_reports_the_plane(kg):
    from calm_forge.mcp_server import _kg_query

    out = _kg_query(str(kg), "Workload", plane="controls")
    assert out["count"] == 1
    assert out["plane"] == "controls"
    assert out["results"][0]["node"]["@id"] == "workload:app:ctrl-governed"


def test_mcp_tool_reports_an_unknown_plane_as_an_error_not_an_empty_result(kg):
    from calm_forge.mcp_server import _kg_query

    out = _kg_query(str(kg), "Workload", plane="vibes")
    assert out["count"] == 0
    assert "added by ADR" in out["error"]
