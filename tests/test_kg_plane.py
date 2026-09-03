"""The plane dimension — MP-08 (ADR-005 §1, ADR-004 §2/§11, ADR-012 §1).

Three properties carry the design, and each has a test that fails loudly if someone
"simplifies" it later:

1. ``plane`` is required on authored nodes with **no default** — a silent fallback to
   ``architecture`` is how an OSCAL intake pollutes the architecture plane invisibly.
2. Reference nodes carry **no** plane — collapsing them into a plane value would undo
   the ADR-012 taxonomy in every plane-scoped query.
3. Edges **derive** their plane from the authoring node and never store it.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from calm_forge.kg_loader import load_patterns, validate_planes
from calm_forge.kg_plane import (
    NODE_CLASS_AUTHORED,
    NODE_CLASS_REFERENCE,
    PLANE_ARCHITECTURE,
    PLANE_CONTROLS,
    PLANES,
    PREDICATE_GOVERNS,
    PlaneError,
    backfill_document,
    index_nodes,
    migration_provenance,
    nodes_in_plane,
    plane_of,
    plane_of_edge,
    validate_document,
    validate_node,
)
from calm_forge.provenance import verify_envelope  # noqa: F401  (import sanity)

ROOT = Path(__file__).parent.parent
KG_DIR = ROOT / "src" / "calm_forge" / "knowledge_graph"


def _authored(**kw):
    return {"@id": "n:1", "node_class": NODE_CLASS_AUTHORED, "plane": PLANE_ARCHITECTURE, **kw}


# ---------------------------------------------------------------------------
# Required, no default
# ---------------------------------------------------------------------------

def test_authored_node_without_a_plane_is_a_gap():
    """No default. A fallback to architecture would let OSCAL intake land controls
    nodes in the architecture plane, undetected until a cross-plane finding fired
    against nonsense."""
    gaps = validate_node({"@id": "n:1", "node_class": NODE_CLASS_AUTHORED})
    assert gaps and "no plane" in gaps[0]


def test_node_without_a_class_is_a_gap():
    gaps = validate_node({"@id": "n:1"})
    assert gaps and "missing node_class" in gaps[0]


def test_unknown_plane_is_rejected_because_planes_are_added_by_adr():
    gaps = validate_node(_authored(plane="vibes"))
    assert gaps and "added by ADR" in gaps[0]


def test_unknown_node_class_is_rejected():
    gaps = validate_node({"@id": "n:1", "node_class": "sort-of"})
    assert gaps and "unknown node_class" in gaps[0]


# ---------------------------------------------------------------------------
# Reference nodes belong to no plane
# ---------------------------------------------------------------------------

def test_reference_node_carrying_a_plane_is_a_gap():
    """ADR-012 §1: reference graphs author no intent and project no policy, so they
    belong to no plane. A plane-bearing reference node would surface as authoring in
    every plane-scoped query."""
    gaps = validate_node({
        "@id": "kg://fibo/InterestRateSwap",
        "node_class": NODE_CLASS_REFERENCE,
        "plane": PLANE_ARCHITECTURE,
    })
    assert gaps and "author no intent" in gaps[0]


def test_reference_node_without_a_plane_is_valid():
    assert validate_node({
        "@id": "kg://fibo/InterestRateSwap", "node_class": NODE_CLASS_REFERENCE,
    }) == []


def test_plane_of_returns_none_for_reference_nodes():
    assert plane_of({"node_class": NODE_CLASS_REFERENCE}) is None
    assert plane_of(_authored()) == PLANE_ARCHITECTURE


def test_reference_nodes_are_absent_from_plane_filtered_results():
    """Their exclusion is correct, not a gap — they have no plane to match."""
    doc = {
        "@id": "w:1", "node_class": NODE_CLASS_AUTHORED, "plane": PLANE_ARCHITECTURE,
        "nodes": [
            {"@id": "n:a", "node_class": NODE_CLASS_AUTHORED, "plane": PLANE_ARCHITECTURE},
            {"@id": "kg://fibo/Swap", "node_class": NODE_CLASS_REFERENCE},
        ],
    }
    ids = {n["@id"] for n in nodes_in_plane(doc, PLANE_ARCHITECTURE)}
    assert ids == {"w:1", "n:a"}


def test_querying_an_unknown_plane_raises():
    with pytest.raises(PlaneError, match="added by ADR"):
        nodes_in_plane({"@id": "w:1"}, "vibes")


# ---------------------------------------------------------------------------
# Edges derive, never store
# ---------------------------------------------------------------------------

def test_edge_plane_derives_from_the_authoring_node_not_the_endpoints():
    """The case that decides the rule: a `governs` edge *spans* planes, so its two
    endpoints disagree by construction. The source authored the assertion, so the
    assertion is a fact in the source's plane."""
    control = {"@id": "kg://oscal/control/AC-3/imp-req-1",
               "node_class": NODE_CLASS_AUTHORED, "plane": PLANE_CONTROLS}
    edge_node = {"@id": "kg://edges/v1/abc",
                 "node_class": NODE_CLASS_AUTHORED, "plane": PLANE_ARCHITECTURE}
    index = {n["@id"]: n for n in (control, edge_node)}

    governs = {"@type": PREDICATE_GOVERNS, "from": control["@id"], "to": edge_node["@id"]}
    assert plane_of_edge(governs, index) == PLANE_CONTROLS


def test_edges_do_not_store_a_plane_anywhere_in_the_corpus():
    """A stored derivable is a value that can disagree with its source — the exact
    divergence the content-digest discipline exists to eliminate."""
    for pattern in load_patterns(KG_DIR):
        for edge in pattern.get("edges", []):
            assert "plane" not in edge, f"{pattern['@id']}: edge stores a derivable plane"


def test_edge_from_an_unknown_node_derives_nothing_rather_than_guessing():
    assert plane_of_edge({"from": "missing:1", "to": "n:2"}, {}) is None


# ---------------------------------------------------------------------------
# Backfill migration
# ---------------------------------------------------------------------------

def test_backfill_stamps_untagged_nodes_and_is_idempotent():
    doc = {"@id": "w:1", "nodes": [{"@id": "n:a"}], "policies": [{"@id": "p:a"}]}

    doc, stamped = backfill_document(doc)
    assert set(stamped) == {"w:1", "n:a", "p:a"}
    assert validate_document(doc) == []

    doc, again = backfill_document(doc)
    assert again == [], "backfill must be idempotent"


def test_backfill_does_not_overwrite_an_existing_tag():
    """Re-running the migration must not relabel a controls node as architecture."""
    doc = {"@id": "w:1", "nodes": [
        {"@id": "n:c", "node_class": NODE_CLASS_AUTHORED, "plane": PLANE_CONTROLS},
    ]}
    doc, stamped = backfill_document(doc)
    assert "n:c" not in stamped
    assert doc["nodes"][0]["plane"] == PLANE_CONTROLS


def test_migration_is_attested_not_silent():
    """The backfill is a write like any other and must not be the one unattested write
    in the system (ADR-007)."""
    before, after = '{"a": 1}', '{"a": 2}'
    prov = migration_provenance("x.json", before, after, ["n:a"])

    assert prov["subject"][0]["name"] == "x.json"
    deps = prov["predicate"]["buildDefinition"]["resolvedDependencies"]
    assert deps and deps[0]["digest"]["sha256"], "pre-migration digest not recorded"
    params = prov["predicate"]["buildDefinition"]["externalParameters"]
    assert params["stamped_ids"] == ["n:a"]
    assert params["plane"] == PLANE_ARCHITECTURE


def test_checked_in_migration_record_matches_the_corpus():
    """The record on disk must describe the documents actually in the tree — a
    migration record that drifts from its corpus is worse than none."""
    record = json.loads((KG_DIR / "_migrations" / "plane-backfill.slsa.json").read_text())
    documented = {r["subject"][0]["name"] for r in record}
    on_disk = {p.name for p in KG_DIR.glob("*.json")}
    assert documented == on_disk


# ---------------------------------------------------------------------------
# The corpus itself
# ---------------------------------------------------------------------------

def test_every_checked_in_pattern_is_plane_tagged():
    patterns = load_patterns(KG_DIR)
    assert patterns, "no KG patterns found"
    for pattern in patterns:
        assert validate_planes(pattern) == [], f"{pattern['@id']} has plane gaps"


def test_every_checked_in_node_is_architecture_plane_for_now():
    """Until OSCAL intake lands (MP-16) every authored node is CALM-authored. When that
    stops being true this test should be updated deliberately, not deleted."""
    for pattern in load_patterns(KG_DIR):
        for node in index_nodes(pattern).values():
            assert plane_of(node) == PLANE_ARCHITECTURE


def test_committed_planes_match_the_adrs():
    """Planes are added by ADR (ADR-005 §7). If this set grows, an ADR grew with it."""
    assert PLANES == {
        "architecture", "controls", "business_intent",   # ADR-005
        "data_management",                               # ADR-011
        "supply_chain",                                  # ADR-013
        "requirements",                                  # ADR-015
    }
