"""The plane dimension of the knowledge graph (MP-08, ADR-005 §1, ADR-012 §1).

Two orthogonal facts about a graph object:

``node_class``
    *What kind of thing is this* — ``authored`` (a sovereign community wrote it and it
    projects policy or evidence) or ``reference`` (vocabulary other things point into).
    Sorted by the ADR-012 taxonomy.

``plane``
    *Which authoring plane* — only meaningful for ``authored`` nodes.

The two are deliberately separate fields. A single ``plane: "reference"`` value would
be cheaper and would collapse the taxonomy in every plane-scoped query, which is
precisely the failure the taxonomy exists to prevent.

**Resolvers and feeders have no node class, because they contribute no standing nodes**
(ADR-012 §1a). IPAM bindings, DHCP leases, cert serials and telemetry are resolved at
join time or filtered into findings; they are never stored. If a resolver ever appears
to need a node, that is a design error surfacing — not a missing enum value. Do not add
one.

Edges do **not** store a plane. An edge's plane is the plane of its *authoring node* —
the source side of the predicate — so a `governs` assertion written by an OSCAL node is
a controls-plane fact *about* an architecture-plane object. Storing it would create a
derivable value that can disagree with its source, which is the divergence the
content-digest discipline (ADR-007) exists to eliminate.
"""
from __future__ import annotations

from typing import Any

from .provenance import build_provenance, node_version, sha256_hex

NODE_CLASS_AUTHORED = "authored"
NODE_CLASS_REFERENCE = "reference"
NODE_CLASSES = frozenset({NODE_CLASS_AUTHORED, NODE_CLASS_REFERENCE})

PLANE_ARCHITECTURE = "architecture"
PLANE_CONTROLS = "controls"
PLANE_BUSINESS_INTENT = "business_intent"
PLANE_DATA_MANAGEMENT = "data_management"
PLANE_SUPPLY_CHAIN = "supply_chain"
PLANE_REQUIREMENTS = "requirements"

#: Committed planes. Each is added by ADR (ADR-005 §7), never by configuration.
PLANES = frozenset({
    PLANE_ARCHITECTURE,      # CALM — ADR-005
    PLANE_CONTROLS,          # OSCAL — ADR-005
    PLANE_BUSINESS_INTENT,   # TOSCA — ADR-005
    PLANE_DATA_MANAGEMENT,   # OpenLineage — ADR-011
    PLANE_SUPPLY_CHAIN,      # SLSA / CycloneDX / in-toto — ADR-013
    PLANE_REQUIREMENTS,      # Forge-native — ADR-015. The one minted schema; see
                             # ADR-015 §6 for the standard-vacuum rationale and its exit.
})

#: Cross-plane predicate: an authored node governs a graph object in another plane.
#: Directional, and it may target either a node or an edge — an OSCAL AC-2 control
#: governs a *workload*, not any single flow, while AC-3 may govern one edge.
PREDICATE_GOVERNS = "governs"

#: Cross-plane predicate: an authored node's intent produced another authored node
#: (ADR-015 §2, an MP-08 amendment). The generative sibling of ``governs``.
#:
#: The two point in different directions and that is the whole distinction. ``governs``
#: points *down* the authority chain — this control constrains that object. ``realizes``
#: points *forward* through generation — this requirement begat that artifact. Neither
#: stores a plane, for the reason above: an edge's plane is its authoring node's.
PREDICATE_REALIZES = "realizes"

#: Containers of authored nodes inside a Workload document.
#:
#: ``controls_nodes`` holds OSCAL-authored nodes (MP-16) and ``business_intent_nodes``
#: holds TOSCA-authored policy nodes (MP-21). Both are listed here, and not only in their
#: intakes, because :func:`node_versions` is the left-hand side of every cross-plane
#: comparison: a plane node missing from that map reads as *deleted*, and
#: `ORPHANED_POLICY` would fire on every artifact compiled from a perfectly live source.
_AUTHORED_CONTAINERS = (
    "nodes",
    "policies",
    "compliance_nodes",
    "controls_nodes",
    "business_intent_nodes",
    "job_nodes",
    "dataset_nodes",
    "contract_nodes",
    "contracted_dataset_nodes",
    "actor_nodes",
    "requirement_nodes",
    "target_state_nodes",
    "supply_chain_nodes",
)

MIGRATION_BUILD_TYPE = "https://calm-forge/buildtypes/kg-plane-backfill/v1"


class PlaneError(ValueError):
    """Raised when a graph object's class/plane tagging is incoherent."""


def validate_node(node: dict[str, Any]) -> list[str]:
    """Structural gaps in one node's class/plane tagging.

    Returns descriptions rather than raising, so a loader can report every gap in a
    document at once instead of failing on the first.

    ``plane`` is **required on authored nodes and has no default.** A silent fallback to
    ``architecture`` is how an OSCAL intake would land controls nodes in the architecture
    plane invisibly, and nobody would notice until a cross-plane finding fired against
    nonsense. Fail closed, same posture as ADR-007's empty-``resolvedDependencies`` rule.
    """
    gaps: list[str] = []
    nid = node.get("@id", "<unknown>")
    node_class = node.get("node_class")

    if node_class is None:
        gaps.append(f"{nid}: missing node_class (authored | reference)")
        return gaps
    if node_class not in NODE_CLASSES:
        gaps.append(f"{nid}: unknown node_class {node_class!r} — expected one of "
                    f"{sorted(NODE_CLASSES)}")
        return gaps

    plane = node.get("plane")
    if node_class == NODE_CLASS_AUTHORED:
        if plane is None:
            gaps.append(f"{nid}: authored node has no plane — required, no default")
        elif plane not in PLANES:
            gaps.append(f"{nid}: unknown plane {plane!r} — planes are added by ADR "
                        f"(ADR-005 §7); known: {sorted(PLANES)}")
    elif plane is not None:
        gaps.append(f"{nid}: reference node carries plane {plane!r} — reference graphs "
                    f"author no intent and belong to no plane (ADR-012 §1)")
    return gaps


def validate_document(doc: dict[str, Any]) -> list[str]:
    """Class/plane gaps across a whole Workload document, root node included."""
    gaps = validate_node(doc)
    for container in _AUTHORED_CONTAINERS:
        for node in doc.get(container, []):
            gaps.extend(validate_node(node))
    return gaps


def plane_of(node: dict[str, Any]) -> str | None:
    """The plane a node belongs to, or ``None`` for reference nodes."""
    return node.get("plane") if node.get("node_class") == NODE_CLASS_AUTHORED else None


def plane_of_edge(edge: dict[str, Any], nodes_by_id: dict[str, dict[str, Any]]) -> str | None:
    """Derive an edge's plane from its **authoring node** — the source side.

    Endpoint-derivation is ambiguous for exactly the case that matters: a ``governs``
    edge *spans* planes, so its two endpoints disagree by construction. The source is
    the node that authored the assertion, so the assertion belongs to the source's
    plane. Nothing is stored; this is computed on read.
    """
    source = nodes_by_id.get(edge.get("from", ""))
    return plane_of(source) if source else None


def index_nodes(doc: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Map ``@id`` → node for every authored node in a document, root included."""
    index: dict[str, dict[str, Any]] = {}
    if doc.get("@id"):
        index[doc["@id"]] = doc
    for container in _AUTHORED_CONTAINERS:
        for node in doc.get(container, []):
            if node.get("@id"):
                index[node["@id"]] = node
    return index


def nodes_in_plane(doc: dict[str, Any], plane: str) -> list[dict[str, Any]]:
    """Authored nodes in one plane.

    Reference nodes never appear in a plane-filtered result — they have no plane, so
    their exclusion is correct rather than a gap. An unfiltered query returns
    everything; defaulting to ``architecture`` would make the multi-plane graph
    invisible to every existing caller.
    """
    if plane not in PLANES:
        raise PlaneError(
            f"unknown plane {plane!r} — planes are added by ADR (ADR-005 §7); "
            f"known: {sorted(PLANES)}"
        )
    return [n for n in index_nodes(doc).values() if plane_of(n) == plane]


# ---------------------------------------------------------------------------
# Backfill migration
# ---------------------------------------------------------------------------

def backfill_document(doc: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Stamp ``node_class: authored`` / ``plane: architecture`` where absent.

    Backfill rather than reader-dispatch: the passport dispatches on version because it
    is a *signed* wire format and signed history cannot be mutated. KG documents are
    unsigned working state with a single writer community, so a one-time stamp is
    honest — every existing node **is** CALM-authored, and the stamp records that truth
    rather than rewriting it.

    Returns the migrated document and the ids that were stamped. Already-tagged nodes
    are left alone, so the migration is idempotent.
    """
    stamped: list[str] = []

    def _stamp(node: dict[str, Any]) -> None:
        if node.get("node_class") is not None:
            return
        node["node_class"] = NODE_CLASS_AUTHORED
        node["plane"] = PLANE_ARCHITECTURE
        stamped.append(node.get("@id", "<unknown>"))

    _stamp(doc)
    for container in _AUTHORED_CONTAINERS:
        for node in doc.get(container, []):
            _stamp(node)
    return doc, stamped


def migration_provenance(
    document_name: str,
    before: str | bytes,
    after: str | bytes,
    stamped: list[str],
) -> dict[str, Any]:
    """SLSA provenance for a backfill run (ADR-007).

    The migration is a write like any other, and it must not be the one unattested
    write in the system. The pre-migration document is the resolved dependency at its
    digest-as-read; the migrated document is the subject; the stamped ids are recorded
    as an external parameter so the change is reviewable without diffing.
    """
    return build_provenance(
        [{"name": document_name, "digest": {"sha256": sha256_hex(after)}}],
        [{"uri": f"kg://documents/{document_name}",
          "digest": {"sha256": sha256_hex(before)}}],
        external_parameters={
            "migration": "kg-plane-backfill",
            "node_class": NODE_CLASS_AUTHORED,
            "plane": PLANE_ARCHITECTURE,
            "stamped_ids": sorted(stamped),
        },
        internal_parameters={"source_version": node_version(before)},
        build_type=MIGRATION_BUILD_TYPE,
    )


def plane_node_version(node: dict[str, Any]) -> str:
    """Content digest of a plane node, in the ``sha256:<hex>`` form (ADR-006 §5).

    Canonical JSON (sorted keys, compact separators) then sha256 — the same discipline
    ``edge_id`` uses one level down. Identity by content means a node touched but not
    changed produces the same version, so no drift finding fires on a no-op edit.
    """
    import json

    canonical = json.dumps(node, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return node_version(canonical)


def node_versions(docs: list[dict[str, Any]]) -> dict[str, str]:
    """``@id`` → current content digest across a set of Workload documents.

    This is the *left-hand side* of every cross-plane comparison: what the graph says
    now, against the digest-as-read a provenance record or passport captured earlier.
    """
    versions: dict[str, str] = {}
    for doc in docs:
        for node_id, node in index_nodes(doc).items():
            versions[node_id] = plane_node_version(node)
    return versions
