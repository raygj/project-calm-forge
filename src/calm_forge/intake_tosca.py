"""TOSCA Service Template → business_intent-plane nodes (MP-21, ADR-005 §4).

The application and orchestration community authors in TOSCA. Forge is the PAP that
compiles what they authored into the ``business_intent`` plane; the join to the
architecture plane happens in the graph, on the same identity primitives OSCAL uses —
the workload URN and the edge id (ADR-005 §3). This is the OSCAL adapter's twin
(:mod:`calm_forge.intake_oscal`): same node shape (``node_class: authored`` /
``plane: business_intent``, no plane on edges), same one-way lossless-enough-to-audit
intake, same refusal-by-name for documents this adapter does not read.

Scope
-----
**Service Templates — ``topology_template.policies`` — with ``policy_type`` property
resolution. Nothing else.**

A TOSCA policy is the business/orchestration/lifecycle intent this plane exists to
carry, and ADR-006 already commits its GUID scheme: a passport's ``business_intent``
ref points at ``kg://tosca/policy/<template>/<policy>``. So the authored node is the
policy. ``node_templates`` are read only as a *lookup* — a policy's ``targets`` resolve
through them to the architecture-plane workloads/edges the policy governs — they are not
themselves emitted as business_intent nodes. Emitting the topology as first-class nodes
needs a ``kg://tosca/node`` GUID scheme, which is a plane commitment under ADR-005 §7 and
a separate follow-up; a partial node-template intake that read as complete would be worse
than none, the same discipline the OSCAL adapter applies to the OSCAL model set.

A document that is TOSCA but not a service template (a type-definitions library, which is
a legitimate ``--definitions`` input) raises :class:`ToscaIntakeError` naming what it is,
rather than parsing to zero policies — an empty result is indistinguishable from a
topology with no policies in it.

Property resolution
-------------------
Weakest to strongest:

1. ``policy-type-default`` — the ``default`` declared on the policy's type, resolved
   **through the type's own ``derived_from`` chain** (a child type overriding a parent's
   default wins).
2. ``policy`` — the policy template's own ``properties`` assignment.

**Scope, not just precedence — the property-inheritance trap.** A type's property
defaults apply only to policies *of that type* (through derivation). The wrong
implementation collects every ``policy_types`` default into one flat
``property-name → default`` map and applies it to every policy — which lands a
``max_unavailability_minutes`` default from an availability type onto a placement policy
that never declared it, and the generated artifact then carries a variable the type never
scoped there. This is the exact OSCAL failure (a profile's ``key-rotation-days`` leaking
onto a TLS control) one altitude up: the type's declared properties, walked through
``derived_from``, **are** the scope. The policy's own assignment is exempt — it is
written on one policy and cannot be misdirected.

Typing is deliberately *not* re-done here. OSCAL carries every value as a string and the
adapter must type it; TOSCA/JSON already carries typed values, so re-coercing ``"1.10"``
would reintroduce the exact float-mangling the OSCAL adapter goes out of its way to avoid.
Values pass through as authored; the declared TOSCA ``type`` rides along on each resolved
property for a generator that wants it.

A **required** property (TOSCA properties are required unless ``required: false``) that no
layer resolves is **reported, never defaulted** — see :func:`intake_tosca`. Optional
properties left unset are simply absent, which is not a gap.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .kg_plane import NODE_CLASS_AUTHORED, PLANE_BUSINESS_INTENT, PREDICATE_GOVERNS

#: The business_intent-plane node type. One per TOSCA policy.
NODE_TYPE_POLICY = "ToscaPolicy"

#: Node id scheme, as committed by ADR-006 (the passport's business_intent ref):
#: ``kg://tosca/policy/<template>/<policy>``.
NODE_ID_PREFIX = "kg://tosca/policy"

#: Metadata key carrying a graph object this policy (or one of its targets) governs — a
#: workload URN or a ``kg://edges/v1/...`` edge id. Mirrors the OSCAL adapter's ``governs``
#: prop; the union across the policy and its targets is the node's ``governs`` set.
GOVERNS_KEY = "governs"

#: Property layers, weakest first. The index doubles as the precedence.
PROPERTY_LAYERS = ("policy-type-default", "policy")

#: Top-level sections that mark a document as a TOSCA type-definitions library rather
#: than a service template. Present without a ``topology_template``, the document is
#: refused by name — it is a valid ``--definitions`` input, not a service template.
TYPE_DEFINITION_SECTIONS = (
    "node_types",
    "policy_types",
    "capability_types",
    "relationship_types",
    "group_types",
    "data_types",
    "artifact_types",
    "interface_types",
)


class ToscaIntakeError(ValueError):
    """Raised when a document is not a TOSCA service template this adapter reads."""


# ---------------------------------------------------------------------------
# Reading the TOSCA documents
# ---------------------------------------------------------------------------

def _require_tosca(document: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ToscaIntakeError(
            f"TOSCA documents are objects, got {type(document).__name__}"
        )
    if "tosca_definitions_version" not in document:
        raise ToscaIntakeError(
            "not a TOSCA document — no tosca_definitions_version key; refusing rather "
            "than parsing an unknown document to an empty result"
        )
    return document


def service_template(document: dict[str, Any]) -> dict[str, Any]:
    """Return a service template's ``topology_template``, refusing non-service docs.

    A type-definitions library (``policy_types`` / ``node_types`` / …) with no
    ``topology_template`` is refused by name: it is the ``--definitions`` input that
    supplies property defaults, not a service template, and reading it to zero policies
    would be indistinguishable from a topology that declares none.
    """
    doc = _require_tosca(document)
    topology = doc.get("topology_template")
    if topology is None:
        present = [s for s in TYPE_DEFINITION_SECTIONS if s in doc]
        if present:
            raise ToscaIntakeError(
                f"this is a TOSCA type-definitions library ({', '.join(present)}), not "
                f"a service template — it declares types but no topology_template. Pass "
                f"it with --definitions to supply policy-type property defaults; it is "
                f"not itself an intake source."
            )
        raise ToscaIntakeError(
            "no topology_template — a service template must carry one; there is nothing "
            "to intake"
        )
    if not isinstance(topology, dict):
        raise ToscaIntakeError("topology_template is not an object")
    return topology


def policy_type_index(*documents: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    """Merge ``policy_types`` across documents. Later documents win on name collision.

    Types usually live in the ``--definitions`` document; a service template may also
    declare them inline, and its declarations take precedence (call order puts the
    service document last).
    """
    types: dict[str, dict[str, Any]] = {}
    for doc in documents:
        if not doc:
            continue
        for name, defn in (doc.get("policy_types") or {}).items():
            if isinstance(defn, dict):
                types[name] = defn
    return types


def _named(section: Any) -> dict[str, dict[str, Any]]:
    """A TOSCA ``name → definition`` map, or empty when the section is missing/malformed."""
    return section if isinstance(section, dict) else {}


def _iter_policies(topology: dict[str, Any]):
    """Yield ``(name, definition)`` for each policy.

    TOSCA renders ``policies`` as a list of single-key maps; a dict form is tolerated for
    hand-authored convenience.
    """
    raw = topology.get("policies") or []
    if isinstance(raw, dict):
        yield from raw.items()
        return
    for entry in raw:
        if isinstance(entry, dict):
            yield from entry.items()


def _metadata_governs(obj: dict[str, Any]) -> list[str]:
    metadata = obj.get("metadata") or {}
    value = metadata.get(GOVERNS_KEY)
    if value is None:
        return []
    return [str(v) for v in (value if isinstance(value, list) else [value])]


# ---------------------------------------------------------------------------
# Type inheritance
# ---------------------------------------------------------------------------

def type_lineage(
    type_name: str, types: dict[str, dict[str, Any]]
) -> tuple[list[tuple[str, dict[str, Any]]], list[str]]:
    """The ``derived_from`` chain from ``type_name`` up, **most-derived first**.

    Returns ``(chain, missing)``. ``missing`` names any type in the chain that is not in
    ``types`` — the walk stops there rather than guessing, because a broken ancestry means
    the property set and its required flags cannot be resolved, and silently returning a
    partial set is how a required property goes missing unnoticed. A ``derived_from`` cycle
    is broken defensively.
    """
    chain: list[tuple[str, dict[str, Any]]] = []
    missing: list[str] = []
    seen: set[str] = set()
    current: str | None = type_name
    while current:
        if current in seen:
            break
        seen.add(current)
        defn = types.get(current)
        if defn is None:
            missing.append(current)
            break
        chain.append((current, defn))
        current = defn.get("derived_from")
    return chain, missing


def type_property_definitions(
    type_name: str, types: dict[str, dict[str, Any]]
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """``property-name → definition`` for a type, most-derived declaration winning.

    A child type redeclaring a property (to change its default, say) overrides the
    ancestor's declaration, so the first definition seen walking from the most-derived
    type upward wins. Returns ``(definitions, missing)``.
    """
    chain, missing = type_lineage(type_name, types)
    defs: dict[str, dict[str, Any]] = {}
    for _name, defn in chain:
        for prop, pdef in (defn.get("properties") or {}).items():
            if prop not in defs and isinstance(pdef, dict):
                defs[prop] = pdef
    return defs, missing


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------

def resolve_properties(
    policy_type: str | None,
    *,
    types: dict[str, dict[str, Any]] | None = None,
    assignments: dict[str, Any] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[str], list[str]]:
    """Resolve one policy's properties through the type-default and assignment layers.

    Returns ``(resolved, unresolved, missing_types)`` where ``resolved`` maps
    property-name to ``{"value": ..., "set_by": <layer>, "type": <declared tosca type>}``,
    ``unresolved`` lists **required** type-declared properties no layer supplied, and
    ``missing_types`` names types in the ``derived_from`` chain that were not found.

    **The type's declared properties are the scope.** Type defaults apply only to
    properties the type (through derivation) declares — that scoping is what keeps a
    sibling type's default from leaking onto this policy. The policy's own assignment is
    exempt: it is written on exactly one policy and cannot be misdirected, so it applies
    even for a property the type does not declare, rather than being discarded as the most
    specific statement in the document.

    An unresolved required property is **never given a placeholder** — an artifact
    generated from an empty value asserts something the author never wrote.
    """
    assignments = assignments or {}
    defs: dict[str, dict[str, Any]] = {}
    missing: list[str] = []
    if policy_type is not None and types:
        defs, missing = type_property_definitions(policy_type, types)

    resolved: dict[str, dict[str, Any]] = {}

    # Layer 1 — policy-type-default. Scoped to the type's declared properties by
    # construction: `defs` only holds what this type's lineage declares.
    for prop, pdef in defs.items():
        if "default" in pdef:
            resolved[prop] = {
                "value": pdef["default"],
                "set_by": "policy-type-default",
                "type": pdef.get("type"),
            }

    # Layer 2 — the policy's own assignment. Strongest, and exempt from type-scoping.
    for prop, value in assignments.items():
        resolved[prop] = {
            "value": value,
            "set_by": "policy",
            "type": defs.get(prop, {}).get("type"),
        }

    required = {p for p, d in defs.items() if d.get("required", True) is not False}
    unresolved = sorted(p for p in required if p not in resolved)
    return resolved, unresolved, missing


def property_variables(node: dict[str, Any]) -> dict[str, Any]:
    """``property-name → value``, for a generator to read as variables.

    Computed on read, never stored beside ``properties``: a second copy of the same fact
    is a second thing that can go stale — the divergence the content-digest discipline
    (ADR-007) exists to eliminate.
    """
    return {prop: p["value"] for prop, p in (node.get("properties") or {}).items()}


# ---------------------------------------------------------------------------
# Intake
# ---------------------------------------------------------------------------

def intake_tosca(
    service_document: dict[str, Any],
    *,
    definitions: dict[str, Any] | None = None,
    template_name: str | None = None,
) -> dict[str, list[Any]]:
    """Compile a TOSCA Service Template into business_intent-plane nodes and edges.

    Returns ``{"business_intent_nodes": [...], "edges": [...], "gaps": [...]}``.

    One node per TOSCA policy, tagged ``node_class: authored`` / ``plane:
    business_intent`` — never architecture. A business_intent node landing in the
    architecture plane would be invisible to every cross-plane finding, the exact failure
    ADR-005's no-default plane rule exists to prevent.

    ``governs`` edges join the business_intent plane to the architecture plane in the
    graph, one direction, from the policy node outward. The set unions the policy's own
    ``metadata.governs`` with the ``metadata.governs`` of each node template (or group) the
    policy targets, so a policy targeting ``api`` inherits the architecture URN/edge that
    node template maps to. The edge carries no plane of its own; its plane is its authoring
    node's (ADR-005 §1).
    """
    topology = service_template(service_document)
    name = template_name or (service_document.get("metadata") or {}).get("template_name")
    if not name:
        raise ToscaIntakeError(
            "service template has no metadata.template_name and none was supplied — the "
            "business_intent node GUID kg://tosca/policy/<template>/<policy> needs a "
            "stable template name to key on, so re-running intake updates the node rather "
            "than orphaning it"
        )

    types = policy_type_index(definitions, service_document)
    node_templates = _named(topology.get("node_templates"))
    groups = _named(topology.get("groups"))

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    gaps: list[str] = []

    for policy_name, defn in _iter_policies(topology):
        if not isinstance(defn, dict):
            gaps.append(f"policy {policy_name!r} is not an object — skipped")
            continue

        policy_type = defn.get("type")
        if not policy_type:
            gaps.append(f"policy {policy_name!r} has no type — skipped")
            continue

        resolved, unresolved, missing = resolve_properties(
            policy_type, types=types, assignments=defn.get("properties") or {}
        )
        for missing_type in missing:
            gaps.append(
                f"{policy_name}: policy type {missing_type!r} is not in the supplied "
                f"definitions — its property defaults and required flags cannot be "
                f"resolved, so a required property could be silently missing"
            )
        for prop in unresolved:
            gaps.append(
                f"{policy_name}: required property {prop!r} is declared by "
                f"{policy_type!r} but no layer resolves it — a policy generated from "
                f"this would have a hole"
            )

        targets = list(defn.get("targets") or [])
        governs = set(_metadata_governs(defn))
        for target in targets:
            template = node_templates.get(target) or groups.get(target)
            if template:
                governs |= set(_metadata_governs(template))
        governs_sorted = sorted(governs)

        node_id = policy_node_id(name, policy_name)
        nodes.append({
            "@type": NODE_TYPE_POLICY,
            "@id": node_id,
            "node_class": NODE_CLASS_AUTHORED,
            "plane": PLANE_BUSINESS_INTENT,
            "template_name": name,
            "policy_name": policy_name,
            "policy_type": policy_type,
            "description": defn.get("description"),
            "properties": resolved,
            "unresolved_properties": unresolved,
            "targets": targets,
            "governs": governs_sorted,
            "metadata": defn.get("metadata") or {},
        })
        edges.extend(
            {"@type": PREDICATE_GOVERNS, "from": node_id, "to": target}
            for target in governs_sorted
        )

    return {"business_intent_nodes": nodes, "edges": edges, "gaps": gaps}


def policy_node_id(template_name: str, policy_name: str) -> str:
    """Stable business_intent-plane node id (ADR-006 GUID scheme).

    Keyed on the service-template name plus the policy name — both stable across
    re-authoring — so re-running intake against an updated template **updates** the node
    rather than orphaning it, and ``ORPHANED_POLICY`` stays a real signal instead of
    firing on every routine re-import.
    """
    return f"{NODE_ID_PREFIX}/{_slug(template_name)}/{_slug(policy_name)}"


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(value)).strip("-") or "unknown"


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def _load(path: str | Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise ToscaIntakeError(
            f"{path}: TOSCA documents are objects, got {type(data).__name__}"
        )
    return data


def intake_tosca_from_file(
    service_template_path: str | Path,
    *,
    definitions_path: str | Path | None = None,
    template_name: str | None = None,
) -> dict[str, list[Any]]:
    """Read the TOSCA documents from disk and compile them."""
    service = _load(service_template_path)
    assert service is not None
    return intake_tosca(
        service, definitions=_load(definitions_path), template_name=template_name
    )


def write_business_intent_nodes(
    nodes: list[dict[str, Any]], output_dir: Path
) -> list[Path]:
    """Write business_intent-plane nodes as JSON-LD to ``<output_dir>/business_intent/``."""
    plane_dir = output_dir / "business_intent"
    plane_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for node in nodes:
        safe = node["@id"].removeprefix(f"{NODE_ID_PREFIX}/").replace("/", "-")
        path = plane_dir / f"{safe}.json"
        path.write_text(json.dumps(node, indent=2))
        written.append(path)
    return written
