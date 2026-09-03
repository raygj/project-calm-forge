"""Application registry → `AccountabilityAnchor` reference nodes (MP-20, ADR-010 §1/§6).

Every other governance artifact Forge emits answers *what is authorized*. This one
answers **who answers for it**. The registry binding an application to its accountable
owner enters the graph as a **semantic reference graph** (ADR-012), not as an authoring
plane: it authors no intent and projects no policy, so its nodes carry
``node_class: reference`` and **no plane at all**.

There is no sovereign DSL here
------------------------------
OSCAL has a standards body; TOSCA has one; application registries do not. Every
institution has a different export with different field names, which is exactly the
pressure that produces a per-deployment fork of the intake.

So the shape is inverted: this module defines a small canonical contract, and a
**declared field mapping** (:func:`apply_mapping`) aliases a deployment's own export
onto it. The mapping is *data* — a JSON file — never code. That is ADR-010 §6b as an
implementation: an institution brings its own identifier zoo, each species gets a
mapping, and nothing about the anchor model changes per deployment.

The three rules that fail closed
--------------------------------
1. **``accountable_for`` binds exactly one human.** Not zero, not two, not a group.
   An anchor that cannot satisfy this is **not emitted** — it is reported as a gap.
   Emitting it would produce an anchor that resolves, returns a value, renders in a
   report, and answers nobody, which ADR-010 §6a argues is strictly worse than a
   visibly missing one.
2. **``identity_class`` is declared, never inferred.** No guessing "E44921 looks like an
   employee number, ``svc-payments`` looks like a service account". A registry that does
   not say gets a gap, because a wrong guess here silently anchors an application to a
   robot.
3. **No PII enters a node.** The anchor holds an opaque identifier and nothing else
   about the person — no name, no email, no phone. Resolution to a human happens
   graph-side through an access-controlled traversal (ADR-010 §2), because the passport
   referencing this anchor travels to firewalls, log pipelines and auditors' laptops.
   :func:`assert_no_pii` refuses the node rather than trusting the registry to have
   been careful.

Scope
-----
**Anchor nodes and their identity edges. Nothing else.** Identity nodes themselves are
not authored here — the directory owns those (MP-41), and this intake emits edges
pointing at them the same way :mod:`.intake_oscal` emits ``governs`` edges at targets it
does not create. The ``UNANCHORED_EDGE`` / ``ORPHANED_ANCHOR`` / ``ANCHOR_DRIFT``
findings are a separate ADR-010 follow-up; this module supplies their left-hand side.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from .kg_plane import NODE_CLASS_REFERENCE

#: JSON-LD ``@type`` of an anchor node. The product term, deliberately not "seal" or
#: "license" — ADR-010 §1. Deployment vocabulary is a presentation-layer alias and must
#: never reach a stored type or a GUID.
NODE_TYPE_ANCHOR = "AccountabilityAnchor"

#: GUID scheme, ADR-004 §11 / ADR-012 §3.
NODE_ID_PREFIX = "kg://anchor"

#: The two bindings ADR-010 §6 splits the old single relation into.
PREDICATE_ACCOUNTABLE_FOR = "accountable_for"   # exactly one, human, mandatory
PREDICATE_ASSOCIATED_WITH = "associated_with"   # many, any class, informational

#: Identity GUID scheme for the edge targets. The nodes themselves are the directory's
#: to author (MP-41); these edges point at them by GUID and dangle until it lands.
IDENTITY_ID_PREFIX = "kg://identity"

IDENTITY_CLASS_HUMAN = "human"

#: Everything a human is not. Any of these may hold ``associated_with``; none of them
#: may ever hold ``accountable_for`` (ADR-010 §6a).
NON_HUMAN_IDENTITY_CLASSES = (
    "functional_id",      # FID
    "system_id",          # SID
    "service_account",
    "robot",
    "spiffe",
    "group",
    "distribution_list",  # the "chain terminates in an inbox" case, named explicitly
)

IDENTITY_CLASSES = (IDENTITY_CLASS_HUMAN, *NON_HUMAN_IDENTITY_CLASSES)

#: Field names that carry personal data in every registry export anyone has ever
#: shipped. Matched case-insensitively against key *substrings*, because the failure is
#: ``ownerEmailAddress`` as readily as ``email``.
PII_KEY_FRAGMENTS = (
    "email", "mail", "name", "phone", "mobile", "address", "upn",
    "givenname", "surname", "firstname", "lastname",
)

#: Keys exempt from the PII scan: they name *things*, not people.
PII_KEY_EXEMPT = frozenset({"name", "application_name", "registry_name"})

_EMAILISH = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")


class AnchorIntakeError(ValueError):
    """Raised when a registry document cannot be read as an accountability registry."""


# ---------------------------------------------------------------------------
# Deployment field mapping — data, never code
# ---------------------------------------------------------------------------

#: The canonical contract. A mapping renames a deployment's fields onto these.
CANONICAL_FIELDS = ("anchor_id", "application", "accountable", "associated", "props")
CANONICAL_IDENTITY_FIELDS = ("id", "identity_class", "role")


def apply_mapping(document: dict[str, Any], mapping: dict[str, Any] | None) -> dict[str, Any]:
    """Rewrite a deployment's registry export onto the canonical contract.

    ``mapping`` has three optional keys::

        {"entries": "applications",
         "fields": {"anchor_id": "app_code", "accountable": "owner", "id": "emp_no"},
         "identity_classes": {"EMP": "human", "SVC": "service_account"}}

    ``fields`` is a *canonical → deployment* rename applied at both the entry and the
    identity level; ``identity_classes`` translates the deployment's vocabulary for an
    identity class into ours. Anything unmapped passes through under its own name, so a
    registry that already speaks the contract needs no mapping at all.
    """
    if mapping is None:
        return document

    entries_key = mapping.get("entries", "entries")
    fields: dict[str, str] = mapping.get("fields", {})
    classes: dict[str, str] = mapping.get("identity_classes", {})

    def rename(obj: dict[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
        out = dict(obj)
        for canonical in keys:
            source = fields.get(canonical)
            if source and source in out:
                out[canonical] = out.pop(source)
        return out

    def remap_identity(raw: Any) -> Any:
        if not isinstance(raw, dict):
            return raw
        ident = rename(raw, CANONICAL_IDENTITY_FIELDS)
        declared = ident.get("identity_class")
        if declared in classes:
            ident["identity_class"] = classes[declared]
        return ident

    remapped: list[dict[str, Any]] = []
    for raw_entry in document.get(entries_key, []) or []:
        if not isinstance(raw_entry, dict):
            raise AnchorIntakeError(
                f"registry entries must be objects, got {type(raw_entry).__name__}")
        entry = rename(raw_entry, CANONICAL_FIELDS)
        if "accountable" in entry:
            entry["accountable"] = remap_identity(entry["accountable"])
        if "associated" in entry:
            associated = entry["associated"]
            if isinstance(associated, list):
                entry["associated"] = [remap_identity(i) for i in associated]
        remapped.append(entry)

    out = {k: v for k, v in document.items() if k != entries_key}
    out["entries"] = remapped
    return out


# ---------------------------------------------------------------------------
# PII refusal
# ---------------------------------------------------------------------------

def assert_no_pii(node: dict[str, Any]) -> None:
    """Refuse a node carrying personal data, by key name or by value shape.

    Both checks are needed and neither subsumes the other: a registry that exports
    ``{"owner_contact": "jane@acme.com"}`` defeats the key scan, and one that exports
    ``{"ownerEmail": "REDACTED"}`` defeats the value scan while still telling every
    downstream reader that this field is where the email goes.

    This is a *refusal*, not a scrub. Silently dropping the field would let a registry
    keep shipping PII into an intake that keeps quietly discarding it, and the day
    someone adds a passthrough it all arrives at once.
    """
    def walk(obj: Any, path: str) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                lowered = str(key).lower()
                if key not in PII_KEY_EXEMPT and any(f in lowered for f in PII_KEY_FRAGMENTS):
                    raise AnchorIntakeError(
                        f"{path}{key}: refusing a personal-data field in an anchor node. "
                        f"The anchor carries an opaque identifier; resolution to a person "
                        f"happens graph-side through an access-controlled traversal "
                        f"(ADR-010 §2), because this node's reference travels to every "
                        f"enforcement point that reads the passport")
                walk(value, f"{path}{key}.")
        elif isinstance(obj, list):
            for item in obj:
                walk(item, path)
        elif isinstance(obj, str) and _EMAILISH.search(obj):
            raise AnchorIntakeError(
                f"{path}: refusing an email-shaped value {obj!r} in an anchor node — "
                f"no PII travels with the artifact (ADR-010 §2)")

    walk(node, "")


# ---------------------------------------------------------------------------
# Identity handling
# ---------------------------------------------------------------------------

def _identity(raw: Any, *, where: str) -> tuple[dict[str, Any] | None, list[str]]:
    """Normalise one identity entry, reporting rather than raising on a bad one."""
    if not isinstance(raw, dict):
        return None, [f"{where}: identity must be an object, got {type(raw).__name__}"]

    ident_id = raw.get("id")
    if not ident_id:
        return None, [f"{where}: identity has no id"]

    declared = raw.get("identity_class")
    if declared is None:
        # Deliberately not inferred from the shape of the id. See module docstring.
        return None, [
            f"{where}: identity {ident_id!r} declares no identity_class — required, "
            f"never inferred (ADR-010 §6a). Known classes: {list(IDENTITY_CLASSES)}"
        ]
    if declared not in IDENTITY_CLASSES:
        return None, [
            f"{where}: identity {ident_id!r} has unknown identity_class {declared!r} — "
            f"known: {list(IDENTITY_CLASSES)}"
        ]

    ident: dict[str, Any] = {"id": str(ident_id), "identity_class": declared}
    if raw.get("role"):
        ident["role"] = str(raw["role"])
    return ident, []


def identity_node_id(identity: dict[str, Any]) -> str:
    """GUID of the identity an edge points at: ``kg://identity/<class>/<id>``."""
    return f"{IDENTITY_ID_PREFIX}/{identity['identity_class']}/{_slug(identity['id'])}"


def anchor_node_id(anchor_id: str) -> str:
    """GUID of an anchor node: ``kg://anchor/<id>``."""
    return f"{NODE_ID_PREFIX}/{_slug(anchor_id)}"


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(value)).strip("-") or "unknown"


# ---------------------------------------------------------------------------
# Intake
# ---------------------------------------------------------------------------

def intake_anchors(
    registry_document: dict[str, Any],
    *,
    mapping: dict[str, Any] | None = None,
) -> dict[str, list[Any]]:
    """Compile an application registry into anchor reference nodes and identity edges.

    Returns ``{"reference_nodes": [...], "edges": [...], "gaps": [...]}``.

    An entry that violates ADR-010 §6 or §6a yields a gap and **no node**. That is the
    fail-closed posture the ADR requires: a half-valid anchor is indistinguishable from
    a valid one at every downstream reader, so there is nowhere later to catch it.
    """
    if not isinstance(registry_document, dict):
        raise AnchorIntakeError(
            f"registry documents are objects, got {type(registry_document).__name__}")

    document = apply_mapping(registry_document, mapping)
    source = document.get("registry") or document.get("source") or "<unnamed-registry>"

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    gaps: list[str] = []
    seen: set[str] = set()

    for index, entry in enumerate(document.get("entries", []) or []):
        if not isinstance(entry, dict):
            gaps.append(f"entries[{index}]: must be an object, got {type(entry).__name__}")
            continue

        anchor_id = entry.get("anchor_id")
        where = f"anchor {anchor_id!r}" if anchor_id else f"entries[{index}]"
        if not anchor_id:
            gaps.append(f"entries[{index}]: no anchor_id")
            continue

        node_id = anchor_node_id(anchor_id)
        if node_id in seen:
            # Two entries claiming one anchor is a registry defect, and picking either
            # one silently would make accountability depend on export ordering.
            gaps.append(f"{where}: duplicate anchor id — {node_id} was already emitted")
            continue

        accountable, accountable_gaps = _accountable_of(entry, where)
        gaps.extend(accountable_gaps)

        associated: list[dict[str, Any]] = []
        raw_associated = entry.get("associated") or []
        if not isinstance(raw_associated, list):
            gaps.append(f"{where}: associated must be a list, got "
                        f"{type(raw_associated).__name__}")
            raw_associated = []
        for position, raw in enumerate(raw_associated):
            ident, ident_gaps = _identity(raw, where=f"{where} associated[{position}]")
            gaps.extend(ident_gaps)
            if ident is not None:
                associated.append(ident)

        if accountable is None:
            continue  # fail closed — no node without exactly one human

        node: dict[str, Any] = {
            "@type": NODE_TYPE_ANCHOR,
            "@id": node_id,
            "node_class": NODE_CLASS_REFERENCE,
            # No `plane` key, and not `"plane": None` either. A reference node belongs
            # to no plane, and kg_plane.validate_node rejects one that carries the key
            # (ADR-012 §1).
            "anchor_id": str(anchor_id),
            "source": source,
            "accountable_for": accountable,
            "associated_with": associated,
        }
        if entry.get("application"):
            node["application"] = entry["application"]
        if entry.get("props"):
            node["props"] = entry["props"]

        try:
            assert_no_pii(node)
        except AnchorIntakeError as exc:
            gaps.append(f"{where}: {exc}")
            continue

        nodes.append(node)
        seen.add(node_id)

        # Edges point *up* at the anchor — ADR-010 §6b. Nothing maps across.
        edges.append({
            "@type": PREDICATE_ACCOUNTABLE_FOR,
            "from": identity_node_id(accountable),
            "to": node_id,
        })
        for ident in associated:
            edges.append({
                "@type": PREDICATE_ASSOCIATED_WITH,
                "from": identity_node_id(ident),
                "to": node_id,
            })

    return {"reference_nodes": nodes, "edges": edges, "gaps": gaps}


def _accountable_of(
    entry: dict[str, Any], where: str
) -> tuple[dict[str, Any] | None, list[str]]:
    """The single accountable human, or ``None`` plus the reason there isn't one."""
    raw = entry.get("accountable")

    if isinstance(raw, list):
        # The shape ADR-010 §6 refuses. Reported specifically, because "expected an
        # object, got a list" would send someone off to fix a serialisation bug when
        # the actual answer is that the model does not represent shared accountability.
        if len(raw) == 1:
            raw = raw[0]
        else:
            return None, [
                f"{where}: accountable is a list of {len(raw)} — accountability binds "
                f"exactly one human (ADR-010 §6). A set of candidates resolves to "
                f"'one of these {len(raw)} people', which is indistinguishable from no "
                f"anchor. Put the others in associated and name one accountable party"
            ]

    if raw is None:
        return None, [f"{where}: no accountable party — mandatory, fails closed "
                      f"(ADR-010 §6)"]

    ident, gaps = _identity(raw, where=f"{where} accountable")
    if ident is None:
        return None, gaps

    if ident["identity_class"] != IDENTITY_CLASS_HUMAN:
        return None, [
            f"{where}: accountable party {ident['id']!r} is a "
            f"{ident['identity_class']}, not a human (ADR-010 §6a). A chain terminating "
            f"in a non-human identity resolves, returns a value, and answers nobody — "
            f"worse than an unanchored edge, which is at least visibly missing"
        ]
    return ident, gaps


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def _load(path: str | Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise AnchorIntakeError(
            f"{path}: expected a JSON object, got {type(data).__name__}")
    return data


def intake_anchors_from_file(
    registry_path: str | Path,
    *,
    mapping_path: str | Path | None = None,
) -> dict[str, list[Any]]:
    """Read the registry (and optional field mapping) from disk and compile them."""
    registry = _load(registry_path)
    assert registry is not None
    return intake_anchors(registry, mapping=_load(mapping_path))


def write_anchor_nodes(nodes: list[dict[str, Any]], output_dir: Path) -> list[Path]:
    """Write anchor nodes as JSON-LD to ``<output_dir>/reference/anchors/``.

    Under ``reference/`` rather than beside the plane outputs, because the directory
    layout is the first thing a reader uses to tell a plane from a reference graph.
    """
    anchors_dir = output_dir / "reference" / "anchors"
    anchors_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for node in nodes:
        safe = node["@id"].removeprefix(f"{NODE_ID_PREFIX}/").replace("/", "-")
        path = anchors_dir / f"{safe}.json"
        path.write_text(json.dumps(node, indent=2))
        written.append(path)
    return written
