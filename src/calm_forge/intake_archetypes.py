"""Archetype suite — the Gate's policy as ``supply_chain``-plane nodes (MP-32).

ADR-013 §4: each persona is a versioned, owned node carrying its test-suite
definition and the estate evidence that justifies it. The suite has a content
digest per version. This module is the **mechanical half**:

* the node shape (``Archetype``, ``ArchetypeSuite``)
* the coverage-evidence schema (stored, not implied)
* the suite digest, computed on read from content, never from a clock

It does **not** author persona content. A suite with zero personas is
representable — that is the state until the design pass runs. An archetype
without coverage evidence is *not* representable: a persona nobody can audit
for ossification is the MP-32 trap.

Derived fields (persona count, represented classes, the digest itself) are
computed, never stored. Stored, they enter the content the digest is taken
over, and every later refinement would look like the suite moved (MP-44 /
ADR-015 B1, applied here).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from .kg_plane import NODE_CLASS_AUTHORED, PLANE_SUPPLY_CHAIN
from .provenance import sha256_hex
from .registry_intake import write_supply_chain_nodes

NODE_TYPE_ARCHETYPE = "Archetype"
NODE_TYPE_SUITE = "ArchetypeSuite"

ARCHETYPE_ID_PREFIX = "kg://supply_chain/archetype"
SUITE_ID_PREFIX = "kg://supply_chain/archetype-suite"

SCHEMA_VERSION = "0.1"
SCHEMA_KEY = "archetype_suite"

_SLUG = re.compile(r"[^A-Za-z0-9._-]+")


class ArchetypeIntakeError(ValueError):
    """Raised when a suite document cannot be read — unknown version, not a mapping."""


def _slug(value: str) -> str:
    return _SLUG.sub("-", str(value)).strip("-") or "unknown"


def archetype_node_id(name: str) -> str:
    return f"{ARCHETYPE_ID_PREFIX}/{_slug(name)}"


def suite_node_id(suite_version: str) -> str:
    return f"{SUITE_ID_PREFIX}/{_slug(suite_version)}"


def _plane_tag(node: dict[str, Any]) -> None:
    node["node_class"] = NODE_CLASS_AUTHORED
    node["plane"] = PLANE_SUPPLY_CHAIN


def _require_version(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise ArchetypeIntakeError(
            f"an archetype suite is a mapping, got {type(document).__name__}"
        )
    version = document.get(SCHEMA_KEY)
    if version is None:
        raise ArchetypeIntakeError(
            f"no {SCHEMA_KEY} — the version is the reader-dispatch key and has no "
            f"default. Falling back would silently misread a later document (MP-02)"
        )
    if str(version) != SCHEMA_VERSION:
        raise ArchetypeIntakeError(
            f"unknown {SCHEMA_KEY} {version!r} — this reader knows {SCHEMA_VERSION!r} "
            f"only. A default-to-newest branch silently misreads a valid document "
            f"(MP-02)"
        )
    return document


def _canonical(payload: Any) -> str:
    """Byte-stable JSON — same discipline as :func:`gate_runner.suite_descriptor`."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digestable_suite(
    suite_version: str,
    archetypes: list[dict[str, Any]],
) -> dict[str, Any]:
    """The suite content the digest is taken over. No ids, no plane tags, no clock."""
    bodies: list[dict[str, Any]] = []
    for node in sorted(archetypes, key=lambda n: n.get("name") or ""):
        body = {
            "name": node.get("name"),
            "coverage": node.get("coverage"),
        }
        for optional in ("purpose", "checks", "dependency_surface"):
            if node.get(optional) is not None:
                body[optional] = node[optional]
        bodies.append(body)
    return {"suite_version": suite_version, "archetypes": bodies}


def suite_digest(
    suite_version: str,
    archetypes: list[dict[str, Any]],
) -> str:
    """Content digest of the suite, bare sha256 hex. Computed, never stored.

    Matches :func:`calm_forge.gate_runner.suite_descriptor` so a VSA that hashed
    this payload compares equal to the current suite (MP-36).
    """
    return sha256_hex(_canonical(digestable_suite(suite_version, archetypes)))


def persona_count(archetypes: list[dict[str, Any]]) -> int:
    """Derived: how many personas the suite currently holds."""
    return len(archetypes)


def represented_classes(archetypes: list[dict[str, Any]]) -> list[str]:
    """Derived: the union of workload classes the personas claim to cover."""
    classes: set[str] = set()
    for node in archetypes:
        coverage = node.get("coverage") or {}
        for entry in coverage.get("workload_classes") or []:
            if isinstance(entry, dict) and entry.get("class"):
                classes.add(str(entry["class"]))
    return sorted(classes)


def _coverage(raw: Any, where: str) -> tuple[dict[str, Any] | None, list[str]]:
    if not isinstance(raw, dict):
        return None, [
            f"{where}: coverage evidence is required — a persona without it is a "
            f"suite nobody can audit for ossification (ADR-013 §4, MP-32)"
        ]
    gaps: list[str] = []
    basis = raw.get("basis")
    if not basis or not str(basis).strip():
        gaps.append(
            f"{where}: coverage.basis is required — counts without a measurement "
            f"story are a claim, not evidence"
        )
    classes_in = raw.get("workload_classes")
    if classes_in is None:
        gaps.append(f"{where}: coverage.workload_classes is required (may be empty)")
        classes_in = []
    if not isinstance(classes_in, list):
        gaps.append(f"{where}: coverage.workload_classes must be a list")
        classes_in = []

    classes: list[dict[str, Any]] = []
    for index, entry in enumerate(classes_in):
        slot = f"{where}.workload_classes[{index}]"
        if not isinstance(entry, dict):
            gaps.append(f"{slot}: must be {{class, count}}")
            continue
        klass = entry.get("class")
        count = entry.get("count")
        if not klass:
            gaps.append(f"{slot}: no class")
        if not isinstance(count, int) or isinstance(count, bool) or count < 0:
            gaps.append(f"{slot}: count must be a non-negative integer")
            continue
        if klass:
            classes.append({"class": str(klass), "count": count})

    if gaps:
        return None, gaps
    return {"workload_classes": classes, "basis": str(basis).strip()}, []


def _archetype(raw: Any, index: int) -> tuple[dict[str, Any] | None, list[str]]:
    where = f"archetypes[{index}]"
    if not isinstance(raw, dict):
        return None, [f"{where}: not a mapping — skipped"]
    name = raw.get("name")
    if not name:
        return None, [f"{where}: no name"]
    where = f"archetype {name!r}"
    coverage, coverage_gaps = _coverage(raw.get("coverage"), where)
    if coverage is None:
        return None, coverage_gaps

    node: dict[str, Any] = {
        "@type": NODE_TYPE_ARCHETYPE,
        "@id": archetype_node_id(str(name)),
        "name": str(name),
        "coverage": coverage,
    }
    _plane_tag(node)
    if raw.get("purpose"):
        node["purpose"] = str(raw["purpose"])
    if raw.get("checks"):
        node["checks"] = [str(c) for c in raw["checks"]]
    if raw.get("dependency_surface"):
        node["dependency_surface"] = raw["dependency_surface"]
    return node, []


def intake_archetypes(document: Any) -> dict[str, Any]:
    """Compile a suite document into ``Archetype`` / ``ArchetypeSuite`` nodes.

    Zero personas is success. A persona without coverage is a gap and is not
    emitted — fail closed, so a guessed name cannot land with a real digest.
    """
    doc = _require_version(document)
    suite_version = doc.get("suite_version")
    if not suite_version:
        raise ArchetypeIntakeError("suite_version is required")

    archetypes: list[dict[str, Any]] = []
    gaps: list[str] = []
    for index, raw in enumerate(doc.get("archetypes") or []):
        node, node_gaps = _archetype(raw, index)
        gaps.extend(node_gaps)
        if node is not None:
            archetypes.append(node)

    suite: dict[str, Any] = {
        "@type": NODE_TYPE_SUITE,
        "@id": suite_node_id(str(suite_version)),
        "suite_version": str(suite_version),
        "archetype_ids": [n["@id"] for n in archetypes],
    }
    _plane_tag(suite)
    if doc.get("description"):
        suite["description"] = str(doc["description"])

    return {
        "suite_nodes": [suite],
        "archetype_nodes": archetypes,
        "supply_chain_nodes": [suite, *archetypes],
        "gaps": gaps,
    }


def intake_archetypes_from_file(path: str | Path) -> dict[str, Any]:
    text = Path(path).read_text()
    if Path(path).suffix in {".yaml", ".yml"}:
        document = yaml.safe_load(text)
    else:
        document = json.loads(text)
    return intake_archetypes(document)


def write_archetype_nodes(result: dict[str, Any], output_dir: Path) -> list[Path]:
    """Write suite + archetype nodes into ``<output_dir>/supply_chain/``."""
    return write_supply_chain_nodes(result["supply_chain_nodes"], output_dir)
