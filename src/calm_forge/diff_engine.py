"""CALM diff engine — structural comparison of two CALM instantiation dicts.

Computes added/removed/modified nodes and relationships, classifies the
overall impact, estimates Terraform operation counts, and flags compliance-
sensitive field changes.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Fields whose change makes an element require destroy+recreate (breaking)
_BREAKING_NODE_FIELDS = {"node-type", "engine"}

# Fields that trigger OPA re-validation independent of impact level
_COMPLIANCE_FIELDS = {"node-type", "engine", "authentication", "protocol"}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def diff_calm(before: dict, after: dict) -> dict:
    """Compare two CALM instantiation dicts and return a structured diff.

    Parameters
    ----------
    before:
        The original CALM instantiation dict.
    after:
        The updated CALM instantiation dict.

    Returns
    -------
    dict with keys:
        nodes, relationships, metadata, impact, estimated_terraform,
        opa_revalidation_required, compliance_changes, summary
    """
    node_diff = _diff_elements(
        before.get("nodes", []),
        after.get("nodes", []),
        breaking_fields=_BREAKING_NODE_FIELDS,
    )
    rel_diff = _diff_elements(
        before.get("relationships", []),
        after.get("relationships", []),
        breaking_fields=set(),  # relationship changes are mutative unless removed
    )
    meta_diff = _diff_metadata(
        before.get("metadata", {}),
        after.get("metadata", {}),
    )

    # Impact classification (priority order: breaking > mutative > additive > none)
    impact = _classify_impact(node_diff, rel_diff)

    # Compliance changes
    compliance_changes = _collect_compliance_changes(node_diff, "node") + \
                         _collect_compliance_changes(rel_diff, "relationship")

    # OPA revalidation required when breaking, mutative, or compliance fields changed
    opa_required = impact in ("breaking", "mutative") or bool(compliance_changes)

    # Terraform operation estimates
    creates = len(node_diff["added"]) + len(rel_diff["added"])
    destroys = len(node_diff["removed"]) + len(rel_diff["removed"])
    updates = len(node_diff["modified"]) + len(rel_diff["modified"])

    estimated_terraform = {
        "creates": creates,
        "updates": updates,
        "destroys": destroys,
    }

    summary = _build_summary(impact, node_diff, rel_diff)

    return {
        "nodes": node_diff,
        "relationships": rel_diff,
        "metadata": meta_diff,
        "impact": impact,
        "estimated_terraform": estimated_terraform,
        "opa_revalidation_required": opa_required,
        "compliance_changes": compliance_changes,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _index_by_id(elements: list[dict]) -> dict[str, dict]:
    """Return a dict mapping unique-id → element dict."""
    return {e["unique-id"]: e for e in elements if "unique-id" in e}


def _diff_elements(
    before_list: list[dict],
    after_list: list[dict],
    *,
    breaking_fields: set[str],
) -> dict:
    """Compute added/removed/modified for a list of CALM elements."""
    before_map = _index_by_id(before_list)
    after_map = _index_by_id(after_list)

    before_ids = set(before_map)
    after_ids = set(after_map)

    added = [after_map[uid] for uid in sorted(after_ids - before_ids)]
    removed = [before_map[uid] for uid in sorted(before_ids - after_ids)]
    modified = []

    for uid in sorted(before_ids & after_ids):
        b = before_map[uid]
        a = after_map[uid]
        if b != a:
            modified.append({
                "before": b,
                "after": a,
                "_breaking_fields_changed": bool(
                    _changed_fields(b, a) & breaking_fields
                ),
            })

    return {"added": added, "removed": removed, "modified": modified}


def _changed_fields(before: dict, after: dict) -> set[str]:
    """Return the set of top-level keys whose values differ."""
    all_keys = set(before) | set(after)
    return {k for k in all_keys if before.get(k) != after.get(k)}


def _diff_metadata(before_meta: dict, after_meta: dict) -> dict:
    """Compute field-level diff for metadata dicts."""
    changed: dict[str, dict] = {}
    all_keys = set(before_meta) | set(after_meta)
    for key in sorted(all_keys):
        bv = before_meta.get(key)
        av = after_meta.get(key)
        if bv != av:
            changed[key] = {"before": bv, "after": av}
    return {"changed": changed}


def _classify_impact(node_diff: dict, rel_diff: dict) -> str:
    """Classify overall impact in priority order."""
    # Breaking: any removals, or breaking fields changed in nodes
    has_removals = bool(node_diff["removed"] or rel_diff["removed"])
    has_breaking_modifications = any(
        m.get("_breaking_fields_changed", False)
        for m in node_diff["modified"] + rel_diff["modified"]
    )

    if has_removals or has_breaking_modifications:
        return "breaking"

    # Mutative: modifications exist (but no removals or breaking field changes)
    has_modifications = bool(node_diff["modified"] or rel_diff["modified"])
    if has_modifications:
        return "mutative"

    # Additive: only additions
    has_additions = bool(node_diff["added"] or rel_diff["added"])
    if has_additions:
        return "additive"

    return "none"


def _collect_compliance_changes(element_diff: dict, kind: str) -> list[dict]:
    """Collect compliance-sensitive field changes from an element diff."""
    changes = []
    for mod in element_diff["modified"]:
        b = mod["before"]
        a = mod["after"]
        uid = b.get("unique-id", "unknown")
        for field in sorted(_COMPLIANCE_FIELDS):
            bv = b.get(field)
            av = a.get(field)
            if bv != av and (bv is not None or av is not None):
                changes.append({
                    "element": uid,
                    "kind": kind,
                    "field": field,
                    "before": bv,
                    "after": av,
                })
    return changes


def _build_summary(impact: str, node_diff: dict, rel_diff: dict) -> str:
    """Build a human-readable one-liner summary."""
    label = f"[{impact.upper()}]"
    parts = []

    added_nodes = len(node_diff["added"])
    removed_nodes = len(node_diff["removed"])
    modified_nodes = len(node_diff["modified"])
    added_rels = len(rel_diff["added"])
    removed_rels = len(rel_diff["removed"])

    if added_nodes:
        parts.append(f"+{added_nodes} node(s)")
    if removed_nodes:
        parts.append(f"-{removed_nodes} node(s)")
    if modified_nodes:
        parts.append(f"~{modified_nodes} node(s) modified")
    if added_rels:
        parts.append(f"+{added_rels} relationship(s)")
    if removed_rels:
        parts.append(f"-{removed_rels} relationship(s)")

    if not parts:
        return f"{label} no changes"

    return f"{label} {', '.join(parts)}"
