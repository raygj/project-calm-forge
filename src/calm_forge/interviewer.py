"""Interview skill — agent-guided Workload authoring.

Accepts a structured spec dict and produces a complete Workload KG node in
ADR-0024 format with typed requires_capability and authored_in edges.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Core builder — spec dict → Workload node
# ---------------------------------------------------------------------------

def _workload_node_to_spec(node: dict[str, Any]) -> dict[str, Any]:
    node_id: str = node.get("@id", "")
    name: str = node.get("name", node_id.replace("workload:", "") if node_id else "")
    declared_capabilities: list[str] = node.get("declared_capabilities", [])
    compliance_scope: list[str] = node.get("compliance_scope", [])

    allowed_regions: list[str] = node.get("allowed_regions", [])
    if not allowed_regions:
        for policy in node.get("policies", []):
            if policy.get("predicate_type") == "compliance_boundary":
                allowed_regions = policy.get("allowed_regions", [])
                break

    raw_components: list[Any] = node.get("nodes", [])
    components: list[dict[str, Any]] = []
    for comp in raw_components:
        comp_id: str = comp.get("@id", "")
        comp_caps: list[str] = comp.get("declared_capabilities", comp.get("capabilities", []))
        components.append({
            "id": comp_id,
            "name": comp.get("name", comp_id),
            "capabilities": comp_caps,
        })

    return {
        "name": name,
        "description": node.get("description", ""),
        "declared_capabilities": declared_capabilities,
        "compliance_scope": compliance_scope,
        "allowed_regions": allowed_regions,
        "components": components,
        "purpose": node.get("purpose", ""),
        "owner": node.get("owner", ""),
    }


def _apply_proposal_patches(
    spec: dict[str, Any],
    proposed_changes: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[str]]:
    patched = dict(spec)
    prefilled_fields: list[str] = []

    for change in proposed_changes:
        field: str = change.get("field", "")
        if "suggested_value" not in change:
            continue
        suggested = change["suggested_value"]

        if field == "allowed_regions":
            patched["allowed_regions"] = suggested
            prefilled_fields.append(field)
        elif field == "compliance_scope":
            patched["compliance_scope"] = suggested
            prefilled_fields.append(field)
        elif field == "declared_capabilities":
            patched["declared_capabilities"] = suggested
            prefilled_fields.append(field)
        elif field == "components":
            prefilled_fields.append(field)

    return patched, prefilled_fields


def interview_from_proposal(proposal: dict[str, Any], kg_dir: Path) -> dict[str, Any]:
    workload_id: str = proposal.get("workload_id", "")
    slug = workload_id.replace("workload:", "")
    workload_path = kg_dir / "workloads" / f"{slug}.json"

    if workload_path.exists():
        try:
            node = json.loads(workload_path.read_text())
        except (ValueError, OSError):
            node = None
    else:
        node = None

    if node and node.get("@type") == "Workload":
        spec = _workload_node_to_spec(node)
    else:
        spec = {"name": slug}

    proposed_changes: list[dict[str, Any]] = proposal.get("proposed_changes", [])
    patched_spec, prefilled_fields = _apply_proposal_patches(spec, proposed_changes)

    workload_node = build_workload(patched_spec)
    return {
        "workload_id": workload_id,
        "workload": workload_node,
        "prefilled_fields": prefilled_fields,
        "proposal_confidence": proposal.get("confidence", "low"),
    }


def build_workload(spec: dict[str, Any], prefill: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build a Workload KG node from a structured spec.

    spec keys:
      name             str  — workload name (will be slugified for @id)
      purpose          str  — one-line description (optional)
      owner            str  — owning team (optional)
      components       list — [{name, role?, capabilities: [str]}]
      compliance_scope list — ["PCI-DSS-v4:req-3", "HIPAA:164.312", ...]
      allowed_regions  list — ["us-east-1", "eu-west-1", ...]
    """
    if prefill is not None:
        proposed_changes: list[dict[str, Any]] = prefill.get("proposed_changes", [])
        spec, _ = _apply_proposal_patches(spec, proposed_changes)

    name: str = spec.get("name", "unnamed-workload")
    slug = _slugify(name)
    workload_id = f"workload:{slug}"
    purpose: str = spec.get("purpose", "")
    owner: str = spec.get("owner", "")
    compliance_scope: list[str] = spec.get("compliance_scope", [])
    allowed_regions: list[str] = spec.get("allowed_regions", [])
    components: list[dict[str, Any]] = spec.get("components", [])

    # Build component nodes + collect capability union
    component_nodes: list[dict[str, Any]] = []
    all_capabilities: list[str] = []
    for comp in components:
        comp_name: str = comp.get("name", "")
        comp_slug = _slugify(comp_name)
        caps: list[str] = comp.get("capabilities", [])
        all_capabilities.extend(caps)
        node: dict[str, Any] = {
            "@type": "WorkloadComponent",
            "@id": f"{workload_id}:{comp_slug}",
            "name": comp_name,
        }
        if comp.get("role"):
            node["role"] = comp["role"]
        if caps:
            node["declared_capabilities"] = caps
        component_nodes.append(node)

    declared_capabilities = sorted(set(all_capabilities))

    # Build edges
    edges: list[dict[str, Any]] = []
    for comp in components:
        comp_slug = _slugify(comp.get("name", ""))
        comp_id = f"{workload_id}:{comp_slug}"
        for cap in comp.get("capabilities", []):
            edges.append({
                "@type": "requires_capability",
                "from": comp_id,
                "to": f"capability:{cap}",
            })
    for scope in compliance_scope:
        edges.append({
            "@type": "authored_in",
            "from": workload_id,
            "to": f"compliance:{scope}",
        })

    # Build policies
    policies: list[dict[str, Any]] = []
    if allowed_regions:
        policies.append({
            "@type": "Policy",
            "@id": f"{workload_id}:policy:data-residency",
            "predicate_type": "compliance_boundary",
            "subject": workload_id,
            "allowed_regions": allowed_regions,
            "enforcement_mode": "enforce",
            "evaluated_by": "calm.placement.region_constraint",
            "provenance": "authored",
        })
    # Capability-ceiling sentinel (manifests_as invariant)
    policies.append({
        "@type": "Policy",
        "@id": f"{workload_id}:policy:capability-ceiling",
        "predicate_type": "capability_ceiling",
        "subject": workload_id,
        "enforcement_mode": "enforce",
        "evaluated_by": "calm.manifest.capability_subset_check",
        "rationale": "Runtime Agent capabilities must not exceed declared Workload capabilities (manifests_as invariant)",
        "provenance": "authored",
    })

    node_body: dict[str, Any] = {
        "@context": "https://calmforge.io/kg/v1/context.jsonld",
        "@type": "Workload",
        "@id": workload_id,
        "version": "1.0.0",
        "name": name,
    }
    if purpose:
        node_body["purpose"] = purpose
    if owner:
        node_body["owner"] = owner
    if compliance_scope:
        node_body["compliance_scope"] = compliance_scope
    node_body["declared_capabilities"] = declared_capabilities
    if component_nodes:
        node_body["nodes"] = component_nodes
    if policies:
        node_body["policies"] = policies
    if edges:
        node_body["edges"] = edges
    node_body["review_required"] = False
    node_body["_provenance"] = {
        "authored_by": "calm-forge/interview",
        "authored_at": datetime.now(timezone.utc).isoformat(),
        "provenance": "authored",
    }
    return node_body


def write_workload_node(node: dict[str, Any], output_dir: Path) -> Path:
    """Write a Workload node to <output_dir>/workloads/<slug>.json."""
    wl_dir = output_dir / "workloads"
    wl_dir.mkdir(parents=True, exist_ok=True)
    slug = node["@id"].replace("workload:", "").replace("/", "-")
    path = wl_dir / f"{slug}.json"
    path.write_text(json.dumps(node, indent=2))
    return path


# ---------------------------------------------------------------------------
# Interactive session (Click-based, readable from stdin)
# ---------------------------------------------------------------------------

def interview_interactive() -> dict[str, Any]:
    """Run an interactive interview and return the spec dict."""
    import click

    click.echo("\nCALM Forge — Workload Interview")
    click.echo("────────────────────────────────")
    click.echo("Answer each prompt to author a new Workload node.")
    click.echo("Press Enter to accept defaults. Separate multiple values with commas.\n")

    name = click.prompt("Workload name")
    purpose = click.prompt("Short purpose (one sentence)", default="")
    owner = click.prompt("Owning team", default="platform-engineering")

    raw_components = click.prompt(
        "Service components (comma-separated, e.g. api-gateway,payments-processor,audit-db)"
    )
    component_names = [c.strip() for c in raw_components.split(",") if c.strip()]

    components: list[dict[str, Any]] = []
    for comp_name in component_names:
        raw_caps = click.prompt(
            f"  Required capabilities for {comp_name!r} (comma-separated, or Enter to skip)",
            default="",
        )
        caps = [c.strip() for c in raw_caps.split(",") if c.strip()]
        components.append({"name": comp_name, "capabilities": caps})

    raw_compliance = click.prompt(
        "Compliance scope (e.g. PCI-DSS-v4:req-3,HIPAA:164.312 — or Enter to skip)",
        default="",
    )
    compliance_scope = [c.strip() for c in raw_compliance.split(",") if c.strip()]

    raw_regions = click.prompt(
        "Allowed regions (e.g. us-east-1,eu-west-1 — or Enter for no constraint)",
        default="",
    )
    allowed_regions = [r.strip() for r in raw_regions.split(",") if r.strip()]

    return {
        "name": name,
        "purpose": purpose,
        "owner": owner,
        "components": components,
        "compliance_scope": compliance_scope,
        "allowed_regions": allowed_regions,
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
