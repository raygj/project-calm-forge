"""DCM placement artifact writer.

Generates a dcm-placement-api compatible Application spec from a CALM
architecture + decorator. The artifact is emitted as part of the full
generator output and can be POSTed directly to POST /applications on a
dcm-placement-api instance.

Field derivation:
  name     — architecture title (sanitized) or metadata.name
  service  — "container" if any node carries container-image, else "webserver"
  tier     — decorator.data.dcm.tier  OR  PCI heuristic (1) OR 2 (default)
  zones    — decorator.data.dcm.zones OR [decorator.data.region] OR []

Explicit overrides via decorator.data.dcm take precedence over heuristics.
"""
from __future__ import annotations

import json
import re


def write_dcm_application(architecture: dict, decorator: dict) -> str:
    """Return a JSON string suitable for POST /applications on dcm-placement-api."""
    spec: dict = {
        "name": _derive_name(architecture),
        "service": _derive_service(architecture),
        "tier": _derive_tier(architecture, decorator),
        "zones": _derive_zones(decorator),
    }
    required_capabilities = _derive_required_capabilities(architecture)
    if required_capabilities:
        spec["required_capabilities"] = required_capabilities
        spec["placement_strategy"] = _derive_placement_strategy(architecture, decorator)
    return json.dumps(spec, indent=2)


# ---------------------------------------------------------------------------
# Field derivation helpers
# ---------------------------------------------------------------------------


def _derive_name(architecture: dict) -> str:
    title = (
        architecture.get("title")
        or architecture.get("metadata", {}).get("name")
        or architecture.get("$id", "").split("/")[-1]
        or "unknown"
    )
    # Strip everything after a long dash or " - " separator (e.g. "Portal — Production Architecture")
    title = re.split(r"\s*[—–]\s*|\s+-\s+", title)[0].strip()
    # Normalize to lowercase hyphenated slug for DCM compatibility
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return slug or "unknown"


def _derive_service(architecture: dict) -> str:
    nodes = architecture.get("nodes", [])
    for node in nodes:
        if node.get("container-image") or node.get("node-type") == "service":
            return "container"
    return "webserver"


def _derive_tier(architecture: dict, decorator: dict) -> int:
    dcm_overrides = decorator.get("data", {}).get("dcm", {})
    if "tier" in dcm_overrides:
        return int(dcm_overrides["tier"])

    # Heuristic: PCI scope in node descriptions or title → tier 1
    title = architecture.get("title", "").lower()
    if "pci" in title:
        return 1
    for node in architecture.get("nodes", []):
        desc = node.get("description", "").lower()
        if "pci" in desc:
            return 1

    return 2


def _derive_required_capabilities(architecture: dict) -> list[str]:
    """Collect required-capabilities from all nodes, deduplicated and sorted."""
    capabilities: set[str] = set()
    for node in architecture.get("nodes", []):
        for cap in node.get("required-capabilities", []):
            capabilities.add(cap)
    return sorted(capabilities)


def _derive_placement_strategy(architecture: dict, decorator: dict) -> str:
    dcm = decorator.get("data", {}).get("dcm", {})
    if "placement_strategy" in dcm:
        return str(dcm["placement_strategy"])
    if architecture.get("metadata", {}).get("placement-strategy"):
        return str(architecture["metadata"]["placement-strategy"])
    return "zone_match"


def _derive_zones(decorator: dict) -> list[str]:
    dcm_overrides = decorator.get("data", {}).get("dcm", {})
    if "zones" in dcm_overrides:
        zones = dcm_overrides["zones"]
        return list(zones) if isinstance(zones, (list, tuple)) else [str(zones)]

    region = decorator.get("data", {}).get("region")
    if region:
        return [region]

    return []
