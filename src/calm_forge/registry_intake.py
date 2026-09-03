"""Registry intake — vendor drops → `supply_chain` plane graph (MP-35, ADR-013 §5).

Every vendor drop is ingested as graph state: image → layers → packages → versions. Two
payoffs the ADR names, and both are what make the Gate cheap rather than exhaustive:

**N → N±1 as a diff.** Consecutive drops are graph states; the delta is a traversal
(:func:`diff_drops`). The Gate then runs the *affected* archetypes — those whose dependency
surface intersects the diff (:func:`select_affected_archetypes`) — not the full suite on
every drop. Gate cost falls from O(archetypes) toward O(affected archetypes).

**Blast radius as a query.** "Which production workloads consume an image whose layer diff
includes this CVE'd package" is one traversal over the graph this intake produces as exhaust.

The graph is the accelerant; producing it is the point of this module. It emits nodes, not
attestations — the VSA is MP-33's job, and the two never merge.

Node class
----------
Images, layers and packages are ``node_class: authored`` / ``plane: supply_chain`` because
ADR-013 §7 makes registry graph state a citizen of the plane, and plane membership requires
an authored node. They are ingested evidence rather than hand-authored intent, so each
carries ``source: sbom`` to record that — the same honesty ``intake-tfe`` applies with
``provenance: reconstructed``. They are not reference nodes: a reference node authors no
intent and belongs to no plane (ADR-012 §1), whereas these *are* the plane's subject matter.

Scope
-----
SBOM ingestion is **CycloneDX and SPDX**, the two formats ADR-013 §7 names. Any other
document is refused by name rather than parsed to an empty package set — an SBOM that yields
zero packages is indistinguishable from an image with nothing in it, and the Gate would then
run no affected archetypes and wave the drop through. Layer attribution is optional: when a
drop supplies per-layer package lists the graph carries image → layer → package; without it,
image → package directly. Nothing is invented — an unattributed package links to the image,
never to a guessed layer.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .kg_plane import NODE_CLASS_AUTHORED, PLANE_SUPPLY_CHAIN

NODE_TYPE_IMAGE = "Image"
NODE_TYPE_LAYER = "Layer"
NODE_TYPE_PACKAGE = "Package"

IMAGE_ID_PREFIX = "kg://supply_chain/image"
LAYER_ID_PREFIX = "kg://supply_chain/layer"
PACKAGE_ID_PREFIX = "kg://supply_chain/package"

#: Within-plane edges. The authoring node is the source (ADR-005 §1), so both are
#: supply_chain-plane facts.
PREDICATE_CONTAINS_LAYER = "contains_layer"
PREDICATE_CONTAINS_PACKAGE = "contains_package"


class RegistryIntakeError(ValueError):
    """Raised when a document is not an SBOM this adapter reads."""


# ---------------------------------------------------------------------------
# Packages
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Package:
    """A package as read from an SBOM."""

    ecosystem: str
    name: str
    version: str
    purl: str | None = None

    def identity(self) -> tuple[str, str]:
        """Version-independent identity — what a diff keys on to detect a bump."""
        return (self.ecosystem, self.name)

    @property
    def node_id(self) -> str:
        return package_node_id(self.ecosystem, self.name, self.version)


def package_node_id(ecosystem: str, name: str, version: str) -> str:
    return f"{PACKAGE_ID_PREFIX}/{_slug(ecosystem)}/{_slug(name)}/{_slug(version)}"


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(value)).strip("-") or "unknown"


_PURL_RE = re.compile(r"^pkg:(?P<type>[^/]+)/(?P<rest>.+)$")


def parse_purl(purl: str) -> tuple[str, str, str] | None:
    """``pkg:<type>/<ns>/<name>@<version>`` → ``(ecosystem, name, version)``.

    Qualifiers and subpaths (``?...`` / ``#...``) are dropped; they do not change package
    identity. Returns ``None`` for a string that is not a purl.
    """
    match = _PURL_RE.match(purl.strip())
    if not match:
        return None
    ecosystem = match.group("type").lower()
    rest = match.group("rest").split("#", 1)[0].split("?", 1)[0]
    version = ""
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
    name = rest.rstrip("/").split("/")[-1]
    return ecosystem, name, version


def _purl_of(refs: list[dict[str, Any]]) -> str | None:
    for ref in refs or []:
        rtype = (ref.get("referenceType") or ref.get("type") or "").lower()
        if rtype == "purl":
            return ref.get("referenceLocator") or ref.get("locator")
    return None


def parse_sbom(sbom: dict[str, Any]) -> list[Package]:
    """Read packages from a CycloneDX or SPDX SBOM.

    The format is detected from its own marker keys; anything else is refused by name.
    """
    if not isinstance(sbom, dict):
        raise RegistryIntakeError(
            f"an SBOM is a JSON object, got {type(sbom).__name__}"
        )
    if sbom.get("bomFormat") == "CycloneDX" or "components" in sbom:
        return _parse_cyclonedx(sbom)
    if "spdxVersion" in sbom or "SPDXID" in sbom or "packages" in sbom:
        return _parse_spdx(sbom)
    raise RegistryIntakeError(
        "unrecognised SBOM — expected CycloneDX (bomFormat/components) or SPDX "
        "(spdxVersion/packages). Refusing rather than parsing to an empty package set, "
        "which would be indistinguishable from an image with nothing in it."
    )


def _package_from(name: str, version: str, purl: str | None) -> Package | None:
    ecosystem = ""
    if purl:
        parsed = parse_purl(purl)
        if parsed:
            p_eco, p_name, p_ver = parsed
            ecosystem = p_eco
            name = name or p_name
            version = version or p_ver
    if not name:
        return None
    return Package(ecosystem=ecosystem or "unknown", name=name, version=version or "", purl=purl)


def _parse_cyclonedx(sbom: dict[str, Any]) -> list[Package]:
    packages: list[Package] = []
    for component in sbom.get("components", []) or []:
        if not isinstance(component, dict):
            continue
        pkg = _package_from(
            component.get("name", ""), str(component.get("version", "")),
            component.get("purl"),
        )
        if pkg:
            packages.append(pkg)
    return packages


def _parse_spdx(sbom: dict[str, Any]) -> list[Package]:
    packages: list[Package] = []
    for entry in sbom.get("packages", []) or []:
        if not isinstance(entry, dict):
            continue
        pkg = _package_from(
            entry.get("name", ""), str(entry.get("versionInfo", "")),
            _purl_of(entry.get("externalRefs", [])),
        )
        if pkg:
            packages.append(pkg)
    return packages


# ---------------------------------------------------------------------------
# Intake
# ---------------------------------------------------------------------------

def intake_drop(
    sbom: dict[str, Any],
    *,
    image_ref: str,
    image_digest: str,
    layers: list[dict[str, Any]] | None = None,
) -> dict[str, list[Any]]:
    """Ingest one vendor drop into supply_chain-plane nodes and edges.

    Returns ``{"supply_chain_nodes": [...], "edges": [...], "gaps": [...]}``.

    ``image_digest`` is the content-addressable identity of the drop; ``image_ref`` is the
    human tag (never the identity — tags are not trusted, ADR-013 tier semantics).
    ``layers`` optionally maps packages to layers: ``[{"digest": ..., "packages":
    [<purl or name>...]}]``. A package no layer claims links to the image directly rather
    than to a fabricated layer.
    """
    bare_digest = _bare(image_digest)
    packages = parse_sbom(sbom)
    gaps: list[str] = []

    image_id = f"{IMAGE_ID_PREFIX}/{bare_digest}"
    image_node = {
        "@type": NODE_TYPE_IMAGE,
        "@id": image_id,
        "node_class": NODE_CLASS_AUTHORED,
        "plane": PLANE_SUPPLY_CHAIN,
        "source": "sbom",
        "image_ref": image_ref,
        "image_digest": f"sha256:{bare_digest}",
        "package_count": len(packages),
    }

    nodes: list[dict[str, Any]] = [image_node]
    edges: list[dict[str, Any]] = []

    # Package nodes, de-duplicated by node id (a package can be listed once per layer).
    package_nodes: dict[str, dict[str, Any]] = {}
    for pkg in packages:
        package_nodes.setdefault(pkg.node_id, {
            "@type": NODE_TYPE_PACKAGE,
            "@id": pkg.node_id,
            "node_class": NODE_CLASS_AUTHORED,
            "plane": PLANE_SUPPLY_CHAIN,
            "source": "sbom",
            "ecosystem": pkg.ecosystem,
            "name": pkg.name,
            "version": pkg.version,
            "purl": pkg.purl,
        })

    if not packages:
        gaps.append(
            f"{image_ref}: SBOM parsed to zero packages — the drop cannot be diffed or "
            f"gated meaningfully"
        )

    if layers:
        attributed = _intake_layers(
            image_id, layers, packages, nodes, edges, package_nodes, gaps
        )
        # Packages no layer claimed still belong to the image.
        for pkg in packages:
            if pkg.node_id not in attributed:
                edges.append({"@type": PREDICATE_CONTAINS_PACKAGE,
                              "from": image_id, "to": pkg.node_id})
    else:
        for pkg in packages:
            edges.append({"@type": PREDICATE_CONTAINS_PACKAGE,
                          "from": image_id, "to": pkg.node_id})

    nodes.extend(package_nodes.values())
    return {"supply_chain_nodes": nodes, "edges": edges, "gaps": gaps}


def _intake_layers(
    image_id: str,
    layers: list[dict[str, Any]],
    packages: list[Package],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    package_nodes: dict[str, dict[str, Any]],
    gaps: list[str],
) -> set[str]:
    """Emit layer nodes + image→layer→package edges. Returns attributed package node ids."""
    by_purl = {p.purl: p for p in packages if p.purl}
    by_name = {p.name: p for p in packages}
    by_identity = {p.identity(): p for p in packages}
    attributed: set[str] = set()

    for layer in layers:
        digest = _bare(layer.get("digest", ""))
        if not digest:
            gaps.append("a layer entry has no digest — skipped")
            continue
        layer_id = f"{LAYER_ID_PREFIX}/{digest}"
        nodes.append({
            "@type": NODE_TYPE_LAYER,
            "@id": layer_id,
            "node_class": NODE_CLASS_AUTHORED,
            "plane": PLANE_SUPPLY_CHAIN,
            "source": "sbom",
            "layer_digest": f"sha256:{digest}",
        })
        edges.append({"@type": PREDICATE_CONTAINS_LAYER, "from": image_id, "to": layer_id})

        for ref in layer.get("packages", []) or []:
            pkg = by_purl.get(ref) or by_name.get(ref)
            if pkg is None:
                parsed = parse_purl(ref) if isinstance(ref, str) else None
                if parsed:
                    pkg = by_identity.get((parsed[0], parsed[1]))
            if pkg is None:
                gaps.append(
                    f"layer {digest[:12]}… references package {ref!r} not in the SBOM — skipped"
                )
                continue
            edges.append({"@type": PREDICATE_CONTAINS_PACKAGE,
                          "from": layer_id, "to": pkg.node_id})
            attributed.add(pkg.node_id)

    return attributed


# ---------------------------------------------------------------------------
# N → N±1 diff
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PackageChange:
    ecosystem: str
    name: str
    from_version: str
    to_version: str


@dataclass
class DropDiff:
    added: list[Package]
    removed: list[Package]
    changed: list[PackageChange]

    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.changed)

    def touched_identities(self) -> set[tuple[str, str]]:
        """Every ``(ecosystem, name)`` the diff touches — added, removed, or bumped."""
        touched = {(p.ecosystem, p.name) for p in self.added}
        touched |= {(p.ecosystem, p.name) for p in self.removed}
        touched |= {(c.ecosystem, c.name) for c in self.changed}
        return touched

    def touched_ecosystems(self) -> set[str]:
        return {eco for eco, _ in self.touched_identities()}

    def touched_names(self) -> set[str]:
        return {name for _, name in self.touched_identities()}


def _packages_of(drop: dict[str, list[Any]] | list[dict[str, Any]]) -> list[Package]:
    """Extract Package objects from an intake result or a raw node list."""
    nodes = drop["supply_chain_nodes"] if isinstance(drop, dict) else drop
    packages: list[Package] = []
    for node in nodes:
        if node.get("@type") == NODE_TYPE_PACKAGE:
            packages.append(Package(
                ecosystem=node.get("ecosystem", "unknown"),
                name=node.get("name", ""),
                version=node.get("version", ""),
                purl=node.get("purl"),
            ))
    return packages


def diff_drops(
    before: dict[str, list[Any]] | list[dict[str, Any]],
    after: dict[str, list[Any]] | list[dict[str, Any]],
) -> DropDiff:
    """Compute the N → N±1 delta between two drops.

    Identity is ``(ecosystem, name)``; a version change on the same identity is a
    ``PackageChange``, not an add+remove pair — the version bump is the CVE-relevant event,
    and collapsing it to add/remove would lose that it is the *same* package.
    """
    before_pkgs = {p.identity(): p for p in _packages_of(before)}
    after_pkgs = {p.identity(): p for p in _packages_of(after)}

    added = [after_pkgs[k] for k in after_pkgs.keys() - before_pkgs.keys()]
    removed = [before_pkgs[k] for k in before_pkgs.keys() - after_pkgs.keys()]
    changed = [
        PackageChange(k[0], k[1], before_pkgs[k].version, after_pkgs[k].version)
        for k in before_pkgs.keys() & after_pkgs.keys()
        if before_pkgs[k].version != after_pkgs[k].version
    ]

    added.sort(key=lambda p: p.identity())
    removed.sort(key=lambda p: p.identity())
    changed.sort(key=lambda c: (c.ecosystem, c.name))
    return DropDiff(added=added, removed=removed, changed=changed)


# ---------------------------------------------------------------------------
# Affected-archetype selection
# ---------------------------------------------------------------------------

def select_affected_archetypes(
    diff: DropDiff, archetypes: list[dict[str, Any]]
) -> list[str]:
    """The archetypes whose dependency surface intersects the diff (ADR-013 §5).

    An archetype declares a ``dependency_surface`` — ``{"packages": [...names],
    "ecosystems": [...]}`` — of what it exercises. It is affected iff the diff touches a
    package it names or an ecosystem it covers. The Gate runs exactly these, not the full
    suite, which is what turns gate cost from O(archetypes) toward O(affected).

    A conservative default matters here: an archetype with **no declared surface** is
    treated as always affected, because "we did not say what this persona depends on" must
    not read as "this persona depends on nothing" and silently skip it.
    """
    touched_names = diff.touched_names()
    touched_ecos = diff.touched_ecosystems()
    affected: list[str] = []
    for archetype in archetypes:
        name = archetype.get("name")
        if not name:
            continue
        surface = archetype.get("dependency_surface")
        if not surface:
            affected.append(name)
            continue
        pkgs = set(surface.get("packages", []) or [])
        ecos = set(surface.get("ecosystems", []) or [])
        if (pkgs & touched_names) or (ecos & touched_ecos):
            affected.append(name)
    return sorted(affected)


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def _bare(digest: str) -> str:
    return digest.split(":", 1)[1] if digest.startswith("sha256:") else digest


def _load(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise RegistryIntakeError(
            f"{path}: expected a JSON object, got {type(data).__name__}"
        )
    return data


def intake_drop_from_file(
    sbom_path: str | Path,
    *,
    image_ref: str,
    image_digest: str,
    layers_path: str | Path | None = None,
) -> dict[str, list[Any]]:
    """Read the SBOM (and optional layer map) from disk and ingest the drop."""
    layers = None
    if layers_path is not None:
        loaded = _load(layers_path)
        layers = loaded.get("layers", loaded) if isinstance(loaded, dict) else loaded
    return intake_drop(
        _load(sbom_path), image_ref=image_ref, image_digest=image_digest, layers=layers
    )


def write_supply_chain_nodes(
    nodes: list[dict[str, Any]], output_dir: Path
) -> list[Path]:
    """Write supply_chain-plane nodes as JSON-LD to ``<output_dir>/supply_chain/``."""
    plane_dir = output_dir / "supply_chain"
    plane_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for node in nodes:
        safe = node["@id"].split("kg://supply_chain/", 1)[-1].replace("/", "-")
        path = plane_dir / f"{safe}.json"
        path.write_text(json.dumps(node, indent=2))
        written.append(path)
    return written
