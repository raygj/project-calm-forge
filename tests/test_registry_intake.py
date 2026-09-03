"""Registry intake — supply_chain graph, N→N±1 diff, affected-archetype selection
(MP-35, ADR-013 §5).

Behaviours pinned with their reason:

1. **A drop is graph state**, node_class=authored / plane=supply_chain, so it is a plane
   citizen (ADR-013 §7) and walks with :func:`node_versions`.
2. **A version bump is a change, not add+remove** — the bump is the CVE-relevant event, and
   collapsing it loses that it is the same package.
3. **The Gate runs only the affected archetypes** — the diff is the accelerant (§5).
4. **An unknown SBOM is refused by name**, not parsed to an empty package set that would
   wave a drop through the Gate.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.kg_plane import node_versions, plane_of
from calm_forge.registry_intake import (
    NODE_TYPE_IMAGE,
    NODE_TYPE_LAYER,
    NODE_TYPE_PACKAGE,
    RegistryIntakeError,
    diff_drops,
    intake_drop,
    parse_purl,
    parse_sbom,
    select_affected_archetypes,
    write_supply_chain_nodes,
)

ROOT = Path(__file__).parent.parent
SC = ROOT / "examples" / "supply-chain"

_CYCLONEDX = {
    "bomFormat": "CycloneDX",
    "components": [
        {"type": "library", "name": "openssl", "version": "3.0.11",
         "purl": "pkg:deb/debian/openssl@3.0.11"},
        {"type": "library", "name": "spring-core", "version": "6.0.11",
         "purl": "pkg:maven/org.springframework/spring-core@6.0.11"},
    ],
}
_SPDX = {
    "spdxVersion": "SPDX-2.3",
    "packages": [
        {"name": "openssl", "versionInfo": "3.0.11",
         "externalRefs": [{"referenceType": "purl",
                           "referenceLocator": "pkg:deb/debian/openssl@3.0.11"}]},
    ],
}


# ---------------------------------------------------------------------------
# purl + SBOM parsing
# ---------------------------------------------------------------------------

def test_parse_purl_extracts_ecosystem_name_version():
    assert parse_purl("pkg:maven/org.springframework/spring-core@6.0.11") == (
        "maven", "spring-core", "6.0.11")


def test_parse_purl_drops_qualifiers_and_subpath():
    assert parse_purl("pkg:deb/debian/openssl@3.0.11?arch=amd64#/usr/lib") == (
        "deb", "openssl", "3.0.11")


def test_parse_purl_rejects_a_non_purl():
    assert parse_purl("openssl-3.0.11") is None


def test_parse_cyclonedx_and_spdx_yield_the_same_package():
    cyclone = parse_sbom(_CYCLONEDX)
    spdx = parse_sbom(_SPDX)
    assert cyclone[0].ecosystem == spdx[0].ecosystem == "deb"
    assert cyclone[0].name == spdx[0].name == "openssl"
    assert cyclone[0].version == spdx[0].version == "3.0.11"


def test_an_unrecognised_sbom_is_refused_by_name():
    """Refusing beats parsing to an empty package set: zero packages would be
    indistinguishable from an empty image and the Gate would run no archetypes."""
    with pytest.raises(RegistryIntakeError, match="unrecognised SBOM"):
        parse_sbom({"format": "my-homegrown-thing", "stuff": []})


# ---------------------------------------------------------------------------
# Intake → graph
# ---------------------------------------------------------------------------

def test_drop_becomes_supply_chain_plane_nodes():
    result = intake_drop(_CYCLONEDX, image_ref="payments/api",
                         image_digest="sha256:" + "ab" * 32)
    nodes = result["supply_chain_nodes"]
    assert all(plane_of(n) == "supply_chain" for n in nodes)
    types = {n["@type"] for n in nodes}
    assert types == {NODE_TYPE_IMAGE, NODE_TYPE_PACKAGE}


def test_image_is_keyed_by_digest_not_tag():
    result = intake_drop(_CYCLONEDX, image_ref="payments/api:latest",
                         image_digest="sha256:" + "cd" * 32)
    image = next(n for n in result["supply_chain_nodes"] if n["@type"] == NODE_TYPE_IMAGE)
    assert image["@id"].endswith("cd" * 32)
    assert image["image_ref"] == "payments/api:latest"


def test_without_layers_packages_link_to_the_image():
    result = intake_drop(_CYCLONEDX, image_ref="x", image_digest="sha256:" + "ab" * 32)
    edges = result["edges"]
    assert all(e["@type"] == "contains_package" for e in edges)
    assert all(e["from"].startswith("kg://supply_chain/image/") for e in edges)


def test_layer_map_builds_image_layer_package_edges():
    layers = [{"digest": "sha256:" + "11" * 32,
               "packages": ["pkg:deb/debian/openssl@3.0.11"]}]
    result = intake_drop(_CYCLONEDX, image_ref="x", image_digest="sha256:" + "ab" * 32,
                         layers=layers)
    types = {n["@type"] for n in result["supply_chain_nodes"]}
    assert NODE_TYPE_LAYER in types
    # openssl attributed to the layer; spring-core (no layer) falls back to the image
    layer_edges = [e for e in result["edges"] if e["@type"] == "contains_layer"]
    assert len(layer_edges) == 1
    pkg_from_layer = [e for e in result["edges"]
                      if e["@type"] == "contains_package"
                      and e["from"].startswith("kg://supply_chain/layer/")]
    assert len(pkg_from_layer) == 1


def test_an_empty_sbom_is_reported_as_a_gap():
    result = intake_drop({"bomFormat": "CycloneDX", "components": []},
                         image_ref="empty", image_digest="sha256:" + "00" * 32)
    assert result["gaps"]
    assert "zero packages" in result["gaps"][0]


def test_supply_chain_nodes_are_walked_by_node_versions():
    """A plane node missing from the node_versions map reads as deleted; supply_chain nodes
    must be discovered by that walk, so the container is registered in kg_plane."""
    result = intake_drop(_CYCLONEDX, image_ref="x", image_digest="sha256:" + "ab" * 32)
    doc = {"@id": "workload:x", "node_class": "authored", "plane": "architecture",
           "supply_chain_nodes": result["supply_chain_nodes"]}
    versions = node_versions([doc])
    assert any(nid.startswith("kg://supply_chain/package/") for nid in versions)


# ---------------------------------------------------------------------------
# N → N±1 diff
# ---------------------------------------------------------------------------

def test_diff_detects_add_remove_and_bump():
    before = intake_drop(json.loads((SC / "drop-n.cyclonedx.json").read_text()),
                         image_ref="n", image_digest="sha256:" + "aa" * 32)
    after = intake_drop(json.loads((SC / "drop-n1.cyclonedx.json").read_text()),
                        image_ref="n1", image_digest="sha256:" + "bb" * 32)
    diff = diff_drops(before, after)

    assert [p.name for p in diff.added] == ["log4j-core"]
    assert diff.removed == []
    changed = {(c.name, c.from_version, c.to_version) for c in diff.changed}
    assert changed == {("openssl", "3.0.11", "3.0.13")}


def test_a_version_bump_is_a_change_not_an_add_and_remove():
    """The bump is the CVE event; collapsing it to add+remove loses that it is the same
    package identity moving versions."""
    before = intake_drop(_CYCLONEDX, image_ref="n", image_digest="sha256:" + "aa" * 32)
    bumped = json.loads(json.dumps(_CYCLONEDX))
    bumped["components"][0]["version"] = "3.0.13"
    bumped["components"][0]["purl"] = "pkg:deb/debian/openssl@3.0.13"
    after = intake_drop(bumped, image_ref="n1", image_digest="sha256:" + "bb" * 32)

    diff = diff_drops(before, after)
    assert diff.added == [] and diff.removed == []
    assert len(diff.changed) == 1 and diff.changed[0].name == "openssl"


def test_identical_drops_diff_to_nothing():
    a = intake_drop(_CYCLONEDX, image_ref="x", image_digest="sha256:" + "aa" * 32)
    b = intake_drop(_CYCLONEDX, image_ref="x", image_digest="sha256:" + "bb" * 32)
    assert diff_drops(a, b).is_empty()


# ---------------------------------------------------------------------------
# Affected-archetype selection
# ---------------------------------------------------------------------------

def test_affected_archetypes_intersect_the_diff():
    before = intake_drop(json.loads((SC / "drop-n.cyclonedx.json").read_text()),
                         image_ref="n", image_digest="sha256:" + "aa" * 32)
    after = intake_drop(json.loads((SC / "drop-n1.cyclonedx.json").read_text()),
                        image_ref="n1", image_digest="sha256:" + "bb" * 32)
    diff = diff_drops(before, after)
    suite = json.loads((SC / "archetype-suite.json").read_text())

    affected = select_affected_archetypes(diff, suite["archetypes"])
    # openssl (deb) hits go-strict-tls; log4j-core (maven) hits java-spring-heavy;
    # static-html (apk/nginx) is untouched
    assert affected == ["go-strict-tls", "java-spring-heavy"]


def test_an_archetype_with_no_declared_surface_is_always_affected():
    """'We did not say what this persona depends on' must not read as 'depends on nothing'
    and silently skip the persona — fail conservative."""
    before = intake_drop(_CYCLONEDX, image_ref="n", image_digest="sha256:" + "aa" * 32)
    after = intake_drop(_CYCLONEDX, image_ref="n", image_digest="sha256:" + "bb" * 32)
    diff = diff_drops(before, after)  # empty diff
    affected = select_affected_archetypes(diff, [{"name": "mystery-persona"}])
    assert affected == ["mystery-persona"]


# ---------------------------------------------------------------------------
# Files + CLI
# ---------------------------------------------------------------------------

def test_write_supply_chain_nodes(tmp_path):
    result = intake_drop(_CYCLONEDX, image_ref="x", image_digest="sha256:" + "ab" * 32)
    paths = write_supply_chain_nodes(result["supply_chain_nodes"], tmp_path)
    assert all(p.parent.name == "supply_chain" for p in paths)
    assert len(paths) == len(result["supply_chain_nodes"])


def test_cli_registry_intake_writes_nodes(tmp_path):
    res = CliRunner().invoke(cli, [
        "registry", "intake",
        "--sbom", str(SC / "drop-n1.cyclonedx.json"),
        "--image-ref", "payments/api:2026.34",
        "--image-digest", "sha256:" + "ab" * 32,
        "--output-dir", str(tmp_path),
    ])
    assert res.exit_code == 0, res.output
    assert "Image" in res.output and "Package" in res.output
    written = list((tmp_path / "supply_chain").glob("*.json"))
    assert written


def test_cli_registry_affected_selects_the_gate_subset():
    res = CliRunner().invoke(cli, [
        "registry", "affected",
        "--before", str(SC / "drop-n.cyclonedx.json"),
        "--after", str(SC / "drop-n1.cyclonedx.json"),
        "--archetypes", str(SC / "archetype-suite.json"),
    ])
    assert res.exit_code == 0, res.output
    assert "go-strict-tls" in res.output
    assert "java-spring-heavy" in res.output
    assert "static-html" not in res.output.split("affected archetype")[-1]
