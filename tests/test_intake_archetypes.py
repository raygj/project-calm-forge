"""Archetype suite intake — mechanical half (MP-32, ADR-013 §4)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.gate_runner import suite_descriptor
from calm_forge.intake_archetypes import (
    NODE_TYPE_ARCHETYPE,
    NODE_TYPE_SUITE,
    SCHEMA_KEY,
    ArchetypeIntakeError,
    digestable_suite,
    intake_archetypes,
    intake_archetypes_from_file,
    persona_count,
    represented_classes,
    suite_digest,
    write_archetype_nodes,
)
from calm_forge.kg_plane import NODE_CLASS_AUTHORED, PLANE_SUPPLY_CHAIN

_EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "supply-chain"
_EMPTY = _EXAMPLES / "archetype-suite-empty.json"

_ONE_PERSONA = {
    SCHEMA_KEY: "0.1",
    "suite_version": "v1-fixture",
    "archetypes": [
        {
            "name": "fixture-persona",
            "purpose": "Test fixture only — not an estate claim",
            "dependency_surface": {"ecosystems": ["maven"], "packages": ["postgresql"]},
            "coverage": {
                "workload_classes": [
                    {"class": "payments-java-api", "count": 3},
                ],
                "basis": "unit-test fixture, not an inventory join",
            },
        }
    ],
}


def test_empty_suite_is_representable_and_has_a_content_digest() -> None:
    result = intake_archetypes_from_file(_EMPTY)
    assert result["gaps"] == []
    assert result["archetype_nodes"] == []
    suite = result["suite_nodes"][0]
    assert suite["@type"] == NODE_TYPE_SUITE
    assert suite["node_class"] == NODE_CLASS_AUTHORED
    assert suite["plane"] == PLANE_SUPPLY_CHAIN
    assert suite["archetype_ids"] == []
    digest = suite_digest(suite["suite_version"], [])
    assert len(digest) == 64
    assert "digest" not in suite
    assert persona_count([]) == 0


def test_empty_suite_digest_is_stable_across_reads() -> None:
    a = suite_digest("v0", [])
    b = suite_digest("v0", [])
    assert a == b


def test_digest_matches_the_gate_suite_descriptor() -> None:
    """MP-36 compares VSA policy.digest to the current suite — one hash, both sides."""
    payload = digestable_suite("v0", [])
    assert suite_descriptor("kg://unused", content=payload)["digest"]["sha256"] == (
        suite_digest("v0", [])
    )


def test_persona_without_coverage_is_a_gap_and_is_not_emitted() -> None:
    result = intake_archetypes({
        SCHEMA_KEY: "0.1",
        "suite_version": "v1",
        "archetypes": [{"name": "guessed-java"}],
    })
    assert result["archetype_nodes"] == []
    assert any("coverage" in g for g in result["gaps"])
    # The suite still lands — the guessed name does not, so it cannot carry a digest.
    assert result["suite_nodes"][0]["archetype_ids"] == []


def test_coverage_without_a_basis_is_a_gap() -> None:
    result = intake_archetypes({
        SCHEMA_KEY: "0.1",
        "suite_version": "v1",
        "archetypes": [{
            "name": "named",
            "coverage": {"workload_classes": [{"class": "x", "count": 1}]},
        }],
    })
    assert result["archetype_nodes"] == []
    assert any("basis" in g for g in result["gaps"])


def test_persona_with_coverage_is_emitted_and_digest_covers_it() -> None:
    result = intake_archetypes(_ONE_PERSONA)
    assert result["gaps"] == []
    node = result["archetype_nodes"][0]
    assert node["@type"] == NODE_TYPE_ARCHETYPE
    assert node["coverage"]["workload_classes"][0]["class"] == "payments-java-api"
    assert represented_classes(result["archetype_nodes"]) == ["payments-java-api"]
    assert persona_count(result["archetype_nodes"]) == 1

    empty = suite_digest("v1-fixture", [])
    filled = suite_digest("v1-fixture", result["archetype_nodes"])
    assert empty != filled


def test_digest_does_not_embed_a_clock() -> None:
    result = intake_archetypes(_ONE_PERSONA)
    blob = json.dumps(result["supply_chain_nodes"])
    assert "2026" not in blob
    assert "generated" not in blob.lower()
    for node in result["supply_chain_nodes"]:
        assert "digest" not in node
        assert "persona_count" not in node


def test_unknown_schema_version_raises() -> None:
    with pytest.raises(ArchetypeIntakeError, match="unknown"):
        intake_archetypes({SCHEMA_KEY: "9.9", "suite_version": "v1"})


def test_missing_schema_version_raises() -> None:
    with pytest.raises(ArchetypeIntakeError, match="no archetype_suite"):
        intake_archetypes({"suite_version": "v1"})


def test_example_empty_suite_authors_no_personas() -> None:
    doc = json.loads(_EMPTY.read_text())
    assert doc["archetypes"] == []


def test_mp35_surface_example_is_not_coverage_evidence() -> None:
    """The MP-35 fixture names surfaces for diff intersection, not estate coverage."""
    surfaces = json.loads((_EXAMPLES / "archetype-suite.json").read_text())
    assert all("coverage" not in a for a in surfaces["archetypes"])


def test_cli_writes_the_empty_suite(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "kg"
    result = runner.invoke(cli, [
        "intake-archetypes", "--suite", str(_EMPTY), "--output-dir", str(out),
    ])
    assert result.exit_code == 0, result.output
    assert "personas         0" in result.output
    assert "digest" in result.output
    written = list((out / "supply_chain").glob("*.json"))
    assert len(written) == 1
    node = json.loads(written[0].read_text())
    assert node["@type"] == NODE_TYPE_SUITE


def test_write_then_reread_digest_agrees(tmp_path: Path) -> None:
    result = intake_archetypes(_ONE_PERSONA)
    write_archetype_nodes(result, tmp_path)
    digest = suite_digest(
        result["suite_nodes"][0]["suite_version"], result["archetype_nodes"]
    )
    path = tmp_path / "supply_chain" / "archetype-fixture-persona.json"
    reread = json.loads(path.read_text())
    assert suite_digest("v1-fixture", [reread]) == digest
