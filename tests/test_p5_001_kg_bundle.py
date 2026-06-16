"""Tests for P5-001 — KG export/import bundle."""
from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from calm_forge.kg_bundle import (
    _BUNDLE_SCHEMA_VERSION,
    _MANIFEST_NAME,
    BundleManifest,
    KGBundleError,
    kg_export,
    kg_import,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_kg(tmp_path: Path) -> Path:
    """Minimal but realistic KG directory layout."""
    kg = tmp_path / "kg"
    (kg / "workloads").mkdir(parents=True)
    (kg / "placements").mkdir(parents=True)
    (kg / "deployments").mkdir(parents=True)
    (kg / "_fabric").mkdir(parents=True)

    (kg / "workloads" / "fraud-v1.json").write_text(
        json.dumps({"@type": "Workload", "workload_id": "workload:fraud-v1"})
    )
    (kg / "placements" / "fraud-placement.json").write_text(
        json.dumps({"@type": "Placement", "workload_id": "workload:fraud-v1"})
    )
    (kg / "_fabric" / "namespace-policy.json").write_text(
        json.dumps({"namespace": "default", "allowed_principals": ["*"]})
    )
    (kg / "fabric-state.json").write_text(
        json.dumps({"workloads": [], "timestamp": "2026-05-09T00:00:00Z"})
    )
    return kg


# ---------------------------------------------------------------------------
# BundleManifest
# ---------------------------------------------------------------------------

def test_manifest_round_trip():
    m = BundleManifest(
        schema_version="1.0",
        exported_at="2026-05-09T00:00:00+00:00",
        source_kg_dir="/tmp/kg",
        node_counts={"workloads": 1},
    )
    assert BundleManifest.from_dict(m.to_dict()).schema_version == "1.0"


def test_manifest_from_dict_defaults():
    m = BundleManifest.from_dict({})
    assert m.schema_version == ""
    assert m.node_counts == {}


def test_manifest_to_dict_has_all_keys():
    m = BundleManifest("1.0", "ts", "/kg", {"x": 1})
    d = m.to_dict()
    assert {"schema_version", "exported_at", "source_kg_dir", "node_counts"} == set(d)


# ---------------------------------------------------------------------------
# kg_export
# ---------------------------------------------------------------------------

def test_export_creates_zip(tmp_path):
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    assert bundle.exists()
    assert zipfile.is_zipfile(bundle)


def test_export_default_output_path(tmp_path):
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg)
    assert bundle.name == "kg-bundle.zip"
    assert bundle.parent == tmp_path


def test_export_contains_manifest(tmp_path):
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    with zipfile.ZipFile(bundle) as zf:
        assert _MANIFEST_NAME in zf.namelist()


def test_export_manifest_schema_version(tmp_path):
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    with zipfile.ZipFile(bundle) as zf:
        manifest = json.loads(zf.read(_MANIFEST_NAME))
    assert manifest["schema_version"] == _BUNDLE_SCHEMA_VERSION


def test_export_contains_workload_file(tmp_path):
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    with zipfile.ZipFile(bundle) as zf:
        names = zf.namelist()
    assert any("fraud-v1.json" in n for n in names)


def test_export_contains_fabric_state(tmp_path):
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    with zipfile.ZipFile(bundle) as zf:
        names = zf.namelist()
    assert "fabric-state.json" in names


def test_export_manifest_node_counts(tmp_path):
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    with zipfile.ZipFile(bundle) as zf:
        manifest = json.loads(zf.read(_MANIFEST_NAME))
    assert manifest["node_counts"]["workloads"] == 1


def test_export_nonexistent_kg_raises(tmp_path):
    with pytest.raises(KGBundleError, match="does not exist"):
        kg_export(tmp_path / "ghost", tmp_path / "out.zip")


def test_export_empty_kg_produces_valid_bundle(tmp_path):
    kg = tmp_path / "empty_kg"
    kg.mkdir()
    bundle = kg_export(kg, tmp_path / "out.zip")
    assert zipfile.is_zipfile(bundle)


def test_export_manifest_has_exported_at(tmp_path):
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    with zipfile.ZipFile(bundle) as zf:
        manifest = json.loads(zf.read(_MANIFEST_NAME))
    assert manifest["exported_at"]


# ---------------------------------------------------------------------------
# kg_import
# ---------------------------------------------------------------------------

def test_import_creates_target_dir(tmp_path):
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    target = tmp_path / "restored"
    kg_import(bundle, target)
    assert target.is_dir()


def test_import_returns_imported_count(tmp_path):
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    result = kg_import(bundle, tmp_path / "restored")
    assert result["imported"] > 0


def test_import_returns_no_conflicts_on_fresh_target(tmp_path):
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    result = kg_import(bundle, tmp_path / "restored")
    assert result["conflicts"] == []


def test_import_workload_file_present(tmp_path):
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    target = tmp_path / "restored"
    kg_import(bundle, target)
    assert (target / "workloads" / "fraud-v1.json").exists()


def test_import_fabric_state_present(tmp_path):
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    target = tmp_path / "restored"
    kg_import(bundle, target)
    assert (target / "fabric-state.json").exists()


def test_round_trip_byte_equality(tmp_path):
    """Export → import preserves file contents exactly."""
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    target = tmp_path / "restored"
    kg_import(bundle, target)
    original = (kg / "workloads" / "fraud-v1.json").read_bytes()
    restored = (target / "workloads" / "fraud-v1.json").read_bytes()
    assert original == restored


def test_import_non_empty_target_raises_without_overwrite(tmp_path):
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    target = tmp_path / "restored"
    kg_import(bundle, target)
    with pytest.raises(KGBundleError, match="not empty"):
        kg_import(bundle, target, overwrite=False)


def test_import_non_empty_target_succeeds_with_overwrite(tmp_path):
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    target = tmp_path / "restored"
    kg_import(bundle, target)
    result = kg_import(bundle, target, overwrite=True)
    assert result["imported"] >= 0


def test_import_missing_bundle_raises(tmp_path):
    with pytest.raises(KGBundleError, match="not found"):
        kg_import(tmp_path / "ghost.zip", tmp_path / "target")


def test_import_bad_zip_raises(tmp_path):
    bad = tmp_path / "bad.zip"
    bad.write_text("not a zip")
    with pytest.raises(KGBundleError, match="valid zip"):
        kg_import(bad, tmp_path / "target")


def test_import_missing_manifest_raises(tmp_path):
    bundle = tmp_path / "no-manifest.zip"
    with zipfile.ZipFile(bundle, "w") as zf:
        zf.writestr("workloads/foo.json", "{}")
    with pytest.raises(KGBundleError, match="missing"):
        kg_import(bundle, tmp_path / "target")


def test_import_wrong_schema_version_raises(tmp_path):
    bundle = tmp_path / "old.zip"
    manifest = {
        "schema_version": "0.9",
        "exported_at": "2026-01-01T00:00:00Z",
        "source_kg_dir": "/old",
        "node_counts": {},
    }
    with zipfile.ZipFile(bundle, "w") as zf:
        zf.writestr(_MANIFEST_NAME, json.dumps(manifest))
    with pytest.raises(KGBundleError, match="0.9"):
        kg_import(bundle, tmp_path / "target")


def test_import_skips_identical_files_on_overwrite(tmp_path):
    """Identical files do not count as conflicts even when target is non-empty."""
    kg = _make_kg(tmp_path)
    bundle = kg_export(kg, tmp_path / "out.zip")
    target = tmp_path / "restored"
    kg_import(bundle, target)
    result = kg_import(bundle, target, overwrite=True)
    assert result["conflicts"] == []
