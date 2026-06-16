"""KG export/import bundle — portable zip snapshots of a kg_dir."""
from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_BUNDLE_SCHEMA_VERSION = "1.0"
_MANIFEST_NAME = "bundle-manifest.json"
_KG_SUBDIRS = ("workloads", "environments", "placements", "deployments", "_fabric")


class KGBundleError(Exception):
    """Raised for malformed, version-mismatched, or conflicting bundle operations."""


@dataclass
class BundleManifest:
    schema_version: str
    exported_at: str
    source_kg_dir: str
    node_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "exported_at": self.exported_at,
            "source_kg_dir": self.source_kg_dir,
            "node_counts": self.node_counts,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BundleManifest":
        return cls(
            schema_version=data.get("schema_version", ""),
            exported_at=data.get("exported_at", ""),
            source_kg_dir=data.get("source_kg_dir", ""),
            node_counts=data.get("node_counts", {}),
        )


def _count_nodes(kg_dir: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for subdir in _KG_SUBDIRS:
        d = kg_dir / subdir
        if d.is_dir():
            counts[subdir] = len(list(d.rglob("*.json")) + list(d.rglob("*.jsonl")))
    return counts


def kg_export(kg_dir: Path, output_path: Path | None = None) -> Path:
    """Zip a kg_dir into a portable bundle.

    Args:
        kg_dir:      Source KG directory.
        output_path: Destination zip path. Defaults to <kg_dir>/../kg-bundle.zip.

    Returns:
        Path to the written bundle zip.
    """
    kg_dir = Path(kg_dir).resolve()
    if not kg_dir.is_dir():
        raise KGBundleError(f"kg_dir does not exist: {kg_dir}")

    if output_path is None:
        output_path = kg_dir.parent / "kg-bundle.zip"
    output_path = Path(output_path)

    manifest = BundleManifest(
        schema_version=_BUNDLE_SCHEMA_VERSION,
        exported_at=datetime.now(timezone.utc).isoformat(),
        source_kg_dir=str(kg_dir),
        node_counts=_count_nodes(kg_dir),
    )

    with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(_MANIFEST_NAME, json.dumps(manifest.to_dict(), indent=2))
        for subdir in _KG_SUBDIRS:
            d = kg_dir / subdir
            if not d.is_dir():
                continue
            for file_path in sorted(d.rglob("*")):
                if file_path.is_file():
                    arcname = file_path.relative_to(kg_dir)
                    zf.write(file_path, arcname)
        # Also capture any top-level json files (fabric-state.json etc.)
        for file_path in kg_dir.glob("*.json"):
            zf.write(file_path, file_path.relative_to(kg_dir))

    return output_path


def kg_import(
    bundle_path: Path,
    target_kg_dir: Path,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Unpack a bundle into a target KG directory.

    Args:
        bundle_path:    Path to the bundle zip produced by kg_export.
        target_kg_dir:  Destination directory. Created if absent.
        overwrite:      Allow writing into a non-empty target. Defaults to False.

    Returns:
        dict with keys ``imported`` (int), ``skipped`` (int), ``conflicts`` (list[str]).

    Raises:
        KGBundleError: If bundle is malformed, schema version mismatches, or
                       target is non-empty and overwrite=False.
    """
    bundle_path = Path(bundle_path)
    target_kg_dir = Path(target_kg_dir)

    if not bundle_path.exists():
        raise KGBundleError(f"Bundle not found: {bundle_path}")

    try:
        zf_check = zipfile.ZipFile(bundle_path, "r")
        zf_check.close()
    except zipfile.BadZipFile as exc:
        raise KGBundleError(f"Not a valid zip bundle: {bundle_path}") from exc

    with zipfile.ZipFile(bundle_path, "r") as zf:
        names = zf.namelist()

        if _MANIFEST_NAME not in names:
            raise KGBundleError(f"Bundle missing {_MANIFEST_NAME}")

        manifest = BundleManifest.from_dict(json.loads(zf.read(_MANIFEST_NAME)))

        if manifest.schema_version != _BUNDLE_SCHEMA_VERSION:
            raise KGBundleError(
                f"Bundle schema version {manifest.schema_version!r} does not match "
                f"expected {_BUNDLE_SCHEMA_VERSION!r}"
            )

        # Check for non-empty target
        if target_kg_dir.exists() and any(target_kg_dir.iterdir()):
            if not overwrite:
                raise KGBundleError(
                    f"Target directory is not empty: {target_kg_dir}. "
                    "Pass overwrite=True to allow."
                )

        target_kg_dir.mkdir(parents=True, exist_ok=True)

        imported = 0
        skipped = 0
        conflicts: list[str] = []

        for name in names:
            if name == _MANIFEST_NAME:
                continue

            dest = target_kg_dir / name
            dest.parent.mkdir(parents=True, exist_ok=True)

            if dest.exists() and not overwrite:
                existing = dest.read_bytes()
                incoming = zf.read(name)
                if existing != incoming:
                    conflicts.append(name)
                skipped += 1
                continue

            dest.write_bytes(zf.read(name))
            imported += 1

    return {"imported": imported, "skipped": skipped, "conflicts": conflicts}
