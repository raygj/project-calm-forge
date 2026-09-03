"""ODCS data contracts → the declared side of `data_management` (MP-49, ADR-011 §7).

:mod:`.intake_openlineage` reads what *happened*. This reads what was *promised*. Together
they are the plane's drift pair (ADR-011 §7b): an ODCS contract declares a dataset's schema,
quality rules, classification, SLAs and ownership; OpenLineage observes data actually moving;
and the comparison between them is the finding.

ODCS — the Open Data Contract Standard (Bitol, Linux Foundation AI & Data) — is authored by
data producers and stewards, a third constituency that is neither the app team nor cyber.
Forge compiles it; it does not edit it, and it does not ask anyone to learn another language.

The join is derived, never stored
---------------------------------
A contract declares *physical* identity — a server, a database, a schema, a table. OpenLineage
names the same table its own way. :func:`observed_dataset_ids` computes the correspondence
**on read** from what the contract declared, following the same pattern as
:func:`~.intake_oscal.parameter_variables` and :func:`~.intake_tosca.property_variables`.

Computed rather than stored on purpose. A derived field in the node would enter its content
digest, so refining the join rule later would re-digest every contract in the estate and
present it as drift — a change in *our* code reading as a change in *their* intent. Deriving
it keeps the node exactly what the producer wrote.

Ownership is read, but accountability is not asserted
-----------------------------------------------------
ODCS ``team`` entries are emitted as ``associated_with`` edges only. A data contract naming a
"data owner" is **not** the accountability anchor — the application registry is (ADR-010 §1),
and it is the single system of record for ``accountable_for``. Minting accountability from a
contract would give the estate two sources of truth for who answers, which is indistinguishable
from having none the first time they disagree.

Scope
-----
**Contracts and their schema objects.** Support channels, pricing, and the free-text
description fields are read only where they govern; the rest is dropped rather than
stored-and-excluded, on the same reasoning as the OpenLineage facet admission list.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from .intake_openlineage import dataset_node_id
from .kg_plane import NODE_CLASS_AUTHORED, PLANE_DATA_MANAGEMENT

NODE_TYPE_CONTRACT = "DataContract"
NODE_TYPE_CONTRACTED_DATASET = "ContractedDataset"

#: GUID schemes. These extend the shape ADR-011 §2 already establishes for this plane
#: (``kg://<dsl>/<kind>/<identity>``) rather than opening a new plane, so they follow the
#: plane-scheme-open pattern of ADR-006 §4 and need no wire-format bump.
CONTRACT_ID_PREFIX = "kg://odcs/contract"
CONTRACTED_DATASET_ID_PREFIX = "kg://odcs/dataset"

#: Predicates. ``declares`` is within-plane and directional; ``associated_with`` is
#: ADR-010's informational binding, reused deliberately — see the module docstring.
PREDICATE_DECLARES = "declares"
PREDICATE_ASSOCIATED_WITH = "associated_with"

IDENTITY_ID_PREFIX = "kg://identity"

SUPPORTED_KIND = "DataContract"

#: Only the v3 line is read. v2 renamed enough of the schema block that reading it as v3
#: yields a contract with no datasets — indistinguishable from a contract that declares
#: none, which is the partial-support-reading-as-complete failure ADR-005 §4 rejects.
SUPPORTED_API_VERSION_PREFIX = "v3"

#: Property-level fields admitted into node content: the ones that govern. A quality rule,
#: a classification and a required flag are all projectable into a data PDP; a display
#: hint is not.
PROPERTY_FIELDS = (
    "logicalType", "physicalType", "required", "unique", "partitioned",
    "classification", "quality", "description", "authoritativeDefinitions",
)

#: OpenLineage's dataset naming spec gives most warehouse servers ``<scheme>://<host>:<port>``
#: as the namespace. Where a server type's scheme differs from its ODCS name, it is listed.
_NAMESPACE_SCHEMES = {
    "postgres": "postgres", "postgresql": "postgres", "mysql": "mysql",
    "snowflake": "snowflake", "bigquery": "bigquery", "redshift": "redshift",
    "databricks": "databricks", "kafka": "kafka", "s3": "s3", "azure": "abfss",
}


class OdcsIntakeError(ValueError):
    """Raised when a document cannot be read as an ODCS data contract."""


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def contract_node_id(contract_id: str) -> str:
    """``kg://odcs/contract/<id>``."""
    return f"{CONTRACT_ID_PREFIX}/{_slug(contract_id)}"


def contracted_dataset_node_id(contract_id: str, object_name: str) -> str:
    """``kg://odcs/dataset/<contract>/<schema object>``."""
    return f"{CONTRACTED_DATASET_ID_PREFIX}/{_slug(contract_id)}/{_slug(object_name)}"


def _slug(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", str(value)).strip("-") or "unknown"


# ---------------------------------------------------------------------------
# The derived join (computed on read, never stored)
# ---------------------------------------------------------------------------

def observed_dataset_ids(node: dict[str, Any]) -> list[str]:
    """Candidate OpenLineage dataset GUIDs for a contracted dataset.

    Follows the OpenLineage dataset naming spec: namespace ``<scheme>://<host>[:<port>]``,
    name ``<database>.<schema>.<table>`` with absent segments omitted. One id per server the
    contract lists, because a contract may promise the same table on several.

    Returns ``[]`` when the contract declared no server, and **that emptiness is the honest
    answer** — there is nothing to derive from. It surfaces as an unjoinable contract rather
    than as a guess, because a fabricated correspondence would make an uncontracted dataset
    look contracted, which is the finding inverted.
    """
    physical = node.get("physical_name") or node.get("name")
    if not physical:
        return []

    ids: list[str] = []
    for server in node.get("servers") or []:
        if not isinstance(server, dict):
            continue
        host = server.get("host")
        if not host:
            continue
        scheme = _NAMESPACE_SCHEMES.get(str(server.get("type", "")).lower(),
                                        str(server.get("type") or "unknown").lower())
        port = server.get("port")
        namespace = f"{scheme}://{host}:{port}" if port else f"{scheme}://{host}"
        ids.append(dataset_node_id(namespace, _qualify(server, physical)))
    return sorted(set(ids))


def _qualify(server: dict[str, Any], physical: Any) -> str:
    """Qualify a physical name with the server's database/schema, without repeating either.

    ODCS ``physicalName`` is sometimes bare (``settled``) and sometimes already carries its
    schema (``mart.settled``); both are legitimate. Naively prefixing produces
    ``analytics.mart.mart.settled``, which joins to nothing and looks like a real dataset.

    The rule is not a guess: **segments the declared name already carries are not added
    again.** The longest suffix of ``[database, schema]`` matching the head of the physical
    name is dropped, so ``settled`` and ``mart.settled`` on the same server resolve to the
    same id — which is exactly right, since they name the same table.
    """
    parts = str(physical).split(".")
    prefix = [str(s) for s in (server.get("database"), server.get("schema")) if s]
    for length in range(min(len(prefix), len(parts)), 0, -1):
        if prefix[-length:] == parts[:length]:
            prefix = prefix[:-length]
            break
    return ".".join([*prefix, *parts])


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def _require_contract(document: Any) -> dict[str, Any]:
    """Refuse anything that is not a v3 ODCS DataContract, **by name**."""
    if not isinstance(document, dict):
        raise OdcsIntakeError(
            f"an ODCS contract is a mapping, got {type(document).__name__}")

    kind = document.get("kind")
    if kind is not None and str(kind) != SUPPORTED_KIND:
        raise OdcsIntakeError(
            f"unsupported ODCS kind {kind!r} — this adapter reads {SUPPORTED_KIND!r} only. "
            f"Parsing it to an empty result would be indistinguishable from a contract that "
            f"declares nothing")

    api_version = document.get("apiVersion")
    if api_version is not None and not str(api_version).startswith(SUPPORTED_API_VERSION_PREFIX):
        raise OdcsIntakeError(
            f"unsupported ODCS apiVersion {api_version!r} — this adapter reads "
            f"{SUPPORTED_API_VERSION_PREFIX}.x only. The v2 line renames enough of the schema "
            f"block that reading it as v3 yields a contract with no datasets, which reads as "
            f"a contract that declares none")
    return document


def _team(document: dict[str, Any]) -> tuple[list[dict[str, Any]], list[str]]:
    """Team entries as opaque identity references, with PII refused rather than scrubbed."""
    members: list[dict[str, Any]] = []
    gaps: list[str] = []
    for position, entry in enumerate(document.get("team") or []):
        if not isinstance(entry, dict):
            gaps.append(f"team[{position}]: not a mapping — skipped")
            continue
        username = entry.get("username")
        if not username:
            gaps.append(f"team[{position}]: no username — skipped, since an unnamed member "
                        f"cannot be resolved to anyone")
            continue
        member: dict[str, Any] = {"username": str(username)}
        if entry.get("role"):
            member["role"] = str(entry["role"])
        for key, value in entry.items():
            if isinstance(value, str) and "@" in value and "." in value.rsplit("@", 1)[-1]:
                gaps.append(
                    f"team[{position}].{key}: refusing an email-shaped value — a contract "
                    f"node carries an opaque identifier, and resolution to a person happens "
                    f"graph-side through an access-controlled traversal (ADR-010 §2)")
                member = {}
                break
        if member:
            members.append(member)
    return members, gaps


def _servers(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Server descriptors, narrowed to the fields the join derives from."""
    out: list[dict[str, Any]] = []
    for server in document.get("servers") or []:
        if not isinstance(server, dict):
            continue
        narrowed = {k: server[k] for k in ("server", "type", "host", "port", "database",
                                           "schema", "location")
                    if server.get(k) is not None}
        if narrowed:
            out.append(narrowed)
    return out


def _properties(obj: dict[str, Any]) -> list[dict[str, Any]]:
    """Column definitions, narrowed to :data:`PROPERTY_FIELDS` and sorted by name.

    Sorted because the digest is taken over the rendered node and ``render`` does not
    canonicalize; two exports of the same contract listing columns in different orders must
    not read as drift. Same defect class as MP-44, reached through serialisation.
    """
    out: list[dict[str, Any]] = []
    for prop in obj.get("properties") or []:
        if not isinstance(prop, dict) or not prop.get("name"):
            continue
        narrowed: dict[str, Any] = {"name": str(prop["name"])}
        narrowed.update({k: prop[k] for k in PROPERTY_FIELDS if prop.get(k) is not None})
        out.append(narrowed)
    return sorted(out, key=lambda p: p["name"])


def _sla(document: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for entry in document.get("slaProperties") or []:
        if isinstance(entry, dict) and entry.get("property"):
            out.append({k: entry[k] for k in ("property", "value", "unit", "element", "driver")
                        if entry.get(k) is not None})
    return out


def intake_odcs(document: Any) -> dict[str, list[Any]]:
    """Compile one ODCS contract into declared-side `data_management` nodes.

    Returns ``{"contract_nodes", "contracted_dataset_nodes", "edges", "gaps"}``.

    A contract with no ``schema`` objects yields a contract node and a gap: it declares
    ownership and SLAs over nothing, so nothing can be compared against the observed side.
    That is reported, never inferred away.
    """
    contract = _require_contract(document)

    contract_id = contract.get("id") or contract.get("name")
    if not contract_id:
        raise OdcsIntakeError("an ODCS contract needs an id (or at least a name) — without "
                              "one there is no stable GUID to reference it by")

    gaps: list[str] = []
    members, team_gaps = _team(contract)
    gaps.extend(team_gaps)
    servers = _servers(contract)

    node_id = contract_node_id(contract_id)
    raw_description = contract.get("description")
    description: dict[str, Any] = raw_description if isinstance(raw_description, dict) else {}

    contract_node: dict[str, Any] = {
        "@type": NODE_TYPE_CONTRACT,
        "@id": node_id,
        "node_class": NODE_CLASS_AUTHORED,
        "plane": PLANE_DATA_MANAGEMENT,
        "contract_id": str(contract_id),
        "servers": servers,
        "team": members,
    }
    for source_key, target_key in (("name", "name"), ("version", "version"),
                                   ("status", "status"), ("domain", "domain"),
                                   ("dataProduct", "data_product"), ("tenant", "tenant")):
        if contract.get(source_key) is not None:
            contract_node[target_key] = contract[source_key]
    for key in ("purpose", "limitations", "usage"):
        if description.get(key):
            contract_node[key] = description[key]
    if contract.get("tags"):
        contract_node["tags"] = sorted(str(t) for t in contract["tags"])
    sla = _sla(contract)
    if sla:
        contract_node["sla"] = sla

    dataset_nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = [
        {"@type": PREDICATE_ASSOCIATED_WITH,
         "from": f"{IDENTITY_ID_PREFIX}/human/{_slug(m['username'])}",
         "to": node_id}
        for m in members
    ]

    schema_objects = contract.get("schema") or []
    if not isinstance(schema_objects, list) or not schema_objects:
        gaps.append(f"{node_id}: declares no schema objects — the contract governs ownership "
                    f"and SLAs over nothing, so there is nothing to compare against observed "
                    f"lineage")
        schema_objects = []

    for position, obj in enumerate(schema_objects):
        if not isinstance(obj, dict) or not obj.get("name"):
            gaps.append(f"{node_id}: schema[{position}] has no name — skipped")
            continue
        dataset_id = contracted_dataset_node_id(contract_id, obj["name"])
        dataset_node: dict[str, Any] = {
            "@type": NODE_TYPE_CONTRACTED_DATASET,
            "@id": dataset_id,
            "node_class": NODE_CLASS_AUTHORED,
            "plane": PLANE_DATA_MANAGEMENT,
            "contract": node_id,
            "name": str(obj["name"]),
            "physical_name": str(obj.get("physicalName") or obj["name"]),
            # Carried so the join can be derived on read. The servers are the contract's,
            # copied here so a dataset node is resolvable without its parent.
            "servers": servers,
            "properties": _properties(obj),
        }
        for source_key, target_key in (("logicalType", "logical_type"),
                                       ("physicalType", "physical_type"),
                                       ("description", "description"),
                                       ("dataGranularityDescription", "granularity")):
            if obj.get(source_key) is not None:
                dataset_node[target_key] = obj[source_key]
        if obj.get("quality"):
            dataset_node["quality"] = obj["quality"]

        if not observed_dataset_ids(dataset_node):
            gaps.append(
                f"{dataset_id}: no observed-side correspondence can be derived — the contract "
                f"declares no server with a host, so this dataset cannot be joined to lineage "
                f"and DATASET_OBSERVED_NOT_CONTRACTED cannot be evaluated for it")

        dataset_nodes.append(dataset_node)
        edges.append({"@type": PREDICATE_DECLARES, "from": node_id, "to": dataset_id})

    return {
        "contract_nodes": [contract_node],
        "contracted_dataset_nodes": dataset_nodes,
        "edges": edges,
        "gaps": gaps,
    }


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def load_contract(path: str | Path) -> Any:
    """Read one ODCS contract. YAML is the standard's form; JSON is a subset of it."""
    try:
        return yaml.safe_load(Path(path).read_text())
    except yaml.YAMLError as exc:
        raise OdcsIntakeError(f"{path}: {exc}") from exc


def intake_odcs_from_file(contract_path: str | Path) -> dict[str, list[Any]]:
    """Read an ODCS contract from disk and compile it."""
    return intake_odcs(load_contract(contract_path))


def write_contract_nodes(result: dict[str, list[Any]], output_dir: Path) -> list[Path]:
    """Write contract and contracted-dataset nodes to ``<output_dir>/data_management/``."""
    plane_dir = output_dir / PLANE_DATA_MANAGEMENT
    plane_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for node in [*result["contract_nodes"], *result["contracted_dataset_nodes"]]:
        prefix = (CONTRACT_ID_PREFIX if node["@type"] == NODE_TYPE_CONTRACT
                  else CONTRACTED_DATASET_ID_PREFIX)
        safe = node["@id"].removeprefix(f"{prefix}/").replace("/", "-")
        path = plane_dir / f"{node['@type'].lower()}-{safe}.json"
        path.write_text(json.dumps(node, indent=2))
        written.append(path)
    return written
