"""The `requirements` plane — generative intent (MP-54, ADR-015).

Every other plane compiles a DSL some sovereign community already authors. This one does
not, and ADR-015 §6 says why: the authoring community — product and application teams
writing specs for generation — is converging on a practice with no ratified language.
**This is the one plane where Forge mints rather than adopts**, and the commitments that
keep that honest are versioning, embedded Gherkin, a standing migration trigger, and a
scope guard.

What it holds, and what it refuses
----------------------------------
`Actor` (who holds the intent), `Requirement` (the story, with executable acceptance) and
`TargetState` (non-functional intent as assertions). **Not** workflow: no sprint, no
assignee, no comments, no story points. ADR-015 §6's scope guard is normative and
:data:`WORKFLOW_FIELDS` enforces it — Forge is not a requirements-management tool, and the
day process state becomes plane content is the day this plane starts drifting on someone
else's cadence.

`realized_by` is derived, never stored
--------------------------------------
ADR-015 §1 sketched `realized_by` as a stored field "populated by generation." Stored, it
enters the node's content digest, so:

* generating an artifact **mutates the requirement it was generated from**, and
* ``REQUIREMENTS_NEWER_THAN_CODE`` compares against a value that moves every time code is
  generated — the finding inverted.

The data is already in the graph as inbound ``realizes`` edges, so :func:`realized_by`
computes it. Same discipline as :func:`~.intake_oscal.parameter_variables`,
:func:`~.intake_tosca.property_variables` and
:func:`~.intake_odcs.observed_dataset_ids`. **If generation writes it, it is derived.**

Accountability is referenced, never asserted
--------------------------------------------
An actor's ``anchor_ref`` produces an ``associated_with`` edge and nothing else — including
for ``kind: agent``. Autonomy lives in the execution; accountability never leaves the human
(ADR-010 §6a). Reading it the other way — an agent actor points at an anchor, therefore the
agent is accountable — terminates the chain in a robot, which resolves, renders in a report,
and answers nobody.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

from .kg_plane import NODE_CLASS_AUTHORED, PLANE_REQUIREMENTS, PREDICATE_REALIZES

# ``PLANE_REQUIREMENTS`` is registered in :data:`~.kg_plane.PLANES` by ADR-015 under the
# ADR-005 §7 rule — the sixth committed plane, and the only one whose DSL Forge mints.

NODE_TYPE_ACTOR = "Actor"
NODE_TYPE_REQUIREMENT = "Requirement"
NODE_TYPE_TARGET_STATE = "TargetState"

ACTOR_ID_PREFIX = "kg://requirements/actor"
REQUIREMENT_ID_PREFIX = "kg://requirements/requirement"
TARGET_STATE_ID_PREFIX = "kg://requirements/target-state"

#: ADR-010's informational binding, and the only identity edge this intake ever emits.
PREDICATE_ASSOCIATED_WITH = "associated_with"

SCHEMA_VERSION = "0.1"
SCHEMA_KEY = "requirements_schema"

ACTOR_KIND_HUMAN = "human"
NON_HUMAN_ACTOR_KINDS = ("system", "agent")
ACTOR_KINDS = (ACTOR_KIND_HUMAN, *NON_HUMAN_ACTOR_KINDS)

STATUS_DRAFT = "draft"
STATUS_RATIFIED = "ratified"
STATUS_SUPERSEDED = "superseded"
STATUSES = (STATUS_DRAFT, STATUS_RATIFIED, STATUS_SUPERSEDED)

PRIORITIES = ("must", "should", "could")

#: ADR-015 §6's scope guard, made checkable. Matched case-insensitively against key
#: substrings. A requirements plane that accepts these becomes a requirements-management
#: tool with a graph attached, and then it drifts on Jira's cadence rather than intent's.
WORKFLOW_FIELDS = (
    "sprint", "assignee", "assigned", "comment", "story_point", "storypoint",
    "epic", "board", "column", "due_date", "duedate", "estimate", "reporter",
    "watcher", "workflow",
)

#: Assertion values that name a platform rather than a property. Not exhaustive and not a
#: blocklist of vendors — a heuristic guard on the one rule that makes TargetState durable:
#: assertions name what the system must hold, never what provides it.
_PLATFORM_SHAPED_KEYS = ("runtime", "vendor", "product", "service_name", "sku", "instance_type")


class RequirementsIntakeError(ValueError):
    """Raised when a document cannot be read as a requirements-plane document."""


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def actor_node_id(actor_id: str) -> str:
    """``kg://requirements/actor/<id>`` from an authored ``actor:<name>``."""
    return f"{ACTOR_ID_PREFIX}/{_slug(_strip_prefix(actor_id, 'actor'))}"


def requirement_node_id(requirement_id: str) -> str:
    """``kg://requirements/requirement/<id>`` from an authored ``req:<path>``."""
    return f"{REQUIREMENT_ID_PREFIX}/{_slug(_strip_prefix(requirement_id, 'req'))}"


def target_state_node_id(target_state_id: str) -> str:
    """``kg://requirements/target-state/<id>`` from an authored ``ts:<path>``."""
    return f"{TARGET_STATE_ID_PREFIX}/{_slug(_strip_prefix(target_state_id, 'ts'))}"


def _strip_prefix(value: str, prefix: str) -> str:
    return str(value)[len(prefix) + 1:] if str(value).startswith(f"{prefix}:") else str(value)


def _slug(value: Any) -> str:
    return re.sub(r"[^A-Za-z0-9._/-]+", "-", str(value)).strip("-/") or "unknown"


# ---------------------------------------------------------------------------
# The derived field (computed on read, never stored)
# ---------------------------------------------------------------------------

def realized_by(node: dict[str, Any], edges: list[dict[str, Any]]) -> list[str]:
    """What this node's intent produced — the inbound ``realizes`` set.

    ADR-015 §1 sketched this as a stored field "populated by generation". It is computed
    instead, because a stored value enters the node's content digest and generation would
    then mutate the intent it was generated from. See the module docstring.
    """
    node_id = node.get("@id")
    if not node_id:
        return []
    return sorted({
        str(edge["to"]) for edge in edges
        if edge.get("@type") == PREDICATE_REALIZES and edge.get("from") == node_id
        and edge.get("to")
    })


def acceptance_skeletons(node: dict[str, Any]) -> list[str]:
    """Runnable test-skeleton names projected from a requirement's Gherkin acceptance.

    Also computed on read. The projection is what makes "ratified requirements are
    executable" a checkable claim rather than a slogan — a block that cannot project is a
    block that was never executable.
    """
    skeletons: list[str] = []
    for index, block in enumerate(node.get("acceptance") or []):
        if not isinstance(block, dict):
            continue
        stem = _slug(block.get("then", "")).lower().replace("/", "-").replace(".", "-")
        skeletons.append(f"test_{index:02d}_{stem}"[:120])
    return skeletons


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _reject_workflow_fields(obj: dict[str, Any], where: str) -> list[str]:
    gaps = []
    for key in obj:
        lowered = str(key).lower()
        if any(fragment in lowered for fragment in WORKFLOW_FIELDS):
            gaps.append(
                f"{where}: {key!r} is workflow state, not generative intent (ADR-015 §6). "
                f"Forge is not a requirements-management tool; process state never becomes "
                f"plane content, or this plane drifts on someone else's cadence")
    return gaps


def _require_version(document: Any) -> dict[str, Any]:
    """Dispatch on ``requirements_schema``. An unknown version **raises**."""
    if not isinstance(document, dict):
        raise RequirementsIntakeError(
            f"a requirements document is a mapping, got {type(document).__name__}")
    version = document.get(SCHEMA_KEY)
    if version is None:
        raise RequirementsIntakeError(
            f"no {SCHEMA_KEY} — the version is the reader-dispatch key and has no default. "
            f"This plane mints its own schema (ADR-015 §6), so the version is the only "
            f"thing that says how to read the document")
    if str(version) != SCHEMA_VERSION:
        raise RequirementsIntakeError(
            f"unknown {SCHEMA_KEY} {version!r} — this reader knows {SCHEMA_VERSION!r} only. "
            f"Falling back to the newest known reader would silently misread a valid "
            f"document, and the failure would surface as nonsense findings rather than as a "
            f"parse error (MP-02)")
    return document


# ---------------------------------------------------------------------------
# Intake
# ---------------------------------------------------------------------------

def intake_requirements(document: Any) -> dict[str, list[Any]]:
    """Compile a requirements document into plane nodes and edges.

    Returns ``{"actor_nodes", "requirement_nodes", "target_state_nodes", "edges", "gaps"}``.

    A malformed entry yields a gap and no node. A ``ratified`` requirement whose acceptance
    does not project into test skeletons is a gap too — ADR-015 §6 names prose-in-Gherkin-
    clothing as the risk, and the projection is what detects it.
    """
    doc = _require_version(document)

    actor_nodes: list[dict[str, Any]] = []
    requirement_nodes: list[dict[str, Any]] = []
    target_state_nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    gaps: list[str] = []
    known_actors: set[str] = set()

    for index, raw in enumerate(doc.get("actors") or []):
        node, actor_gaps = _actor(raw, index)
        gaps.extend(actor_gaps)
        if node is None:
            continue
        actor_nodes.append(node)
        known_actors.add(node["actor_id"])
        if node.get("anchor_ref"):
            # `associated_with`, never `accountable_for` — including for agents.
            edges.append({"@type": PREDICATE_ASSOCIATED_WITH,
                          "from": node["@id"], "to": node["anchor_ref"]})

    for index, raw in enumerate(doc.get("requirements") or []):
        node, req_gaps = _requirement(raw, index)
        gaps.extend(req_gaps)
        if node is None:
            continue
        requirement_nodes.append(node)
        edges.extend({"@type": PREDICATE_REALIZES, "from": node["@id"], "to": target}
                     for target in node.get("realizes", []))

    for index, raw in enumerate(doc.get("target_states") or []):
        node, ts_gaps = _target_state(raw, index)
        gaps.extend(ts_gaps)
        if node is None:
            continue
        target_state_nodes.append(node)
        edges.extend({"@type": PREDICATE_REALIZES, "from": node["@id"], "to": target}
                     for target in node.get("realizes", []))

    for node in requirement_nodes:
        if node["actor_id"] not in known_actors:
            gaps.append(
                f"{node['@id']}: names actor {node['actor_id']!r}, which this document does "
                f"not declare — the intent has no holder, so there is nobody the requirement "
                f"is for")

    return {
        "actor_nodes": actor_nodes,
        "requirement_nodes": requirement_nodes,
        "target_state_nodes": target_state_nodes,
        "edges": edges,
        "gaps": gaps,
    }


def _plane_tag(node: dict[str, Any]) -> None:
    node["node_class"] = NODE_CLASS_AUTHORED
    node["plane"] = PLANE_REQUIREMENTS


def _actor(raw: Any, index: int) -> tuple[dict[str, Any] | None, list[str]]:
    where = f"actors[{index}]"
    if not isinstance(raw, dict):
        return None, [f"{where}: not a mapping — skipped"]
    gaps = _reject_workflow_fields(raw, where)
    actor_id, name, kind = raw.get("id"), raw.get("name"), raw.get("kind")
    if not actor_id:
        return None, [*gaps, f"{where}: no id"]
    where = f"actor {actor_id!r}"
    if not name:
        gaps.append(f"{where}: no name")
    if kind not in ACTOR_KINDS:
        return None, [*gaps, f"{where}: kind {kind!r} is not one of {list(ACTOR_KINDS)}"]

    anchor_ref = raw.get("anchor_ref")
    if anchor_ref and not str(anchor_ref).startswith("kg://anchor/"):
        return None, [*gaps, f"{where}: anchor_ref {anchor_ref!r} is not a kg://anchor/ "
                             f"reference — 'seal' and 'license' are display aliases and "
                             f"never appear in a GUID (ADR-010 §1)"]
    if kind in NON_HUMAN_ACTOR_KINDS and not anchor_ref:
        return None, [*gaps, f"{where}: a {kind} actor has no anchor_ref — an internal "
                             f"non-human actor must resolve to an accountability anchor. "
                             f"Autonomy lives in the execution; accountability never leaves "
                             f"the human (ADR-010)"]
    if gaps:
        return None, gaps

    node: dict[str, Any] = {"@type": NODE_TYPE_ACTOR, "@id": actor_node_id(str(actor_id))}
    _plane_tag(node)
    node.update({"actor_id": str(actor_id), "name": str(name), "kind": str(kind)})
    if anchor_ref:
        node["anchor_ref"] = str(anchor_ref)
    if raw.get("description"):
        node["description"] = str(raw["description"])
    return node, []


def _requirement(raw: Any, index: int) -> tuple[dict[str, Any] | None, list[str]]:
    where = f"requirements[{index}]"
    if not isinstance(raw, dict):
        return None, [f"{where}: not a mapping — skipped"]
    gaps = _reject_workflow_fields(raw, where)
    req_id, actor_id, story = raw.get("id"), raw.get("actor"), raw.get("story")
    if not req_id:
        return None, [*gaps, f"{where}: no id"]
    where = f"requirement {req_id!r}"
    if not actor_id:
        gaps.append(f"{where}: no actor — a requirement nobody holds is not intent")
    if not story:
        gaps.append(f"{where}: no story")

    status = raw.get("status", STATUS_DRAFT)
    if status not in STATUSES:
        gaps.append(f"{where}: status {status!r} is not one of {list(STATUSES)}")
    priority = raw.get("priority")
    if priority is not None and priority not in PRIORITIES:
        gaps.append(f"{where}: priority {priority!r} is not one of {list(PRIORITIES)}")

    acceptance, acceptance_gaps = _acceptance(raw.get("acceptance"), where)
    gaps.extend(acceptance_gaps)
    if gaps:
        return None, gaps

    node: dict[str, Any] = {"@type": NODE_TYPE_REQUIREMENT,
                            "@id": requirement_node_id(str(req_id))}
    _plane_tag(node)
    node.update({"requirement_id": str(req_id), "actor_id": str(actor_id),
                 "actor": actor_node_id(str(actor_id)), "story": str(story),
                 "status": status, "acceptance": acceptance})
    if priority:
        node["priority"] = priority
    node["realizes"] = sorted({str(t) for t in raw.get("realizes") or []})

    if status == STATUS_RATIFIED and not acceptance_skeletons(node):
        # ADR-015 §6 names prose-in-Gherkin-clothing as the risk. The projection is the
        # detector: a block that cannot project into a test name was never executable.
        return None, [f"{where}: ratified with no acceptance that projects into a test "
                      f"skeleton — a ratified requirement without executable acceptance is "
                      f"prose, and executability is the whole claim"]
    return node, []


def _acceptance(raw: Any, where: str) -> tuple[list[dict[str, str]], list[str]]:
    if raw is None:
        return [], []
    if not isinstance(raw, list):
        return [], [f"{where}: acceptance must be a list of given/when/then blocks"]
    blocks: list[dict[str, str]] = []
    gaps: list[str] = []
    for position, block in enumerate(raw):
        if not isinstance(block, dict):
            gaps.append(f"{where}: acceptance[{position}] is not a mapping")
            continue
        missing = [k for k in ("given", "when", "then") if not block.get(k)]
        if missing:
            gaps.append(f"{where}: acceptance[{position}] is missing {missing} — Gherkin is "
                        f"embedded verbatim, and an incomplete block does not project into a "
                        f"runnable test")
            continue
        blocks.append({k: str(block[k]) for k in ("given", "when", "then")})
    return blocks, gaps


def _target_state(raw: Any, index: int) -> tuple[dict[str, Any] | None, list[str]]:
    where = f"target_states[{index}]"
    if not isinstance(raw, dict):
        return None, [f"{where}: not a mapping — skipped"]
    gaps = _reject_workflow_fields(raw, where)
    ts_id = raw.get("id")
    if not ts_id:
        return None, [*gaps, f"{where}: no id"]
    where = f"target state {ts_id!r}"

    if "realized_by" in raw:
        # The defect ADR-015's reviewer annotation B1 records. Refused rather than ignored,
        # because a document carrying it was authored against the wrong model and silently
        # dropping the field would let that model persist.
        gaps.append(f"{where}: 'realized_by' is derived on read from inbound realizes edges, "
                    f"never authored or stored. Stored, it enters the node's content digest, "
                    f"so generating an artifact would mutate the intent it was generated from")

    assertions = raw.get("assertions")
    if not isinstance(assertions, dict) or not assertions:
        gaps.append(f"{where}: no assertions — a target state with nothing to assert "
                    f"constrains nothing")
        assertions = {}
    for key in assertions:
        if str(key).lower() in _PLATFORM_SHAPED_KEYS:
            gaps.append(
                f"{where}: assertion {key!r} names a platform, not a property. Assertions say "
                f"what the instantiated system must hold — `compute_type: isolated_ephemeral`, "
                f"never `runtime: lambda` — so the graph does not change when a deployment "
                f"technology does")
    if gaps:
        return None, gaps

    node: dict[str, Any] = {"@type": NODE_TYPE_TARGET_STATE,
                            "@id": target_state_node_id(str(ts_id))}
    _plane_tag(node)
    node.update({"target_state_id": str(ts_id),
                 "assertions": {k: assertions[k] for k in sorted(assertions)}})
    if raw.get("description"):
        node["description"] = str(raw["description"])
    node["realizes"] = sorted({str(t) for t in raw.get("realizes") or []})
    return node, []


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def load_requirements(path: str | Path) -> Any:
    """Read a requirements document. YAML is the authoring form; JSON is a subset."""
    try:
        return yaml.safe_load(Path(path).read_text())
    except yaml.YAMLError as exc:
        raise RequirementsIntakeError(f"{path}: {exc}") from exc


def intake_requirements_from_file(path: str | Path) -> dict[str, list[Any]]:
    """Read a requirements document from disk and compile it."""
    return intake_requirements(load_requirements(path))


def write_requirements_nodes(result: dict[str, list[Any]], output_dir: Path) -> list[Path]:
    """Write plane nodes as JSON-LD to ``<output_dir>/requirements/``."""
    plane_dir = output_dir / PLANE_REQUIREMENTS
    plane_dir.mkdir(parents=True, exist_ok=True)
    prefixes = {NODE_TYPE_ACTOR: ACTOR_ID_PREFIX,
                NODE_TYPE_REQUIREMENT: REQUIREMENT_ID_PREFIX,
                NODE_TYPE_TARGET_STATE: TARGET_STATE_ID_PREFIX}
    written: list[Path] = []
    for node in [*result["actor_nodes"], *result["requirement_nodes"],
                 *result["target_state_nodes"]]:
        safe = node["@id"].removeprefix(f"{prefixes[node['@type']]}/").replace("/", "-")
        path = plane_dir / f"{node['@type'].lower()}-{safe}.json"
        path.write_text(json.dumps(node, indent=2))
        written.append(path)
    return written
