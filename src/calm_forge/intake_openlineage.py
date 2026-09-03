"""OpenLineage run events → `data_management` plane nodes (MP-18, ADR-011 §6).

This is the first intake whose source is **observed rather than declared**. CALM, OSCAL
and TOSCA are documents somebody authored; an OpenLineage event is emitted by runtime
instrumentation as a job executes, and nobody writes one. ADR-011 §6a records what that
costs and what it does not: the plane holds both halves — OpenLineage authors the
observed side, dataset policy the declared side — and the finding is the comparison.

A run is never a node
---------------------
Lineage emits per run; a busy estate emits far more events than authored intent ever
does. The reduction is not a volume optimisation, though — it is what keeps the plane
comparable at all. A run event is a *timestamped observation* entering a graph whose
correctness property is clock-independence (ADR-007 §1), so storing runs would put a
clock inside the comparison basis.

Instead a run contributes an **edge**, keyed by the distinct ``(job, dataset,
direction)`` tuple — the ``edge_id`` discipline applied to a different tuple. Millions of
runs of one job collapse to one edge whose digest never moves, and at-least-once
redelivery is therefore idempotent, which a stream requires.

The facet admission list
------------------------
:data:`CONTENT_FACETS` is the whole list, and everything else is **dropped rather than
stored-and-excluded**. A column appearing on a dataset is a real governance event and
must move the digest; a row count changing every night must not, or every scheduled job
manufactures phantom drift forever.

Dropping matters more than it looks. A node carrying fields that must be scrubbed before
comparison is the MP-44 trap rebuilt: the workaround lives at the comparison layer, the
defect lives at the write layer, and the scrub hides it for as long as it exists. **The
node's stored content is exactly what gets digested. There is no exclusion list.**

Retraction
----------
**OpenLineage emits what ran. It never emits what stopped.** A job that ceases reading a
dataset simply goes quiet, so no reduction of the stream retracts that edge — the
information is not in it. Per ADR-011 §6c, retraction is bounded by **run count, never by
wall clock**, surfaced as a finding before it fires, and attested when it does. See
:func:`retraction_candidates` and :func:`apply_retractions`.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from .kg_plane import NODE_CLASS_AUTHORED, PLANE_DATA_MANAGEMENT
from .provenance import node_version, render

NODE_TYPE_DATASET = "Dataset"
NODE_TYPE_JOB = "Job"

DATASET_ID_PREFIX = "kg://openlineage/dataset"
JOB_ID_PREFIX = "kg://openlineage/job"

DIRECTION_READS = "reads"
DIRECTION_WRITES = "writes"

#: ``(event key, edge direction)``. A job *reads* its inputs and *writes* its outputs;
#: the direction is the edge's, not the event's.
_SIDES = (("inputs", DIRECTION_READS), ("outputs", DIRECTION_WRITES))

#: Dataset facets admitted into digested node content — ADR-011 §5's declared scope, and
#: nothing beyond it. Everything else is observability metadata and is **dropped**, not
#: stored-and-excluded. See the module docstring for why that distinction is load-bearing.
CONTENT_FACETS = ("schema", "ownership", "lifecycle")

#: Facets seen often enough to be worth naming as deliberately excluded, so a reader can
#: tell "we decided against this" from "nobody thought about it". Not exhaustive and not
#: consulted at runtime — anything outside CONTENT_FACETS is dropped regardless.
_KNOWN_OBSERVED_FACETS = (
    "outputStatistics", "dataQualityMetrics", "dataQualityAssertions",
    "columnMetrics", "storage", "symlinks",
)

#: in-toto predicate type for a retraction record (ADR-011 §6c).
RETRACTION_PREDICATE_TYPE = "https://calm-forge/attestations/lineage-retraction/v1"

#: Terminal run states. A RUNNING or START event asserts nothing about what the job read
#: — the facets are not final — so admitting them would let an aborted run author lineage.
TERMINAL_EVENT_TYPES = ("COMPLETE",)


class OpenLineageIntakeError(ValueError):
    """Raised when an event stream cannot be read as OpenLineage."""


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def dataset_node_id(namespace: str, name: str) -> str:
    """``kg://openlineage/dataset/<namespace>/<name>`` — ADR-011 §2."""
    return f"{DATASET_ID_PREFIX}/{namespace}/{name}"


def job_node_id(namespace: str, name: str) -> str:
    """``kg://openlineage/job/<namespace>/<name>`` — ADR-011 §2."""
    return f"{JOB_ID_PREFIX}/{namespace}/{name}"


def edge_key(job_id: str, direction: str, dataset_id: str) -> str:
    """The tuple identity a run contributes. Runs collapse onto this."""
    return f"{job_id}|{direction}|{dataset_id}"


# ---------------------------------------------------------------------------
# Reduction
# ---------------------------------------------------------------------------

def _named(obj: Any) -> tuple[str, str] | None:
    if not isinstance(obj, dict):
        return None
    namespace, name = obj.get("namespace"), obj.get("name")
    if not namespace or not name:
        return None
    return str(namespace), str(name)


def admitted_facets(facets: Any) -> dict[str, Any]:
    """The subset of a dataset's facets that enters digested node content.

    **Key order is sorted, not source order.** The digest is taken over the rendered
    node, and ``render`` does not canonicalize key order, so a facet dict arriving in a
    different order from a different emitter would digest differently while describing
    the same dataset. That is drift manufactured by serialisation — the same class of
    defect as MP-44, reached by a different route.
    """
    if not isinstance(facets, dict):
        return {}
    return {k: facets[k] for k in sorted(facets) if k in CONTENT_FACETS}


def reduce_events(
    events: list[dict[str, Any]],
    *,
    position: Any = None,
) -> dict[str, Any]:
    """Reduce a run-event stream to plane nodes, edges and observation state.

    Returns::

        {"job_nodes": [...], "dataset_nodes": [...], "edges": [...],
         "observations": {...}, "watermark": {...}, "gaps": [...]}

    ``observations`` is deliberately **not** part of any node or edge: it records, per
    edge, the index of the last run of that job in which the edge appeared, and it exists
    only to drive retraction. Storing it on the edge would make an edge's digest change
    every time a job ran without changing anything, which is the phantom drift the whole
    reduction exists to prevent.

    ``position`` is the transport's resumable offset — a broker offset, a file cursor.
    It is recorded verbatim and **never invented**: a stream has no document to digest,
    so provenance needs the position the transport gives it, and a fabricated one would
    claim a resumability the reader does not have (the same failure a fabricated
    ``node_version`` causes in ADR-006 §5).
    """
    if not isinstance(events, list):
        raise OpenLineageIntakeError(
            f"an event stream is a list, got {type(events).__name__}")

    jobs: dict[str, dict[str, Any]] = {}
    datasets: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}
    observations: dict[str, dict[str, Any]] = {}
    run_counts: dict[str, int] = {}
    seen_runs: dict[str, set[str]] = {}
    gaps: list[str] = []
    admitted = 0

    for index, event in enumerate(events):
        if not isinstance(event, dict):
            gaps.append(f"events[{index}]: not an object — skipped")
            continue

        event_type = event.get("eventType")
        if event_type not in TERMINAL_EVENT_TYPES:
            # Not a gap. A START event is a correct thing to emit and a wrong thing to
            # author lineage from; skipping it silently is the intended behaviour.
            continue

        job = _named(event.get("job"))
        if job is None:
            gaps.append(f"events[{index}]: job has no namespace/name — skipped")
            continue
        job_id = job_node_id(*job)
        jobs.setdefault(job_id, {
            "@type": NODE_TYPE_JOB,
            "@id": job_id,
            "node_class": NODE_CLASS_AUTHORED,
            "plane": PLANE_DATA_MANAGEMENT,
            "namespace": job[0],
            "name": job[1],
        })

        # Run counting is per job and de-duplicated by runId, so at-least-once
        # redelivery cannot inflate a job's run count and silently age out its edges.
        run_id = str((event.get("run") or {}).get("runId") or f"<anonymous-{index}>")
        runs = seen_runs.setdefault(job_id, set())
        if run_id not in runs:
            runs.add(run_id)
            run_counts[job_id] = run_counts.get(job_id, 0) + 1
        run_index = run_counts[job_id]
        admitted += 1

        for side, direction in _SIDES:
            entries = event.get(side) or []
            if not isinstance(entries, list):
                gaps.append(f"events[{index}].{side}: not a list — skipped")
                continue
            for entry in entries:
                named = _named(entry)
                if named is None:
                    gaps.append(
                        f"events[{index}].{side}: dataset has no namespace/name — skipped")
                    continue
                dataset_id = dataset_node_id(*named)
                # Latest terminal observation wins for content. An earlier run's schema
                # is not evidence about the dataset now.
                datasets[dataset_id] = {
                    "@type": NODE_TYPE_DATASET,
                    "@id": dataset_id,
                    "node_class": NODE_CLASS_AUTHORED,
                    "plane": PLANE_DATA_MANAGEMENT,
                    "namespace": named[0],
                    "name": named[1],
                    **admitted_facets(entry.get("facets")),
                }
                key = edge_key(job_id, direction, dataset_id)
                edges[key] = {"@type": direction, "from": job_id, "to": dataset_id}
                observations[key] = {"job": job_id, "last_seen_run_index": run_index}

    return {
        "job_nodes": sorted(jobs.values(), key=lambda n: n["@id"]),
        "dataset_nodes": sorted(datasets.values(), key=lambda n: n["@id"]),
        "edges": [edges[k] for k in sorted(edges)],
        "observations": observations,
        "run_counts": run_counts,
        "watermark": watermark(admitted, position, edges, datasets),
        "gaps": gaps,
    }


def watermark(
    events_read: int,
    position: Any,
    edges: dict[str, Any],
    datasets: dict[str, Any],
) -> dict[str, Any]:
    """What this graph reflects, for ``resolvedDependencies`` (ADR-011 §6b).

    A document intake digests a document. A stream has none, so provenance records the
    transport's position plus a digest of the reduced graph — enough to say *this graph
    reflects lineage through here* and to detect that two readers disagree.

    ``position`` is ``None`` when the caller had none to give. That is recorded honestly
    rather than filled in; a resumable-looking watermark that cannot resume is worse than
    an absent one.
    """
    reduced = {"edges": sorted(edges), "datasets": {k: datasets[k] for k in sorted(datasets)}}
    return {
        "events_read": events_read,
        "position": position,
        "reduced_digest": node_version(render(reduced)),
    }


# ---------------------------------------------------------------------------
# Retraction (ADR-011 §6c)
# ---------------------------------------------------------------------------

def retraction_candidates(
    observations: dict[str, dict[str, Any]],
    run_counts: dict[str, int],
    *,
    window: int,
) -> list[dict[str, Any]]:
    """Edges not observed in their job's last ``window`` runs.

    **The window is counted in runs, never in time.** A wall-clock window would put a
    clock inside the graph, so the same estate would answer differently depending on when
    it was asked — the property MP-44 was fixed to protect. A run-count window is a pure
    function of the event sequence: it bounds the graph without costing determinism, and
    retention scales with each job's own cadence, which is the right unit for that job.

    Returns candidates with their evidence, **sorted and deterministic**. Nothing is
    retracted here; this is the finding, and :func:`apply_retractions` is the act.
    """
    if window < 1:
        raise OpenLineageIntakeError(
            f"retraction window must be at least 1 run, got {window}. A window of 0 "
            f"retracts every edge the current run did not restate, which turns one "
            f"missed emission into a graph-wide contraction")

    candidates: list[dict[str, Any]] = []
    for key in sorted(observations):
        observation = observations[key]
        job_id = observation["job"]
        total = run_counts.get(job_id, 0)
        runs_since = total - observation["last_seen_run_index"]
        if runs_since >= window:
            candidates.append({
                "edge_key": key,
                "job": job_id,
                "runs_since_last_seen": runs_since,
                "job_run_count": total,
                "window": window,
            })
    return candidates


def retraction_statement(candidate: dict[str, Any]) -> dict[str, Any]:
    """An in-toto Statement recording one retraction decision.

    Reuses the attestation shape the repo already signs rather than inventing a record
    format — a retraction is a claim about a subject, which is what a Statement is.

    The record carries dataset and job GUIDs and run positions. **No PII and no wall
    clock**: the build time of the attestation belongs in the signer's own provenance
    (MP-44), and the evidence for a retraction is a run count, not a date.
    """
    job, direction, dataset = candidate["edge_key"].split("|", 2)
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": candidate["edge_key"],
                     "digest": {"sha256": node_version(candidate["edge_key"]).removeprefix("sha256:")}}],
        "predicateType": RETRACTION_PREDICATE_TYPE,
        "predicate": {
            "job": job,
            "direction": direction,
            "dataset": dataset,
            "reason": "not observed within the retraction window",
            "runs_since_last_seen": candidate["runs_since_last_seen"],
            "job_run_count": candidate["job_run_count"],
            "window": candidate["window"],
        },
    }


def apply_retractions(
    edges: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    *,
    attest: Callable[[dict[str, Any]], Any],
) -> dict[str, Any]:
    """Retract candidate edges, **only** where the attestation was written.

    ``attest`` receives the in-toto Statement and must persist it durably — signing it
    into a DSSE envelope and appending it to the retraction log. It returns the record it
    wrote, or raises.

    **Fails closed: no attestation, no retraction.** An unrecorded retraction is a
    governance mutation with no author, which is the same failure ADR-010 §6a rejects one
    plane over — it resolves, it renders, and it answers nobody. An edge whose attestation
    could not be written stays in the graph and is reported as a gap, so the estate keeps
    a true edge rather than losing a real one silently.

    Returns ``{"edges", "retracted", "records", "gaps"}`` — ``edges`` is the surviving
    set, in input order.
    """
    doomed = {c["edge_key"]: c for c in candidates}
    records: list[Any] = []
    retracted: list[str] = []
    gaps: list[str] = []

    for candidate_key in sorted(doomed):
        statement = retraction_statement(doomed[candidate_key])
        try:
            record = attest(statement)
        except Exception as exc:  # noqa: BLE001 — any failure to attest must fail closed
            gaps.append(
                f"{candidate_key}: retraction NOT applied — the attestation could not be "
                f"written ({type(exc).__name__}: {exc}). The edge stays in the graph: an "
                f"unrecorded retraction is a governance mutation with no author")
            continue
        if record is None:
            gaps.append(
                f"{candidate_key}: retraction NOT applied — the attester returned no "
                f"record, so nothing durable says this edge was removed")
            continue
        records.append(record)
        retracted.append(candidate_key)

    survivors = [
        e for e in edges
        if edge_key(e["from"], e["@type"], e["to"]) not in set(retracted)
    ]
    return {"edges": survivors, "retracted": retracted, "records": records, "gaps": gaps}


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def load_events(path: str | Path) -> list[dict[str, Any]]:
    """Read an event stream: a JSON array, or newline-delimited JSON (the usual export)."""
    text = Path(path).read_text().strip()
    if not text:
        return []
    if text.startswith("["):
        # A leading '[' means json.loads returns a list or raises; there is no third
        # outcome to guard against.
        return list(json.loads(text))
    events: list[dict[str, Any]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise OpenLineageIntakeError(f"{path}:{number}: {exc}") from exc
    return events


def intake_openlineage_from_file(
    events_path: str | Path,
    *,
    position: Any = None,
) -> dict[str, Any]:
    """Read an event stream from disk and reduce it."""
    return reduce_events(load_events(events_path), position=position)


def write_data_management_nodes(result: dict[str, Any], output_dir: Path) -> list[Path]:
    """Write job and dataset nodes to ``<output_dir>/data_management/``."""
    plane_dir = output_dir / PLANE_DATA_MANAGEMENT
    plane_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for node in [*result["job_nodes"], *result["dataset_nodes"]]:
        prefix = JOB_ID_PREFIX if node["@type"] == NODE_TYPE_JOB else DATASET_ID_PREFIX
        safe = node["@id"].removeprefix(f"{prefix}/").replace("/", "-")
        path = plane_dir / f"{node['@type'].lower()}-{safe}.json"
        path.write_text(json.dumps(node, indent=2))
        written.append(path)
    return written
