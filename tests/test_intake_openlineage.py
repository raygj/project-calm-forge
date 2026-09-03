"""MP-18 — OpenLineage run events → the data_management plane (ADR-011 §6).

Six behaviours here look wrong to a reader who has not read ADR-011 §6, and reversing
any of them reintroduces a defect this repo has already paid for once:

1. **Runs are not nodes.** Millions of runs collapse to a handful of edges, and
   redelivering the whole stream changes nothing. A run event is a timestamped
   observation, and storing one puts a clock in the comparison basis (MP-44).
2. **Non-admitted facets are dropped, not stored-and-excluded.** A field that must be
   scrubbed before comparison is the MP-44 workaround rebuilt one layer up.
3. **Observation state lives outside nodes and edges.** On an edge it would change the
   digest every time a job ran without changing anything.
4. **The retraction window is counted in runs, never in time.**
5. **Retraction fails closed.** No attestation, no retraction — the edge survives.
6. **An absent stream position is recorded as absent**, never invented.
"""
from __future__ import annotations

import json

import pytest

from calm_forge.intake_openlineage import (
    CONTENT_FACETS,
    OpenLineageIntakeError,
    admitted_facets,
    apply_retractions,
    dataset_node_id,
    edge_key,
    intake_openlineage_from_file,
    job_node_id,
    load_events,
    reduce_events,
    retraction_candidates,
    retraction_statement,
    write_data_management_nodes,
)
from calm_forge.kg_plane import PLANE_DATA_MANAGEMENT, plane_of, validate_node
from calm_forge.kg_query import kg_query
from calm_forge.passport import generate_keypair, public_key_b64
from calm_forge.provenance import dsse_envelope, statement_from_envelope, verify_envelope

SCHEMA = [{"name": "pan", "type": "string"}]
WIDER = SCHEMA + [{"name": "dob", "type": "date"}]


def event(run="r1", job="settle", inputs=(), outputs=(), rows=1, schema=SCHEMA,
          event_type="COMPLETE"):
    def datasets(names):
        return [{"namespace": "wh", "name": n,
                 "facets": {"schema": {"fields": schema},
                            "outputStatistics": {"rowCount": rows}}} for n in names]
    return {"eventType": event_type, "eventTime": "2026-08-01T02:00:00Z",
            "run": {"runId": run}, "job": {"namespace": "etl", "name": job},
            "inputs": datasets(inputs), "outputs": datasets(outputs)}


JOB = job_node_id("etl", "settle")
TXNS = dataset_node_id("wh", "raw.txns")
SETTLED = dataset_node_id("wh", "mart.settled")


# ---------------------------------------------------------------------------
# 1 — runs are not nodes
# ---------------------------------------------------------------------------

def test_many_runs_of_one_job_collapse_to_one_edge_set():
    stream = [event(run=f"r{i}", inputs=["raw.txns"], outputs=["mart.settled"], rows=i)
              for i in range(500)]
    result = reduce_events(stream)
    assert len(result["edges"]) == 2
    assert len(result["job_nodes"]) == 1
    assert len(result["dataset_nodes"]) == 2


def test_redelivering_the_entire_stream_changes_nothing():
    # At-least-once delivery is the norm for a stream. If redelivery moved the graph,
    # the plane would drift on transport behaviour rather than on data behaviour.
    stream = [event(run="r1", inputs=["raw.txns"]), event(run="r2", inputs=["raw.txns"])]
    once = reduce_events(stream)
    twice = reduce_events(stream + stream)
    assert once["edges"] == twice["edges"]
    assert once["dataset_nodes"] == twice["dataset_nodes"]
    assert once["watermark"]["reduced_digest"] == twice["watermark"]["reduced_digest"]


def test_redelivery_does_not_inflate_a_jobs_run_count():
    # If it did, redelivery would age out edges and cause retractions on a live job.
    stream = [event(run="r1", inputs=["raw.txns"])]
    assert reduce_events(stream * 5)["run_counts"][JOB] == 1


def test_no_node_or_edge_carries_an_event_timestamp_or_run_id():
    result = reduce_events([event(run="r1", inputs=["raw.txns"], outputs=["mart.settled"])])
    blob = json.dumps([result["job_nodes"], result["dataset_nodes"], result["edges"]])
    assert "runId" not in blob and "r1" not in blob
    assert "eventTime" not in blob and "2026-08-01" not in blob


def test_nodes_are_tagged_to_the_data_management_plane_and_validate():
    result = reduce_events([event(inputs=["raw.txns"])])
    for node in [*result["job_nodes"], *result["dataset_nodes"]]:
        assert validate_node(node) == []
        assert plane_of(node) == PLANE_DATA_MANAGEMENT


def test_direction_is_the_edges_not_the_events():
    result = reduce_events([event(inputs=["raw.txns"], outputs=["mart.settled"])])
    by_target = {e["to"]: e["@type"] for e in result["edges"]}
    assert by_target[TXNS] == "reads"
    assert by_target[SETTLED] == "writes"


def test_non_terminal_events_never_author_lineage():
    # A START event's facets are not final; an aborted run must not write the graph.
    result = reduce_events([event(event_type="START", inputs=["raw.txns"])])
    assert result["edges"] == []
    assert result["gaps"] == []          # skipping it is intended, not a defect
    assert result["watermark"]["events_read"] == 0


# ---------------------------------------------------------------------------
# 2 — the facet admission list
# ---------------------------------------------------------------------------

def test_row_counts_never_move_a_dataset_digest():
    a = reduce_events([event(run="r1", inputs=["raw.txns"], rows=1)])
    b = reduce_events([event(run="r1", inputs=["raw.txns"], rows=999_999)])
    assert a["dataset_nodes"] == b["dataset_nodes"]


def test_a_new_column_does_move_the_dataset_digest():
    a = reduce_events([event(run="r1", inputs=["raw.txns"], schema=SCHEMA)])
    b = reduce_events([event(run="r1", inputs=["raw.txns"], schema=WIDER)])
    assert a["dataset_nodes"] != b["dataset_nodes"]


def test_non_admitted_facets_are_absent_from_the_node_not_merely_ignored():
    (node,) = reduce_events([event(inputs=["raw.txns"])])["dataset_nodes"]
    assert "outputStatistics" not in node
    assert set(node) == {"@type", "@id", "node_class", "plane", "namespace", "name", "schema"}


@pytest.mark.parametrize("facet", CONTENT_FACETS)
def test_every_admitted_facet_reaches_the_node(facet):
    ev = event(inputs=["raw.txns"])
    ev["inputs"][0]["facets"][facet] = {"marker": True}
    (node,) = reduce_events([ev])["dataset_nodes"]
    assert node[facet] == {"marker": True}


def test_facet_key_order_does_not_change_the_digest():
    # render() does not canonicalize key order, so source order reaching the node would
    # manufacture drift between two emitters describing the same dataset.
    keys = {"schema": {"f": 1}, "lifecycle": {"l": 2}, "ownership": {"o": 3}}
    forward = admitted_facets(keys)
    reverse = admitted_facets(dict(reversed(list(keys.items()))))
    assert list(forward) == list(reverse)


def test_malformed_facets_degrade_to_no_facets():
    assert admitted_facets("not-a-dict") == {}
    assert admitted_facets(None) == {}


def test_the_latest_terminal_observation_wins_for_content():
    # An earlier run's schema is not evidence about the dataset now.
    result = reduce_events([event(run="r1", inputs=["raw.txns"], schema=SCHEMA),
                            event(run="r2", inputs=["raw.txns"], schema=WIDER)])
    assert result["dataset_nodes"][0]["schema"]["fields"] == WIDER


# ---------------------------------------------------------------------------
# 3 — observation state lives outside the graph
# ---------------------------------------------------------------------------

def test_observation_state_is_not_on_any_edge():
    result = reduce_events([event(inputs=["raw.txns"])])
    assert set(result["edges"][0]) == {"@type", "from", "to"}


def test_an_unchanged_job_running_again_leaves_every_edge_identical():
    once = reduce_events([event(run="r1", inputs=["raw.txns"])])
    twice = reduce_events([event(run="r1", inputs=["raw.txns"]),
                           event(run="r2", inputs=["raw.txns"])])
    assert once["edges"] == twice["edges"]
    # ...but the observation moved, which is what retraction reads.
    key = edge_key(JOB, "reads", TXNS)
    assert once["observations"][key]["last_seen_run_index"] == 1
    assert twice["observations"][key]["last_seen_run_index"] == 2


# ---------------------------------------------------------------------------
# 4 — the retraction window is counted in runs
# ---------------------------------------------------------------------------

def dropped_stream():
    """raw.cards read on run 1, then never again across three more runs."""
    return [event(run="r1", inputs=["raw.txns", "raw.cards"]),
            event(run="r2", inputs=["raw.txns"]),
            event(run="r3", inputs=["raw.txns"]),
            event(run="r4", inputs=["raw.txns"])]


def test_an_edge_that_stopped_being_emitted_is_never_removed_by_the_reduction():
    # OpenLineage emits what ran; it never emits what stopped. This is the gap that
    # made retraction a decision rather than a derivation.
    result = reduce_events(dropped_stream())
    assert any("raw.cards" in e["to"] for e in result["edges"])


def test_the_window_counts_runs_of_the_owning_job():
    result = reduce_events(dropped_stream())
    args = (result["observations"], result["run_counts"])
    assert retraction_candidates(*args, window=3) != []
    assert retraction_candidates(*args, window=4) == []      # 3 runs since, not yet 4


def test_a_live_edge_is_never_a_candidate():
    result = reduce_events(dropped_stream())
    candidates = retraction_candidates(result["observations"], result["run_counts"], window=1)
    assert all("raw.txns" not in c["edge_key"] for c in candidates)


def test_candidates_carry_their_evidence():
    result = reduce_events(dropped_stream())
    (candidate,) = retraction_candidates(result["observations"], result["run_counts"], window=3)
    assert candidate["runs_since_last_seen"] == 3
    assert candidate["job_run_count"] == 4
    assert candidate["window"] == 3


def test_a_zero_window_is_refused():
    # It would retract every edge the current run did not restate, turning one missed
    # emission into a graph-wide contraction.
    with pytest.raises(OpenLineageIntakeError, match="at least 1 run"):
        retraction_candidates({}, {}, window=0)


def test_candidates_are_deterministic_in_order():
    result = reduce_events(dropped_stream() + [event(run="r5", inputs=["raw.txns"])])
    args = (result["observations"], result["run_counts"])
    assert retraction_candidates(*args, window=1) == retraction_candidates(*args, window=1)


def test_two_jobs_age_independently():
    stream = [event(run="a1", job="fast", inputs=["raw.txns", "raw.cards"]),
              *[event(run=f"a{i}", job="fast", inputs=["raw.txns"]) for i in range(2, 8)],
              event(run="b1", job="slow", inputs=["raw.cards"])]
    result = reduce_events(stream)
    candidates = retraction_candidates(result["observations"], result["run_counts"], window=3)
    keys = {c["edge_key"] for c in candidates}
    assert any("fast" in k and "raw.cards" in k for k in keys)   # aged out
    assert not any("slow" in k for k in keys)                    # one run, still fresh


# ---------------------------------------------------------------------------
# 5 — retraction fails closed
# ---------------------------------------------------------------------------

def test_a_successful_attestation_retracts_the_edge():
    result = reduce_events(dropped_stream())
    candidates = retraction_candidates(result["observations"], result["run_counts"], window=3)
    applied = apply_retractions(result["edges"], candidates, attest=lambda s: {"stored": s})
    assert applied["retracted"] == [candidates[0]["edge_key"]]
    assert not any("raw.cards" in e["to"] for e in applied["edges"])
    assert applied["gaps"] == []


def test_a_raising_attester_leaves_the_edge_in_the_graph():
    result = reduce_events(dropped_stream())
    candidates = retraction_candidates(result["observations"], result["run_counts"], window=3)

    def broken(_statement):
        raise OSError("log server unreachable")

    applied = apply_retractions(result["edges"], candidates, attest=broken)
    assert applied["retracted"] == []
    assert any("raw.cards" in e["to"] for e in applied["edges"])
    assert "retraction NOT applied" in applied["gaps"][0]
    assert "no author" in applied["gaps"][0]


def test_an_attester_returning_nothing_also_fails_closed():
    # A silent no-op writer is the more dangerous failure: it looks like success.
    result = reduce_events(dropped_stream())
    candidates = retraction_candidates(result["observations"], result["run_counts"], window=3)
    applied = apply_retractions(result["edges"], candidates, attest=lambda _s: None)
    assert applied["retracted"] == []
    assert "no record" in applied["gaps"][0]


def test_one_failed_attestation_does_not_block_the_others():
    result = reduce_events([event(run="r1", inputs=["raw.txns", "raw.cards"], outputs=["mart.settled"]),
                            event(run="r2", inputs=[])])
    candidates = retraction_candidates(result["observations"], result["run_counts"], window=1)
    assert len(candidates) == 3

    def flaky(statement):
        if "raw.cards" in statement["predicate"]["dataset"]:
            raise RuntimeError("nope")
        return {"stored": True}

    applied = apply_retractions(result["edges"], candidates, attest=flaky)
    assert len(applied["retracted"]) == 2
    assert len(applied["gaps"]) == 1


def test_no_candidates_is_a_clean_no_op():
    result = reduce_events([event(inputs=["raw.txns"])])
    applied = apply_retractions(result["edges"], [], attest=lambda _s: {"x": 1})
    assert applied == {"edges": result["edges"], "retracted": [], "records": [], "gaps": []}


def test_the_retraction_record_is_a_signable_in_toto_statement():
    result = reduce_events(dropped_stream())
    (candidate,) = retraction_candidates(result["observations"], result["run_counts"], window=3)
    statement = retraction_statement(candidate)
    assert statement["predicateType"].endswith("/lineage-retraction/v1")
    assert statement["predicate"]["runs_since_last_seen"] == 3

    key = generate_keypair()
    envelope = dsse_envelope(statement, key)
    assert verify_envelope(envelope, public_key_b64(key))
    assert statement_from_envelope(envelope) == statement


def test_the_retraction_record_carries_no_wall_clock():
    # The evidence for a retraction is a run count. A date here would make the record
    # differ on every re-derivation, and MP-44 is the ticket that cost.
    result = reduce_events(dropped_stream())
    (candidate,) = retraction_candidates(result["observations"], result["run_counts"], window=3)
    blob = json.dumps(retraction_statement(candidate))
    assert "2026" not in blob and "eventTime" not in blob


# ---------------------------------------------------------------------------
# 6 — the watermark is honest
# ---------------------------------------------------------------------------

def test_a_supplied_position_is_recorded_verbatim():
    mark = reduce_events([event(inputs=["raw.txns"])], position="kafka:0:991")["watermark"]
    assert mark["position"] == "kafka:0:991"
    assert mark["events_read"] == 1


def test_an_absent_position_is_recorded_as_absent_not_invented():
    mark = reduce_events([event(inputs=["raw.txns"])])["watermark"]
    assert mark["position"] is None
    assert mark["reduced_digest"].startswith("sha256:")


def test_the_reduced_digest_tracks_content_not_event_count():
    same = reduce_events([event(run="r1", inputs=["raw.txns"]),
                          event(run="r2", inputs=["raw.txns"])])["watermark"]
    one = reduce_events([event(run="r1", inputs=["raw.txns"])])["watermark"]
    assert same["reduced_digest"] == one["reduced_digest"]
    assert same["events_read"] != one["events_read"]


# ---------------------------------------------------------------------------
# Malformed input
# ---------------------------------------------------------------------------

def test_a_non_list_stream_is_refused():
    with pytest.raises(OpenLineageIntakeError, match="an event stream is a list"):
        reduce_events({"eventType": "COMPLETE"})  # type: ignore[arg-type]


def test_a_non_object_event_is_reported_not_raised():
    result = reduce_events(["nope", event(inputs=["raw.txns"])])
    assert "not an object" in result["gaps"][0]
    assert len(result["edges"]) == 1


def test_an_event_with_no_job_identity_is_skipped_with_a_gap():
    bad = event(inputs=["raw.txns"])
    bad["job"] = {"namespace": "etl"}
    result = reduce_events([bad])
    assert "job has no namespace/name" in result["gaps"][0]
    assert result["edges"] == []


def test_a_dataset_with_no_identity_is_skipped_with_a_gap():
    bad = event(inputs=["raw.txns"])
    bad["inputs"][0].pop("name")
    result = reduce_events([bad])
    assert "dataset has no namespace/name" in result["gaps"][0]


def test_a_non_list_side_is_reported():
    bad = event(inputs=["raw.txns"])
    bad["outputs"] = {"namespace": "wh"}
    result = reduce_events([bad])
    assert "not a list" in result["gaps"][0]
    assert len(result["edges"]) == 1


def test_an_event_with_no_run_id_still_counts_as_a_run():
    bad = event(inputs=["raw.txns"])
    bad.pop("run")
    result = reduce_events([bad])
    assert result["run_counts"][JOB] == 1


def test_missing_sides_are_treated_as_empty():
    result = reduce_events([{"eventType": "COMPLETE", "job": {"namespace": "etl", "name": "settle"}}])
    assert result["edges"] == []
    assert result["job_nodes"][0]["@id"] == JOB


# ---------------------------------------------------------------------------
# File I/O and the query surface
# ---------------------------------------------------------------------------

def test_newline_delimited_json_is_read(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("\n".join(json.dumps(event(run=f"r{i}", inputs=["raw.txns"]))
                              for i in range(3)) + "\n")
    assert len(load_events(path)) == 3


def test_a_json_array_is_read(tmp_path):
    path = tmp_path / "events.json"
    path.write_text(json.dumps([event(inputs=["raw.txns"])]))
    assert len(load_events(path)) == 1


def test_an_empty_file_is_an_empty_stream(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("   \n")
    assert load_events(path) == []


def test_blank_lines_between_events_are_skipped(tmp_path):
    path = tmp_path / "events.jsonl"
    one = json.dumps(event(run="r1", inputs=["raw.txns"]))
    two = json.dumps(event(run="r2", inputs=["raw.txns"]))
    path.write_text(f"{one}\n\n   \n{two}\n")
    assert len(load_events(path)) == 2


def test_a_malformed_line_names_its_line_number(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps(event()) + "\n{not json\n")
    with pytest.raises(OpenLineageIntakeError, match=":2:"):
        load_events(path)


def test_a_truncated_array_raises_the_decode_error(tmp_path):
    path = tmp_path / "events.json"
    path.write_text("[")
    with pytest.raises(json.JSONDecodeError):
        load_events(path)


def test_a_non_object_job_or_dataset_is_skipped_with_a_gap():
    # A bare string where an object belongs is a real emitter bug, not a shape we guess at.
    bad = event(inputs=["raw.txns"])
    bad["job"] = "etl.settle"
    assert "job has no namespace/name" in reduce_events([bad])["gaps"][0]

    worse = event(inputs=["raw.txns"])
    worse["inputs"] = ["wh.raw.txns"]
    assert "dataset has no namespace/name" in reduce_events([worse])["gaps"][0]


def test_intake_from_file_carries_the_position(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(json.dumps(event(inputs=["raw.txns"])) + "\n")
    result = intake_openlineage_from_file(path, position="offset:7")
    assert result["watermark"]["position"] == "offset:7"


def test_written_nodes_are_queryable_by_type(tmp_path):
    result = reduce_events([event(inputs=["raw.txns"], outputs=["mart.settled"])])
    paths = write_data_management_nodes(result, tmp_path)
    assert len(paths) == 3
    assert [h["node"]["@id"] for h in kg_query(tmp_path, "job", [])] == [JOB]
    assert len(kg_query(tmp_path, "dataset", [])) == 2


def test_written_nodes_answer_a_plane_filtered_query(tmp_path):
    write_data_management_nodes(reduce_events([event(inputs=["raw.txns"])]), tmp_path)
    assert len(kg_query(tmp_path, "dataset", [], plane=PLANE_DATA_MANAGEMENT)) == 1
    assert kg_query(tmp_path, "dataset", [], plane="controls") == []


def test_the_shipped_example_stream_reduces_as_documented():
    result = intake_openlineage_from_file("examples/openlineage/nightly-settle.events.jsonl")
    assert result["watermark"]["events_read"] == 4      # the START event is not one
    assert len(result["edges"]) == 3
    (candidate,) = retraction_candidates(
        result["observations"], result["run_counts"], window=1)
    assert "raw.cards" in candidate["edge_key"]
