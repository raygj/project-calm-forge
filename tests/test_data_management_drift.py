"""The data_management drift pair — declared (ODCS) vs observed (OpenLineage), MP-50.

ADR-011 §7b. The plane finally holds both halves, and the comparison is the finding. The
two findings are pinned to *different authority classes* because collapsing them is the MP-11
mistake at a new altitude:

* ``DATASET_OBSERVED_NOT_CONTRACTED`` is **governed** — acting means stopping a pipeline.
* ``CONTRACT_NEVER_OBSERVED`` is **autonomic to flag** — a control nobody tests.

The join key is derived on read from what the contract declared, so these tests build real
``ContractedDataset`` nodes through :func:`intake_odcs` rather than hand-mocking the join.
"""
from __future__ import annotations

from calm_forge.cross_plane_drift import (
    AUTONOMIC,
    CONTRACT_NEVER_OBSERVED,
    DATASET_OBSERVED_NOT_CONTRACTED,
    GOVERNED,
    REMEDIATION_AUTHOR,
    REMEDIATION_ESCALATE,
    evaluate,
    evaluate_data_management,
)
from calm_forge.intake_odcs import intake_odcs
from calm_forge.intake_openlineage import NODE_TYPE_DATASET, dataset_node_id

# A contract whose one dataset resolves to a single OpenLineage id.
_CONTRACT = {
    "apiVersion": "v3.0.2",
    "kind": "DataContract",
    "id": "payments-settled-v1",
    "name": "Settled Payments",
    "servers": [{"server": "wh", "type": "postgres", "host": "warehouse.internal",
                 "port": 5432, "database": "analytics", "schema": "mart"}],
    "schema": [{"name": "settled", "physicalName": "mart.settled", "logicalType": "object"}],
}
_CONTRACTED_ID = dataset_node_id("postgres://warehouse.internal:5432", "analytics.mart.settled")


def _contracted_nodes(contract=_CONTRACT):
    return intake_odcs(contract)["contracted_dataset_nodes"]


def _observed_node(dataset_id):
    return {"@type": NODE_TYPE_DATASET, "@id": dataset_id,
            "node_class": "authored", "plane": "data_management"}


# ---------------------------------------------------------------------------
# DATASET_OBSERVED_NOT_CONTRACTED — governed
# ---------------------------------------------------------------------------

def test_observed_dataset_with_no_contract_is_governed():
    observed = {"kg://openlineage/dataset/postgres://warehouse.internal:5432/analytics.raw.events"}
    findings = evaluate_data_management(observed, _contracted_nodes())
    orphans = [f for f in findings if f.finding_type == DATASET_OBSERVED_NOT_CONTRACTED]
    assert len(orphans) == 1
    assert orphans[0].authority_class == GOVERNED
    assert orphans[0].remediation == REMEDIATION_AUTHOR
    assert orphans[0].node_id.endswith("analytics.raw.events")


def test_a_contracted_dataset_that_is_observed_is_not_a_finding():
    findings = evaluate_data_management({_CONTRACTED_ID}, _contracted_nodes())
    assert findings == []


# ---------------------------------------------------------------------------
# CONTRACT_NEVER_OBSERVED — autonomic
# ---------------------------------------------------------------------------

def test_contract_no_run_ever_exercised_is_autonomic():
    # nothing observed at all → the contract's dataset is never seen
    findings = evaluate_data_management(set(), _contracted_nodes())
    assert [f.finding_type for f in findings] == [CONTRACT_NEVER_OBSERVED]
    assert findings[0].authority_class == AUTONOMIC
    assert findings[0].remediation == REMEDIATION_ESCALATE
    assert findings[0].node_id == "kg://odcs/contract/payments-settled-v1"


def test_a_partially_observed_contract_is_being_exercised():
    """One dataset observed is enough — the contract *is* being exercised, so it is not
    CONTRACT_NEVER_OBSERVED even if another of its datasets is quiet."""
    two = {**_CONTRACT, "schema": [
        {"name": "settled", "physicalName": "mart.settled", "logicalType": "object"},
        {"name": "pending", "physicalName": "mart.pending", "logicalType": "object"},
    ]}
    findings = evaluate_data_management({_CONTRACTED_ID}, _contracted_nodes(two))
    assert not any(f.finding_type == CONTRACT_NEVER_OBSERVED for f in findings)


# ---------------------------------------------------------------------------
# The join's honest gaps
# ---------------------------------------------------------------------------

def test_an_unjoinable_contract_is_skipped_not_reported_never_observed():
    """A contract naming no server with a host derives no candidate id. 'Cannot be compared'
    must not read as 'compared and absent' — so it produces neither finding here (it is a
    gap at intake instead)."""
    no_server = {**_CONTRACT, "servers": []}
    findings = evaluate_data_management(set(), _contracted_nodes(no_server))
    assert findings == []


def test_the_two_findings_are_never_the_same_authority_class():
    """The MP-11 guard, one altitude up: if this fails because someone made
    DATASET_OBSERVED_NOT_CONTRACTED autonomic, they reasoned 'absence is always safe to
    act on' and were wrong — acting stops a pipeline."""
    seen = {_CONTRACTED_ID}  # the contract is observed
    unseen_observed = {"kg://openlineage/dataset/postgres://warehouse.internal:5432/x.y.z"}
    findings = evaluate_data_management(seen | unseen_observed, _contracted_nodes())
    by_type = {f.finding_type: f.authority_class for f in findings}
    assert by_type[DATASET_OBSERVED_NOT_CONTRACTED] == GOVERNED


# ---------------------------------------------------------------------------
# Integration through evaluate()
# ---------------------------------------------------------------------------

def test_evaluate_picks_up_both_planes_from_the_kg():
    """The composite entry point reads observed Dataset nodes and contracted-dataset nodes
    from the same graph and returns the pair alongside the other findings."""
    contracted = _contracted_nodes()
    observed = _observed_node(
        "kg://openlineage/dataset/postgres://warehouse.internal:5432/analytics.raw.events")
    doc = {
        "@id": "workload:payments", "node_class": "authored", "plane": "architecture",
        "dataset_nodes": [observed],
        "contracted_dataset_nodes": contracted,
    }
    report = evaluate([doc])
    types = {f.finding_type for f in report.findings}
    # observed raw.events has no contract (governed); the contracted 'settled' was never
    # observed (autonomic)
    assert DATASET_OBSERVED_NOT_CONTRACTED in types
    assert CONTRACT_NEVER_OBSERVED in types
    assert len(report.governed) >= 1 and len(report.autonomic) >= 1


def test_evaluate_is_quiet_when_the_declared_and_observed_sides_agree():
    contracted = _contracted_nodes()
    doc = {
        "@id": "workload:payments", "node_class": "authored", "plane": "architecture",
        "dataset_nodes": [_observed_node(_CONTRACTED_ID)],
        "contracted_dataset_nodes": contracted,
    }
    report = evaluate([doc])
    dm = [f for f in report.findings
          if f.finding_type in (DATASET_OBSERVED_NOT_CONTRACTED, CONTRACT_NEVER_OBSERVED)]
    assert dm == []
