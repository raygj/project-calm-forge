"""Sentinel ⇔ tfpolicy parity — the same CALM intent enforces the same predicates.

The ADR's core claim: Sentinel and tfpolicy are independent projections of one intent,
and they enforce the *same predicate* at the same gate. This test proves it across every
example that carries a CALM instantiation. Divergence is a bug in one emitter.

The two emitters use different concrete syntax, so parity is asserted at the predicate
level: each predicate key has a Sentinel marker and a tfpolicy marker, and for a given
metadata the set present in each emission must equal `predicates_for(metadata)`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from calm_forge.sentinel_writer import write_sentinel_policies
from calm_forge.tfpolicy_writer import (
    PREDICATE_COST_GOVERNANCE,
    PREDICATE_DATA_CLASSIFICATION_TAG,
    PREDICATE_ENCRYPTION_AT_REST,
    PREDICATE_NO_PUBLIC_ENDPOINTS,
    predicates_for,
    write_tfpolicy_policies,
)

EXAMPLES_DIR = Path(__file__).parent.parent / "examples"

# Same predicate, two syntaxes → two markers. A rule name unique to each emission.
_SENTINEL_MARKER = {
    PREDICATE_ENCRYPTION_AT_REST: 'rule "enforce_encryption_at_rest"',
    PREDICATE_NO_PUBLIC_ENDPOINTS: 'rule "deny_public_endpoints"',
    PREDICATE_COST_GOVERNANCE: 'rule "cost_advisory"',
    PREDICATE_DATA_CLASSIFICATION_TAG: 'rule "require_data_classification_tag"',
}
_TFPOLICY_MARKER = {
    PREDICATE_ENCRYPTION_AT_REST: 'policy "enforce_encryption_at_rest"',
    PREDICATE_NO_PUBLIC_ENDPOINTS: 'policy "deny_public_endpoints"',
    PREDICATE_COST_GOVERNANCE: 'policy "cost_advisory"',
    PREDICATE_DATA_CLASSIFICATION_TAG: 'policy "require_data_classification_tag"',
}

ALL_CALM_EXAMPLES = [
    "fsi-3tier",
    "fsi-event-driven",
    "fsi-microservices-mesh",
    "fsi-mongodb-multiregion",
    "fraud-detection-workload-portability",
    "pci-multiregion",
]


def _metadata(example: str) -> dict:
    inst = json.loads((EXAMPLES_DIR / example / "instantiation.json").read_text())
    return inst.get("metadata", {})


def _present(markers: dict[str, str], emission: str) -> set[str]:
    return {pred for pred, marker in markers.items() if marker in emission}


@pytest.mark.parametrize("example", ALL_CALM_EXAMPLES)
def test_sentinel_and_tfpolicy_enforce_the_same_predicates(example):
    md = _metadata(example)
    expected = set(predicates_for(md))

    sentinel = write_sentinel_policies(md, {}, [])
    tfpolicy = write_tfpolicy_policies(md, {}, [])

    sentinel_predicates = _present(_SENTINEL_MARKER, sentinel)
    tfpolicy_predicates = _present(_TFPOLICY_MARKER, tfpolicy)

    # both emissions reflect exactly the intent's predicate set — no more, no less
    assert sentinel_predicates == expected, (
        f"{example}: sentinel enforces {sentinel_predicates}, intent declares {expected}"
    )
    assert tfpolicy_predicates == expected, (
        f"{example}: tfpolicy enforces {tfpolicy_predicates}, intent declares {expected}"
    )
    # ...therefore they agree with each other
    assert sentinel_predicates == tfpolicy_predicates


@pytest.mark.parametrize("example", ALL_CALM_EXAMPLES)
def test_enforcement_severity_parity(example):
    """A predicate that hard-blocks in Sentinel must not be advisory in tfpolicy.

    Compliance predicates are mandatory in both; the framework-specific spelling differs
    (Sentinel `hard-mandatory`, tfpolicy `mandatory`) but the severity must not soften.
    """
    md = _metadata(example)
    if PREDICATE_ENCRYPTION_AT_REST not in predicates_for(md):
        pytest.skip("no compliance predicate for this example")

    sentinel = write_sentinel_policies(md, {}, [])
    tfpolicy = write_tfpolicy_policies(md, {}, [])

    assert 'enforce_encryption_at_rest' in sentinel and 'hard-mandatory' in sentinel
    # the tfpolicy encryption block carries mandatory (its highest level), not advisory
    enc_block = tfpolicy.split('policy "enforce_encryption_at_rest"', 1)[1].split("policy ", 1)[0]
    assert 'enforcement_level = "mandatory"' in enc_block
    assert "advisory" not in enc_block
