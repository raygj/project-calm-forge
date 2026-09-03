"""The OTel announcement emitter imports generated constants (MP-52, ADR-009)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from calm_forge.cli import cli
from calm_forge.passport_announce import (
    EVENT_NAME,
    announced_event,
    announcement,
    edge_digest_of,
    expiring_event,
    resource_attributes,
    superseded_event,
)
from calm_forge.semconv import (
    EVENT_FORGE_PASSPORT_ANNOUNCED,
    EVENT_FORGE_PASSPORT_EXPIRING,
    EVENT_FORGE_PASSPORT_SUPERSEDED,
    FORGE_ANCHOR_REF,
    FORGE_PASSPORT_EDGE_DIGEST,
    FORGE_PASSPORT_EXPIRES,
    FORGE_PASSPORT_ID,
    FORGE_WORKLOAD_URN,
    LOG_EVENTS,
    RESOURCE_ATTRIBUTES,
)

_V2 = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "attested-policy-passport"
    / "payments-portal-web-to-api.v0.2.passport.json"
)


def _passport() -> dict:
    return json.loads(_V2.read_text())


def test_resource_keys_are_exactly_the_generated_constants() -> None:
    attrs = resource_attributes(_passport(), anchor_ref="kg://anchor/APP-10432")
    assert set(attrs) <= RESOURCE_ATTRIBUTES
    assert set(attrs) == {
        FORGE_PASSPORT_ID,
        FORGE_PASSPORT_EDGE_DIGEST,
        FORGE_PASSPORT_EXPIRES,
        FORGE_ANCHOR_REF,
        FORGE_WORKLOAD_URN,
    }


def test_anchor_ref_is_omitted_when_unknown_never_invented() -> None:
    attrs = resource_attributes(_passport())
    assert FORGE_ANCHOR_REF not in attrs
    assert FORGE_PASSPORT_ID in attrs


def test_edge_digest_is_the_sha256_from_the_architecture_edge_id() -> None:
    digest = edge_digest_of(_passport())
    assert digest == "6cddff5734fc8c2b0a9ab2c318873f62b409e83109e7b6b54a0d1b91ea20b2aa"
    assert "kg://" not in digest


def test_values_come_from_the_passport() -> None:
    passport = _passport()
    attrs = resource_attributes(passport, anchor_ref="kg://anchor/APP-10432")
    assert attrs[FORGE_PASSPORT_ID] == passport["passport_id"]
    assert attrs[FORGE_PASSPORT_EXPIRES] == passport["lifecycle"]["expires_at"]
    assert attrs[FORGE_WORKLOAD_URN] == "wl:payments-portal/web-frontend"
    assert attrs[FORGE_ANCHOR_REF] == "kg://anchor/APP-10432"


def test_announced_event_uses_the_generated_event_name_and_plane_keys_only() -> None:
    event = announced_event(_passport())
    assert event[EVENT_NAME] == EVENT_FORGE_PASSPORT_ANNOUNCED
    assert event[EVENT_NAME] in LOG_EVENTS
    assert set(event["body"]["graph_ref_planes"]) == {
        "architecture",
        "controls",
        "business_intent",
    }


def test_expiring_and_superseded_event_names_are_registered() -> None:
    passport = _passport()
    assert expiring_event(passport)[EVENT_NAME] == EVENT_FORGE_PASSPORT_EXPIRING
    superseded = superseded_event(passport, "00000000-0000-4000-8000-000000000000")
    assert superseded[EVENT_NAME] == EVENT_FORGE_PASSPORT_SUPERSEDED
    assert superseded["body"]["superseded_passport_id"] == (
        "00000000-0000-4000-8000-000000000000"
    )
    assert superseded["body"][FORGE_PASSPORT_ID] == passport["passport_id"]


def test_no_payload_can_carry_the_unpublished_seal_name() -> None:
    payload = announcement(_passport(), anchor_ref="kg://anchor/APP-10432")
    blob = json.dumps(payload)
    assert "forge.seal.ref" not in blob
    assert FORGE_ANCHOR_REF in blob


def test_cli_announce_prints_the_payload(tmp_path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "passport",
            "announce",
            str(_V2),
            "--anchor-ref",
            "kg://anchor/APP-10432",
            "--supersedes",
            "d954d33f-2729-4fc5-81ce-16747133b16d",
        ],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert payload["resource"][FORGE_PASSPORT_ID] == "7c2d9f11-4e8a-4b63-9d20-6f3b1a8c5e92"
    assert payload["events"]["superseded"]["body"]["superseded_passport_id"] == (
        "d954d33f-2729-4fc5-81ce-16747133b16d"
    )
