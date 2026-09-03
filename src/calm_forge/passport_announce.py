"""Passport announcement over OpenTelemetry (ADR-009, MP-52).

The standing announcement is a set of resource attributes; lifecycle is three
log events. Attribute *names* come from :mod:`calm_forge.semconv` — the Weaver-
generated constants — so an unregistered ``forge.*`` name cannot be emitted.

This is a join accelerator and a drift signal, never proof. Authorization is
still resolve-and-verify against the graph (ADR-009 §5).
"""

from __future__ import annotations

from typing import Any

from .passport import PASSPORT_VERSION, edge_id_of
from .semconv import (
    EVENT_FORGE_PASSPORT_ANNOUNCED,
    EVENT_FORGE_PASSPORT_EXPIRING,
    EVENT_FORGE_PASSPORT_SUPERSEDED,
    FORGE_ANCHOR_REF,
    FORGE_PASSPORT_EDGE_DIGEST,
    FORGE_PASSPORT_EXPIRES,
    FORGE_PASSPORT_ID,
    FORGE_WORKLOAD_URN,
)

EVENT_NAME = "event.name"


def edge_digest_of(passport: dict[str, Any]) -> str:
    """The L4-tuple SHA-256 taken from the passport's architecture edge id.

    ``edge_id`` is ``kg://edges/v1/<digest>``; the attribute carries the digest
    only, so a Collector can join without parsing the scheme (ADR-009 §1).
    """
    return edge_id_of(passport).rsplit("/", 1)[-1]


def graph_ref_planes(passport: dict[str, Any]) -> list[str]:
    """Plane keys present on the passport, by name only — never their contents.

    v0.1 has a single architecture ``graph_ref``; v0.2 spells the set in
    ``graph_refs``. The announced event carries this list so intake can see
    which planes were attested without reading the nodes (ADR-009 §2).
    """
    if passport.get("passport_version") == PASSPORT_VERSION:
        return ["architecture"]
    return sorted(passport.get("graph_refs", {}).keys())


def resource_attributes(
    passport: dict[str, Any],
    *,
    anchor_ref: str | None = None,
) -> dict[str, str | int]:
    """The standing announcement for a passport (ADR-009 §1).

    ``anchor_ref`` is optional because a passport does not yet carry the
    accountability pointer — inventing ``kg://anchor/<id>`` would be a
    fabricated identity. Omit rather than guess.
    """
    attrs: dict[str, str | int] = {
        FORGE_PASSPORT_ID: passport["passport_id"],
        FORGE_PASSPORT_EDGE_DIGEST: edge_digest_of(passport),
        FORGE_PASSPORT_EXPIRES: int(passport["lifecycle"]["expires_at"]),
        FORGE_WORKLOAD_URN: passport["network_binding"]["source_workload_urn"],
    }
    if anchor_ref:
        attrs[FORGE_ANCHOR_REF] = anchor_ref
    return attrs


def announced_event(
    passport: dict[str, Any],
    *,
    anchor_ref: str | None = None,
) -> dict[str, Any]:
    """``forge.passport.announced`` — start and rotation (ADR-009 §2)."""
    return {
        EVENT_NAME: EVENT_FORGE_PASSPORT_ANNOUNCED,
        "body": {
            **resource_attributes(passport, anchor_ref=anchor_ref),
            "graph_ref_planes": graph_ref_planes(passport),
        },
    }


def expiring_event(
    passport: dict[str, Any],
    *,
    anchor_ref: str | None = None,
) -> dict[str, Any]:
    """``forge.passport.expiring`` — inside the pre-expiry window (ADR-009 §2)."""
    attrs = resource_attributes(passport, anchor_ref=anchor_ref)
    return {
        EVENT_NAME: EVENT_FORGE_PASSPORT_EXPIRING,
        "body": {
            FORGE_PASSPORT_ID: attrs[FORGE_PASSPORT_ID],
            FORGE_PASSPORT_EXPIRES: attrs[FORGE_PASSPORT_EXPIRES],
            FORGE_WORKLOAD_URN: attrs[FORGE_WORKLOAD_URN],
        },
    }


def superseded_event(
    passport: dict[str, Any],
    superseded_passport_id: str,
    *,
    anchor_ref: str | None = None,
) -> dict[str, Any]:
    """``forge.passport.superseded`` — re-issue (ADR-009 §2).

    ``forge.passport.id`` is the NEW passport. The previous id is an event-local
    body field, not a resource attribute — v0.1 holds at five ``forge.*``
    attributes rather than minting a sixth for a value that never stands alone.
    """
    attrs = resource_attributes(passport, anchor_ref=anchor_ref)
    return {
        EVENT_NAME: EVENT_FORGE_PASSPORT_SUPERSEDED,
        "body": {
            FORGE_PASSPORT_ID: attrs[FORGE_PASSPORT_ID],
            FORGE_WORKLOAD_URN: attrs[FORGE_WORKLOAD_URN],
            "superseded_passport_id": superseded_passport_id,
        },
    }


def announcement(
    passport: dict[str, Any],
    *,
    anchor_ref: str | None = None,
    superseded_passport_id: str | None = None,
) -> dict[str, Any]:
    """Full announcement payload: resource attributes plus the lifecycle events."""
    events: dict[str, Any] = {
        "announced": announced_event(passport, anchor_ref=anchor_ref),
        "expiring": expiring_event(passport, anchor_ref=anchor_ref),
    }
    if superseded_passport_id:
        events["superseded"] = superseded_event(
            passport, superseded_passport_id, anchor_ref=anchor_ref
        )
    return {
        "resource": resource_attributes(passport, anchor_ref=anchor_ref),
        "events": events,
    }
