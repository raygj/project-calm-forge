"""Tier 3 admission — VSA-chain verification and digest-pin enforcement (MP-34).

ADR-013 §1–2: production pulls by digest only; the pull is admitted only when the
automated gate VSA and the app-tier countersignature both verify over the *same*
statement, and that statement's subject digest is the digest being pulled. Two
signatures, one subject. Tags are not trusted identities.

The countersignature resolves through the ADR-010 anchor chain to a named human
(``accountable_for``, identity_class=human). A countersignature that cannot
resolve, or that resolves to a non-human, is the rubber-stamp failure the ADR
names — rejected, not waved through.

Promotion is governed-expansion (ADR-013 §3). This module verifies the chain; it
does not write a new VSA. Stock DSSE verification (:func:`verify_envelope`) is
the predicate — there is no gate-specific crypto.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .intake_anchor import IDENTITY_CLASS_HUMAN, NODE_ID_PREFIX
from .passport import SigningKey
from .provenance import (
    PAYLOAD_TYPE,
    keyid_for,
    pae,
    statement_from_envelope,
    verify_envelope,
)

#: Authority class of a Tier 2 → 3 promotion (ADR-013 §3).
GOVERNED_EXPANSION = "governed-expansion"

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class AdmissionError(ValueError):
    """Raised when a pull cannot be admitted — fail closed (ADR-013 §1)."""


@dataclass(frozen=True)
class AdmissionDecision:
    """The result of one Tier 3 admission check."""

    admitted: bool
    authority_class: str
    subject_digest: str
    policy_digest: str
    anchor_ref: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "admitted": self.admitted,
            "authority_class": self.authority_class,
            "subject_digest": self.subject_digest,
            "policy_digest": self.policy_digest,
            "anchor_ref": self.anchor_ref,
            "reason": self.reason,
        }


def pull_digest(ref: str) -> str | None:
    """Return the bare sha256 hex if ``ref`` is a digest pin, else None.

    Accepted forms: ``sha256:<hex>``, ``name@sha256:<hex>``. A tag (``:latest``,
    ``:v1.2.3``) is not a pin — ADR-013 §1, and follow-up check (6).
    """
    if "@sha256:" in ref:
        digest = ref.rsplit("@sha256:", 1)[1].split(":")[0].lower()
        return digest if _HEX64.match(digest) else None
    if ref.startswith("sha256:"):
        digest = ref[7:].lower()
        return digest if _HEX64.match(digest) else None
    return None


def is_digest_pin(ref: str) -> bool:
    """True iff ``ref`` is a production-legal pull identity (digest, not tag)."""
    return pull_digest(ref) is not None


def countersign_envelope(
    envelope: dict[str, Any],
    key: SigningKey,
    *,
    anchor_ref: str,
) -> dict[str, Any]:
    """Add a second DSSE signature on the same payload (ADR-013 §2).

    The countersignature is on *this* statement, not a parallel record: two
    signatures, one subject. ``anchor_ref`` is recorded on the new signature
    entry so admission can resolve it through the anchor chain. Stock DSSE
    verifiers ignore unknown signature fields; the signature still covers the
    payload, not the annotation.
    """
    if not anchor_ref.startswith(f"{NODE_ID_PREFIX}/"):
        raise AdmissionError(
            f"countersignature needs kg://anchor/<id>, got {anchor_ref!r} "
            "(ADR-010 §1 — the pointer, never a name)"
        )
    payload = base64.b64decode(envelope["payload"])
    payload_type = envelope.get("payloadType", PAYLOAD_TYPE)
    to_sign = pae(payload_type, payload)

    if isinstance(key, Ed25519PrivateKey):
        signature = key.sign(to_sign)
    else:
        signature = key.sign(to_sign, ec.ECDSA(hashes.SHA256()))

    entry = {
        "keyid": keyid_for(key),
        "sig": base64.b64encode(signature).decode(),
        "anchor_ref": anchor_ref,
    }
    existing = list(envelope.get("signatures") or [])
    if any(s.get("keyid") == entry["keyid"] for s in existing):
        raise AdmissionError(
            "countersignature key already signed this envelope — two signatures "
            "means two parties, not the gate signing twice (ADR-013 §2)"
        )
    return {
        **envelope,
        "signatures": [*existing, entry],
    }


def _countersignature_entry(envelope: dict[str, Any]) -> dict[str, Any]:
    for entry in envelope.get("signatures") or []:
        if entry.get("anchor_ref"):
            return entry
    raise AdmissionError(
        "envelope has no countersignature — Tier 2→3 requires a second signature "
        "resolving to a human (ADR-013 §2–3)"
    )


def _resolve_human(anchor_ref: str, anchors: list[dict[str, Any]]) -> dict[str, Any]:
    """Resolve ``anchor_ref`` to an anchor whose accountable_for is a human."""
    for node in anchors:
        if node.get("@id") != anchor_ref:
            continue
        accountable = node.get("accountable_for") or {}
        if accountable.get("identity_class") != IDENTITY_CLASS_HUMAN:
            raise AdmissionError(
                f"{anchor_ref}: accountable_for is "
                f"{accountable.get('identity_class')!r}, not {IDENTITY_CLASS_HUMAN!r} "
                "— a non-human may only be associated_with (ADR-010 §6a)"
            )
        return node
    raise AdmissionError(
        f"{anchor_ref}: does not resolve to an AccountabilityAnchor — a "
        "countersignature that cannot be attributed is the rubber stamp "
        "ADR-013 names, and it is rejected"
    )


def admit(
    envelope: dict[str, Any],
    *,
    gate_public_key_b64: str,
    countersigner_public_key_b64: str,
    pull_ref: str,
    anchors: list[dict[str, Any]],
    gate_available: bool = True,
) -> AdmissionDecision:
    """Admit a digest-pinned pull if and only if the VSA chain verifies.

    Fail closed on every other path: gate down, tag pull, missing/failed
    signature, FAILED VSA, subject/pull digest mismatch, unresolvable or
    non-human countersigner.
    """
    from .gate_runner import ACTION_PROMOTION, unavailable_allows

    if not gate_available and not unavailable_allows(ACTION_PROMOTION):
        raise AdmissionError(
            "gate unavailable — promotion fails closed (ADR-013)"
        )
    digest = pull_digest(pull_ref)
    if digest is None:
        raise AdmissionError(
            f"production pull {pull_ref!r} is not a digest pin — tags are not "
            "trusted identities (ADR-013 §1)"
        )
    if gate_public_key_b64 == countersigner_public_key_b64:
        raise AdmissionError(
            "gate and countersigner keys are the same — the chain needs two parties"
        )
    if not verify_envelope(envelope, gate_public_key_b64):
        raise AdmissionError("automated VSA signature does not verify")
    if not verify_envelope(envelope, countersigner_public_key_b64):
        raise AdmissionError("countersignature does not verify")

    counter = _countersignature_entry(envelope)
    anchor_ref = str(counter["anchor_ref"])
    _resolve_human(anchor_ref, anchors)

    statement = statement_from_envelope(envelope)
    predicate = statement.get("predicate") or {}
    if predicate.get("verificationResult") != "PASSED":
        raise AdmissionError(
            f"VSA verificationResult is {predicate.get('verificationResult')!r} "
            "— a FAILED gate cannot be countersigned into production (ADR-013 §3)"
        )

    subjects = statement.get("subject") or []
    if not subjects:
        raise AdmissionError("VSA has no subject")
    subject_digest = (subjects[0].get("digest") or {}).get("sha256", "")
    if subject_digest != digest:
        raise AdmissionError(
            f"pull digest {digest} does not match VSA subject {subject_digest} "
            "— the chain attests a different artifact (ADR-013 §2)"
        )

    policy_digest = ((predicate.get("policy") or {}).get("digest") or {}).get(
        "sha256", ""
    )
    if not policy_digest:
        raise AdmissionError(
            "VSA policy has no digest — the evidence scope is unpinnable (ADR-013 §4)"
        )

    return AdmissionDecision(
        admitted=True,
        authority_class=GOVERNED_EXPANSION,
        subject_digest=subject_digest,
        policy_digest=policy_digest,
        anchor_ref=anchor_ref,
        reason="VSA chain verified; digest pin matches subject",
    )


def load_anchors(path: str | Path) -> list[dict[str, Any]]:
    """Load AccountabilityAnchor nodes from a JSON list or ``{reference_nodes: [...]}``."""
    data = json.loads(Path(path).read_text())
    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "reference_nodes" in data:
        return list(data["reference_nodes"])
    raise AdmissionError(f"{path}: expected a list of anchor nodes or reference_nodes")
