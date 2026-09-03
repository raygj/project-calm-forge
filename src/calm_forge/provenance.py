"""SLSA v1.0 build provenance for generated artifacts (ADR-007, MP-01).

Every artifact Forge generates carries provenance recording *what was built, from
which sources, at which content versions, by which builder, when*. The record is a
SLSA v1.0 predicate inside an in-toto Statement — not a bespoke internal format —
because the compile-provenance the cross-plane drift findings need (ADR-005) and the
build-provenance a customer's supply chain requires are the same record.

The load-bearing field is ``resolvedDependencies``: each source read at compile time,
with its **content digest as read**. Cross-plane drift compares a node's current
digest against the digest-as-read, so the comparison is by content and never by
clock — immune to skew, to backdated authoring, and to touched-but-unchanged sources
firing false recompile findings. ``startedOn`` / ``finishedOn`` are for human
legibility and audit narrative; no finding may be specified in terms of them.

Crawl-stage note: today's compile inputs are the CALM instantiation, decorator, and
catalog documents, so those are the resolved dependencies and their URIs are file
URIs. When plane intake lands (MP-08/MP-16), controls- and business_intent-plane
nodes join the same list with ``kg://`` GUIDs. The shape does not change.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import __version__
from .passport import SigningKey, public_key_b64

IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"

BUILD_TYPE = "https://calm-forge/buildtypes/generate-stack/v1"
BUILDER_ID = f"https://calm-forge/builders/generate-stack@{__version__}"

#: Unsigned in-toto Statement written alongside a generated artifact set.
PROVENANCE_FILENAME = "provenance.slsa.json"

#: Signed DSSE envelope, written only when a signing key is supplied (MP-07).
PROVENANCE_ENVELOPE_FILENAME = "provenance.slsa.dsse.json"


class ProvenanceError(RuntimeError):
    """Raised when a provenance record would be emitted without dependency digests.

    Empty ``resolvedDependencies`` is a build failure, not a warning (ADR-007 Risks):
    provenance that records no sources reopens the timestamp-comparison hole the whole
    design exists to close, and a soft check here degrades to no check.
    """


def sha256_hex(content: str | bytes) -> str:
    """Content digest as bare lowercase hex — the in-toto ``digest`` map form."""
    data = content.encode() if isinstance(content, str) else content
    return hashlib.sha256(data).hexdigest()


def node_version(content: str | bytes) -> str:
    """Content digest in the ``sha256:<hex>`` form passports use (ADR-006 §5).

    Same bytes, different spelling: in-toto wants a bare hex value under a ``sha256``
    key, while ``graph_refs[*].node_version`` carries the algorithm inline.
    """
    return f"sha256:{sha256_hex(content)}"


def resolved_dependency(uri: str, content: str | bytes) -> dict[str, Any]:
    """One entry of ``resolvedDependencies`` — a source and its digest as read."""
    return {"uri": uri, "digest": {"sha256": sha256_hex(content)}}


def dependency_from_path(path: str | Path) -> dict[str, Any]:
    """Resolved dependency for a file input, digested from its bytes on disk."""
    p = Path(path)
    return resolved_dependency(p.resolve().as_uri(), p.read_bytes())


def subject(name: str, content: str | bytes) -> dict[str, Any]:
    """One entry of ``subject`` — a generated artifact and its digest."""
    return {"name": name, "digest": {"sha256": sha256_hex(content)}}


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_provenance(
    subjects: list[dict[str, Any]],
    resolved_dependencies: list[dict[str, Any]],
    *,
    external_parameters: dict[str, Any],
    internal_parameters: dict[str, Any] | None = None,
    started_on: datetime | None = None,
    finished_on: datetime | None = None,
    build_type: str = BUILD_TYPE,
    builder_id: str = BUILDER_ID,
) -> dict[str, Any]:
    """Assemble an in-toto Statement carrying a SLSA v1.0 provenance predicate.

    ``resolved_dependencies`` must be non-empty — see :class:`ProvenanceError`.

    ``internal_parameters`` is omitted when empty rather than emitted hollow. It is
    where the graph root / KG state reference lands once plane intake exists; until
    then there is no internal build parameter to record, and inventing one would make
    the record look more grounded than it is.
    """
    if not resolved_dependencies:
        raise ProvenanceError(
            "refusing to emit provenance with no resolvedDependencies — a record that "
            "names no sources cannot support a cross-plane drift comparison (ADR-007)"
        )
    missing = [d for d in resolved_dependencies if not d.get("digest", {}).get("sha256")]
    if missing:
        raise ProvenanceError(
            f"resolvedDependencies entries missing a sha256 digest: "
            f"{[d.get('uri') for d in missing]}"
        )

    now = started_on or datetime.now(timezone.utc)
    build_definition: dict[str, Any] = {
        "buildType": build_type,
        "externalParameters": external_parameters,
        "resolvedDependencies": resolved_dependencies,
    }
    if internal_parameters:
        build_definition["internalParameters"] = internal_parameters

    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": subjects,
        "predicateType": SLSA_PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": build_definition,
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {
                    "startedOn": _timestamp(now),
                    "finishedOn": _timestamp(finished_on or now),
                },
            },
        },
    }


def provenance_for_generated_files(
    files: dict[str, str],
    sources: dict[str, str | Path],
    *,
    external_parameters: dict[str, Any],
    started_on: datetime | None = None,
    finished_on: datetime | None = None,
) -> dict[str, Any]:
    """Provenance for one ``generate`` invocation.

    Every emitted artifact is a subject; every input document is a resolved
    dependency. One statement per build invocation, many subjects — the standard SLSA
    shape — so an admission controller verifies the whole artifact set from one record.
    """
    subjects = [subject(name, content) for name, content in sorted(files.items())]
    deps = [dependency_from_path(path) for _, path in sorted(sources.items())]
    return build_provenance(
        subjects,
        deps,
        external_parameters=external_parameters,
        started_on=started_on,
        finished_on=finished_on,
    )


def render(statement: dict[str, Any]) -> str:
    """Serialize a statement for writing — stable key order, trailing newline."""
    return json.dumps(statement, indent=2) + "\n"


# ---------------------------------------------------------------------------
# DSSE envelope (ADR-007 §2, MP-07)
#
# The passport signs a JCS-canonicalized body with `proof` excluded; provenance
# signs a DSSE Pre-Authentication Encoding of the serialized statement. Two
# disciplines on purpose: the passport answers *why may this edge exist*, the
# provenance answers *how was this artifact produced*. They are sibling claims about
# different questions — never merged, never cross-signed, never substitutable.
# ---------------------------------------------------------------------------

#: DSSE payloadType for an in-toto Statement.
PAYLOAD_TYPE = "application/vnd.in-toto+json"


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding.

    ``DSSEv1 <len(type)> <type> <len(payload)> <payload)>`` — length-prefixed so no
    choice of payload can be reinterpreted as a different type. The signature covers
    this, never the base64 transport form.
    """
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def keyid_for(key: SigningKey) -> str:
    """Conventional keyid: sha256 over the raw public key bytes.

    A hint for selecting a key from a trust bundle, not the key itself. The envelope
    deliberately does **not** carry the public key: verification must reach a trust
    source, which keeps the trust question visible instead of letting a self-describing
    envelope answer it. Crawl-stage callers resolve it from the same stubbed single-key
    source as passports; trust-bundle governance is walk/run.
    """
    return sha256_hex(base64.b64decode(public_key_b64(key)))


def dsse_envelope(statement: dict[str, Any], key: SigningKey) -> dict[str, Any]:
    """Wrap and sign an in-toto Statement in a DSSE envelope."""
    payload = render(statement).encode()
    to_sign = pae(PAYLOAD_TYPE, payload)

    if isinstance(key, Ed25519PrivateKey):
        signature = key.sign(to_sign)
    else:
        signature = key.sign(to_sign, ec.ECDSA(hashes.SHA256()))

    return {
        "payload": base64.b64encode(payload).decode(),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [
            {"keyid": keyid_for(key), "sig": base64.b64encode(signature).decode()}
        ],
    }


def statement_from_envelope(envelope: dict[str, Any]) -> dict[str, Any]:
    """Decode the payload without verifying it.

    Named to be awkward at the call site: reading a statement is not the same as
    trusting one, and a consumer that decodes without verifying should have to say so.
    """
    return json.loads(base64.b64decode(envelope["payload"]))


def verify_envelope(envelope: dict[str, Any], public_key_b64_value: str) -> bool:
    """Verify a DSSE envelope against a caller-supplied public key.

    Returns False on any signature failure rather than raising, matching
    ``verify_passport``. A malformed envelope is a failure, not an exception —
    verification is a predicate, and callers branch on it.
    """
    try:
        payload = base64.b64decode(envelope["payload"])
        to_verify = pae(envelope.get("payloadType", PAYLOAD_TYPE), payload)
        raw = base64.b64decode(public_key_b64_value)
        signatures = envelope["signatures"]
    except (KeyError, TypeError, ValueError, binascii.Error):
        return False

    for entry in signatures:
        try:
            sig = base64.b64decode(entry["sig"])
        except (KeyError, TypeError, ValueError, binascii.Error):
            continue
        for verifier in (_verify_ed25519, _verify_ecdsa_p256):
            if verifier(raw, sig, to_verify):
                return True
    return False


def _verify_ed25519(raw_public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(raw_public_key).verify(signature, message)
        return True
    except Exception:
        return False


def _verify_ecdsa_p256(raw_public_key: bytes, signature: bytes, message: bytes) -> bool:
    """EC public keys ride as SPKI DER, matching ``passport.public_key_b64``.

    An EC key has no single canonical raw form, so the two signing disciplines share
    one encoding rather than each inventing its own — otherwise the same SPIRE SVID
    would serialize differently depending on which claim it signed.
    """
    try:
        key = serialization.load_der_public_key(raw_public_key)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            return False
        key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
