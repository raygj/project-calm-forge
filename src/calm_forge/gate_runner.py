"""The Gate — archetype evaluation harness emitting SLSA VSAs (MP-33, ADR-013 §2).

An artifact advances through the tiered registries only by an automated, signed promotion
decision, and the signed result of each gate evaluation is a SLSA **Verification Summary
Attestation** — not a bespoke format. This module is the evaluation harness: it runs an
artifact against a set of archetype checks (mTLS handshake, DB driver compatibility,
memory/CPU profile, synthetic transactions) and emits a VSA carrying the verdict, the
archetype-suite it evaluated against (by digest), and the input attestations it consumed.
DSSE signing rides the same key posture as SLSA provenance (MP-07): the VSA is an in-toto
Statement in a DSSE envelope, so **stock SLSA-aware tooling verifies it** — there is no
gate-specific verifier at Tier 3 admission (that is MP-34).

The authority split is structural, not rhetorical (ADR-013 §3): **promotion is
governed-expansion, quarantine is autonomic-contraction.** This harness produces the VSA
(the governance record a promotion reads) and, on failure, a quarantine record — refusing
exposure is reversible and needs no human, so it is autonomic and this module acts. It does
**not** promote, countersign, or verify a chain; those grow risk or trust and belong to
MP-34 / MP-38.

Evidence, not proof (ADR-013 §6). The VSA records the suite digest precisely so the *scope*
of the evidence is machine-readable: the claim is always "validated against archetype suite
vN (digest …)", never "validated for production". The suite content — the 10–15 personas and
their coverage evidence — is authored elsewhere (MP-32); this harness runs whatever suite it
is handed and pins what it ran.

Crawl-stage honesty: the four check kinds evaluate *provided evidence* against a *declared
expectation*. They do not open sockets, load DB drivers, or drive traffic — a live probe is
a run-stage concern, and a harness that pretended to handshake while reading a fixture would
be exactly the false assurance the ADR warns against. The shape — named checks, pass/fail
with a reason, rolled into a signed VSA — is the deliverable, and it does not change when the
evidence starts arriving from a live sandbox.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import __version__
from .passport import SigningKey
from .provenance import (
    IN_TOTO_STATEMENT_TYPE,
    dsse_envelope,
    render,
    sha256_hex,
)

#: SLSA Verification Summary Attestation predicate type.
VSA_PREDICATE_TYPE = "https://slsa.dev/verification_summary/v1"
SLSA_VERSION = "1.0"

#: The Gate's verifier identity, recorded as ``predicate.verifier.id``.
GATE_VERIFIER_ID = f"https://calm-forge/gate@{__version__}"

RESULT_PASSED = "PASSED"
RESULT_FAILED = "FAILED"

#: Authority class of a quarantine — refusing exposure is reversible (ADR-013 §3).
AUTONOMIC_CONTRACTION = "autonomic-contraction"

#: The four check kinds ADR-013 §2 names for the archetype gate.
CHECK_MTLS = "mtls_handshake"
CHECK_DB_DRIVER = "db_driver_compat"
CHECK_RESOURCE = "resource_profile"
CHECK_SYNTHETIC = "synthetic_transaction"

#: Files written by :func:`write_gate_result`.
VSA_FILENAME = "vsa.slsa.json"
VSA_ENVELOPE_FILENAME = "vsa.slsa.dsse.json"
QUARANTINE_FILENAME = "quarantine.json"

#: Actions the unavailable-gate posture decides (ADR-013 follow-up 7 / MP-38).
ACTION_PROMOTION = "promotion"
ACTION_QUARANTINE = "quarantine"


class GateError(ValueError):
    """Raised when a gate run is malformed — no checks, or an unknown check kind."""


def unavailable_allows(action: str) -> bool:
    """What may proceed when the gate itself is down (ADR-013 Consequences, MP-38).

    Promotion grows exposure — **fail closed**. Quarantine refuses exposure —
    **fail open**, so a down gate cannot leave a bad artifact reachable. The
    runbook is this function, not tribal knowledge.
    """
    if action == ACTION_QUARANTINE:
        return True
    if action == ACTION_PROMOTION:
        return False
    raise GateError(
        f"unknown gate action {action!r} — known: "
        f"{ACTION_PROMOTION!r}, {ACTION_QUARANTINE!r}"
    )


# ---------------------------------------------------------------------------
# Check outcomes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CheckOutcome:
    """The result of one archetype check."""

    name: str
    kind: str
    archetype: str | None
    passed: bool
    detail: str

    def to_record(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "archetype": self.archetype,
            "passed": self.passed,
            "detail": self.detail,
        }


@dataclass
class GateResult:
    """Everything one gate run produces."""

    artifact: dict[str, Any]
    suite: dict[str, Any]
    result: str
    outcomes: list[CheckOutcome]
    vsa: dict[str, Any]
    envelope: dict[str, Any] | None = None
    quarantine: dict[str, Any] | None = None
    evaluated_archetypes: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.result == RESULT_PASSED

    def failed_checks(self) -> list[CheckOutcome]:
        return [o for o in self.outcomes if not o.passed]


# ---------------------------------------------------------------------------
# The four built-in check kinds
#
# Each takes (spec, evidence) and returns (passed, detail). `spec` is what the
# archetype requires; `evidence` is what was observed for this artifact.
# ---------------------------------------------------------------------------

def _version_tuple(value: Any) -> tuple[int, ...]:
    parts: list[int] = []
    for chunk in str(value).split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts) or (0,)


def _unmeasured(required: Any, observed: Any, what: str) -> str | None:
    """A declared requirement with no corresponding measurement **fails**.

    The tempting shape is ``if required is not None and observed is not None and
    observed > required`` — it only fails on evidence of a breach. But a gate that cannot
    measure a dimension is a gate that is *unavailable* for it, and ADR-013's rule is that
    an unavailable gate fails closed for promotion. Passing here would put a signed VSA
    saying PASSED on an artifact nobody measured, which is the false assurance ADR-013 §6
    exists to prevent — and worse than no gate, because the signature makes it credible.
    """
    if required is None:
        return None                       # nothing declared, nothing to measure
    if observed is None:
        return f"{what} required but not observed — nothing measured, so this fails closed"
    return None


def _check_mtls(spec: dict[str, Any], evidence: dict[str, Any]) -> tuple[bool, str]:
    reasons: list[str] = []
    min_tls = spec.get("min_tls_version")
    negotiated = evidence.get("negotiated_tls_version")
    unmeasured = _unmeasured(min_tls, negotiated, "TLS version")
    if unmeasured:
        reasons.append(unmeasured)
    elif min_tls is not None and _version_tuple(negotiated) < _version_tuple(min_tls):
        reasons.append(f"negotiated TLS {negotiated} < required {min_tls}")
    if spec.get("require_mutual") and not evidence.get("mutual"):
        reasons.append("mutual TLS required but not observed")
    allowed = spec.get("allowed_ciphers")
    cipher = evidence.get("cipher")
    unmeasured = _unmeasured(allowed, cipher, "cipher")
    if unmeasured:
        reasons.append(unmeasured)
    elif allowed and cipher not in allowed:
        reasons.append(f"cipher {cipher!r} not in allowed set")
    if reasons:
        return False, "; ".join(reasons)
    return True, f"mTLS ok (tls={negotiated}, mutual={bool(evidence.get('mutual'))})"


def _check_db_driver(spec: dict[str, Any], evidence: dict[str, Any]) -> tuple[bool, str]:
    want_driver = spec.get("driver")
    got_driver = evidence.get("driver")
    if want_driver is not None and got_driver != want_driver:
        return False, f"driver {got_driver!r} != required {want_driver!r}"
    min_version = spec.get("min_version")
    got_version = evidence.get("version")
    unmeasured = _unmeasured(min_version, got_version, "driver version")
    if unmeasured:
        return False, unmeasured
    if min_version is not None and _version_tuple(got_version) < _version_tuple(min_version):
        return False, f"driver version {got_version} < required {min_version}"
    return True, f"db driver ok ({got_driver} {got_version})"


def _check_resource(spec: dict[str, Any], evidence: dict[str, Any]) -> tuple[bool, str]:
    reasons: list[str] = []
    max_mem = spec.get("max_memory_mb")
    mem = evidence.get("memory_mb")
    unmeasured = _unmeasured(max_mem, mem, "memory")
    if unmeasured:
        reasons.append(unmeasured)
    elif max_mem is not None and mem > max_mem:
        reasons.append(f"memory {mem}MB > budget {max_mem}MB")
    max_cpu = spec.get("max_cpu_millicores")
    cpu = evidence.get("cpu_millicores")
    unmeasured = _unmeasured(max_cpu, cpu, "cpu")
    if unmeasured:
        reasons.append(unmeasured)
    elif max_cpu is not None and cpu > max_cpu:
        reasons.append(f"cpu {cpu}m > budget {max_cpu}m")
    if reasons:
        return False, "; ".join(reasons)
    return True, f"within profile (mem={mem}MB, cpu={cpu}m)"


def _check_synthetic(spec: dict[str, Any], evidence: dict[str, Any]) -> tuple[bool, str]:
    reasons: list[str] = []
    expect_status = spec.get("expect_status")
    status = evidence.get("status")
    if expect_status is not None and status != expect_status:
        reasons.append(f"status {status!r} != expected {expect_status!r}")
    max_latency = spec.get("max_latency_ms")
    latency = evidence.get("latency_ms")
    unmeasured = _unmeasured(max_latency, latency, "latency")
    if unmeasured:
        reasons.append(unmeasured)
    elif max_latency is not None and latency > max_latency:
        reasons.append(f"latency {latency}ms > budget {max_latency}ms")
    if reasons:
        return False, "; ".join(reasons)
    return True, f"synthetic ok (status={status}, latency={latency}ms)"


_CHECK_KINDS: dict[str, Callable[[dict[str, Any], dict[str, Any]], tuple[bool, str]]] = {
    CHECK_MTLS: _check_mtls,
    CHECK_DB_DRIVER: _check_db_driver,
    CHECK_RESOURCE: _check_resource,
    CHECK_SYNTHETIC: _check_synthetic,
}


def run_check(check: dict[str, Any]) -> CheckOutcome:
    """Evaluate one check dict: ``{name, kind, archetype?, spec?, evidence?}``.

    An unknown ``kind`` raises rather than being skipped — a check the harness cannot run
    is not a check that passed, and silently dropping it would let an unimplemented
    requirement read as satisfied.
    """
    kind = check.get("kind")
    if not isinstance(kind, str) or kind not in _CHECK_KINDS:
        raise GateError(
            f"unknown check kind {kind!r} — known: {sorted(_CHECK_KINDS)}. A check the "
            f"harness cannot run must not be silently treated as passed."
        )
    evaluator = _CHECK_KINDS[kind]
    passed, detail = evaluator(check.get("spec") or {}, check.get("evidence") or {})
    return CheckOutcome(
        name=str(check.get("name", kind)),
        kind=kind,
        archetype=check.get("archetype"),
        passed=passed,
        detail=detail,
    )


# ---------------------------------------------------------------------------
# Descriptors
# ---------------------------------------------------------------------------

def artifact_descriptor(uri: str, digest_sha256: str) -> dict[str, Any]:
    """A subject/resource descriptor: ``{uri, digest: {sha256}}``.

    The digest may be given bare or ``sha256:``-prefixed; it is normalized to bare hex,
    the in-toto ``digest`` map form.
    """
    bare = digest_sha256.split(":", 1)[1] if digest_sha256.startswith("sha256:") else digest_sha256
    return {"uri": uri, "digest": {"sha256": bare}}


def suite_descriptor(uri: str, *, content: Any = None, digest_sha256: str | None = None) -> dict[str, Any]:
    """The archetype-suite policy descriptor recorded in the VSA (ADR-013 §4).

    Supply either the suite ``content`` (its digest is computed by canonical JSON, the
    same digest-as-read discipline ADR-007 §1 applies to plane nodes) or a precomputed
    ``digest_sha256``. One or the other is required: a suite reference with no digest
    would make the VSA's evidence scope unpinnable, which is the whole point of §4.
    """
    if content is not None:
        canonical = json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        bare = sha256_hex(canonical)
    elif digest_sha256 is not None:
        bare = digest_sha256.split(":", 1)[1] if digest_sha256.startswith("sha256:") else digest_sha256
    else:
        raise GateError(
            "archetype suite needs a digest — pass content to hash, or digest_sha256; a "
            "suite reference with no digest cannot pin the scope of the evidence (ADR-013 §4)"
        )
    return {"uri": uri, "digest": {"sha256": bare}}


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# The gate run
# ---------------------------------------------------------------------------

def run_gate(
    *,
    artifact: dict[str, Any],
    suite: dict[str, Any],
    checks: list[dict[str, Any]],
    input_attestations: list[dict[str, Any]] | None = None,
    key: SigningKey | None = None,
    verifier_id: str = GATE_VERIFIER_ID,
    time_verified: datetime | None = None,
) -> GateResult:
    """Run an artifact against the archetype checks and emit a VSA.

    ``artifact`` and ``suite`` are descriptors (see :func:`artifact_descriptor`,
    :func:`suite_descriptor`). ``checks`` is a non-empty list of check dicts;
    ``input_attestations`` are the resource descriptors of the SLSA build provenance,
    SBOM, and scan results the evaluation consumed (ADR-013 §2), recorded so an auditor
    can resolve *what was checked*.

    The verdict is **PASSED iff every check passed** — fail closed. An empty check set is
    a caller error (:class:`GateError`), not a vacuous pass: a gate that verifies nothing
    and returns PASSED is precisely the theater ADR-013 §6 warns against. On FAILED a
    quarantine record is produced (autonomic-contraction, ADR-013 §3); promotion is not
    this module's to grant.

    When ``key`` is supplied the VSA is wrapped in a DSSE envelope, signed with the same
    discipline as SLSA provenance (MP-07) so stock tooling verifies it.
    """
    if not checks:
        raise GateError(
            "a gate run needs at least one check — an empty suite that returns PASSED is "
            "the false assurance ADR-013 §6 exists to prevent"
        )
    if "digest" not in artifact or not artifact.get("digest", {}).get("sha256"):
        raise GateError("artifact descriptor needs a sha256 digest (use artifact_descriptor)")
    if "digest" not in suite or not suite.get("digest", {}).get("sha256"):
        raise GateError("suite descriptor needs a sha256 digest (use suite_descriptor)")

    outcomes = [run_check(c) for c in checks]
    result = RESULT_PASSED if all(o.passed for o in outcomes) else RESULT_FAILED
    evaluated_archetypes = sorted({o.archetype for o in outcomes if o.archetype})

    now = time_verified or datetime.now(timezone.utc)
    predicate: dict[str, Any] = {
        "verifier": {"id": verifier_id},
        "timeVerified": _timestamp(now),
        "resourceUri": artifact["uri"],
        "policy": suite,
        "verificationResult": result,
        "verifiedLevels": [],
        "slsaVersion": SLSA_VERSION,
        # Non-standard but harmless: which archetypes actually ran. §5 runs only the
        # affected archetypes, so recording the subset keeps the scope honest and gives
        # ARCHETYPES_NEWER_THAN_PROMOTION (MP-36) the set to reason about. Stock SLSA
        # verifiers ignore unknown predicate fields; the signature still covers them.
        "evaluatedArchetypes": evaluated_archetypes,
    }
    if input_attestations:
        predicate["inputAttestations"] = input_attestations

    vsa = {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [artifact],
        "predicateType": VSA_PREDICATE_TYPE,
        "predicate": predicate,
    }

    envelope = dsse_envelope(vsa, key) if key is not None else None
    quarantine = None
    if result == RESULT_FAILED:
        quarantine = quarantine_record(artifact, suite, outcomes, recorded_at=now)

    return GateResult(
        artifact=artifact,
        suite=suite,
        result=result,
        outcomes=outcomes,
        vsa=vsa,
        envelope=envelope,
        quarantine=quarantine,
        evaluated_archetypes=evaluated_archetypes,
    )


def quarantine_record(
    artifact: dict[str, Any],
    suite: dict[str, Any],
    outcomes: list[CheckOutcome],
    *,
    recorded_at: datetime | None = None,
) -> dict[str, Any]:
    """A quarantine record with cause and disposition (ADR-013 §3, §7).

    Blocking at the gate is refusing exposure — reversible — so it is autonomic and the
    record says so. The failing checks are the cause; a human reviews after the fact,
    which is why the record is structured rather than a log line.
    """
    now = recorded_at or datetime.now(timezone.utc)
    return {
        "artifact": artifact,
        "cause": "gate_failed",
        "authority_class": AUTONOMIC_CONTRACTION,
        "disposition": "quarantined",
        "suite": suite,
        "failed_checks": [o.to_record() for o in outcomes if not o.passed],
        "recorded_at": _timestamp(now),
    }


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def write_gate_result(result: GateResult, output_dir: str | Path) -> list[Path]:
    """Write the VSA (and envelope, and quarantine record) to ``output_dir``."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    vsa_path = out / VSA_FILENAME
    vsa_path.write_text(render(result.vsa))
    written.append(vsa_path)

    if result.envelope is not None:
        env_path = out / VSA_ENVELOPE_FILENAME
        env_path.write_text(json.dumps(result.envelope, indent=2) + "\n")
        written.append(env_path)

    if result.quarantine is not None:
        q_path = out / QUARANTINE_FILENAME
        q_path.write_text(json.dumps(result.quarantine, indent=2) + "\n")
        written.append(q_path)

    return written


def load_gate_spec(path: str | Path) -> dict[str, Any]:
    """Read a gate spec JSON: ``{artifact, suite, checks, input_attestations?}``."""
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise GateError(f"{path}: gate spec must be an object, got {type(data).__name__}")
    return data
