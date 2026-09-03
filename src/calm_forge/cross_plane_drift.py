"""Cross-plane drift evaluation (MP-10..MP-15, ADR-005 follow-ups, ADR-007 §4).

Multi-plane authoring creates a failure class single-plane Forge does not have —
**compositional drift: every part verifies, the whole is wrong.** Each plane compiled
deterministically, each signature verifies, each schema passes, and the fabric is still
not enforcing what the cyber organization authored, because the two were compiled at
different times against different graph states.

The reverse diff (:mod:`calm_forge.passport_diff`) cannot see this. It compares declared
intent against *observed reality* on the architecture plane. Cross-plane drift is a
disagreement between two *authored* planes, or between a plane and the artifact it
generated — both invisible to a loop that only asks "is the network doing what CALM
said".

**Every comparison here is by content, never by clock.** The right-hand side is a
digest-as-read captured by SLSA provenance (ADR-007 §1) or by a passport's
``graph_refs[*].node_version`` (ADR-006 §5); the left-hand side is the node's current
content digest. A timestamp comparison would break on skew, on backdated authoring, and
on no-op edits that would fire a false recompile across the estate.

Authority classes carry the two inversions that are easy to get wrong from first
principles. Read :data:`ORPHANED_POLICY` and :data:`STALE_ATTESTATION` before changing
either.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .kg_plane import (
    PLANE_ARCHITECTURE,
    PLANE_BUSINESS_INTENT,
    PLANE_CONTROLS,
    PLANE_DATA_MANAGEMENT,
    PLANE_REQUIREMENTS,
    PLANE_SUPPLY_CHAIN,
)

# --- finding types ---------------------------------------------------------

CONTROLS_NEWER_THAN_POLICY = "CONTROLS_NEWER_THAN_POLICY"
ORPHANED_POLICY = "ORPHANED_POLICY"
PLANE_MISSING = "PLANE_MISSING"
STALE_ATTESTATION = "STALE_ATTESTATION"

# data_management declared-vs-observed pair — MP-50, ADR-011 §7b. The plane holds both
# halves: ODCS contracts (declared, MP-49) and OpenLineage events (observed, MP-18). The
# comparison is the finding, and the two are deliberately different authority classes.
DATASET_OBSERVED_NOT_CONTRACTED = "DATASET_OBSERVED_NOT_CONTRACTED"
CONTRACT_NEVER_OBSERVED = "CONTRACT_NEVER_OBSERVED"

#: Requirements-plane finding (MP-55, ADR-015 §3). The requirement changed after the
#: artifact was generated from it: a regeneration candidate.
REQUIREMENTS_NEWER_THAN_CODE = "REQUIREMENTS_NEWER_THAN_CODE"

#: supply_chain finding (MP-36, ADR-013 §4). The persona suite tightened after this
#: artifact was promoted; the standing VSA attests against a superseded policy.
#: Flagging is autonomic (the comparison is a digest read). Acting — re-validation
#: or demotion — is governed, because demoting a production artifact expands risk
#: elsewhere (same inversion as MP-11 / MP-55).
ARCHETYPES_NEWER_THAN_PROMOTION = "ARCHETYPES_NEWER_THAN_PROMOTION"

# --- authority ------------------------------------------------------------

AUTONOMIC = "autonomic"
GOVERNED = "governed"

# --- remediation ----------------------------------------------------------

REMEDIATION_RECOMPILE = "recompile"
REMEDIATION_REISSUE = "reissue"
REMEDIATION_ESCALATE = "escalate"
REMEDIATION_AUTHOR = "author"
REMEDIATION_REGENERATE = "regenerate"

#: Planes a production edge must have authored. ADR-005 §5: production admits no waiver.
#: `data_management` (ADR-011) and `supply_chain` (ADR-013) are conditional on the
#: workload declaring a data interface / consuming a gated artifact, so they are not in
#: the unconditional set — a platform passing its own policy overrides this.
DEFAULT_REQUIRED_PLANES: dict[str, frozenset[str]] = {
    "production": frozenset({PLANE_ARCHITECTURE, PLANE_CONTROLS, PLANE_BUSINESS_INTENT}),
    "staging": frozenset({PLANE_ARCHITECTURE, PLANE_CONTROLS}),
    "development": frozenset({PLANE_ARCHITECTURE}),
    "test": frozenset({PLANE_ARCHITECTURE}),
}


@dataclass(frozen=True)
class Finding:
    """One cross-plane drift finding.

    ``authority_class`` is the safety split (APP-000) applied to *acting on* the
    finding, not to detecting it. Detection is always safe; remediation is not.
    """
    finding_type: str
    subject: str
    detail: str
    authority_class: str
    remediation: str
    plane: str | None = None
    node_id: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "subject": self.subject,
            "detail": self.detail,
            "authority_class": self.authority_class,
            "remediation": self.remediation,
            "plane": self.plane,
            "node_id": self.node_id,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class Waiver:
    """A plane deliberately not authored, with the rule that waives it.

    **Not a finding.** Carried separately in the report so an operator sees
    "not here on purpose" and "required and unauthored" as different states end to end
    (MP-15). Collapsing them into one list at the reporting layer would undo ADR-005 §5
    at exactly the surface where the distinction is supposed to do its work.
    """
    subject: str
    plane: str
    waived_by: str | None

    def to_dict(self) -> dict[str, Any]:
        return {"subject": self.subject, "plane": self.plane, "waived_by": self.waived_by}


@dataclass
class DriftReport:
    findings: list[Finding] = field(default_factory=list)
    waivers: list[Waiver] = field(default_factory=list)

    @property
    def governed(self) -> list[Finding]:
        """Findings a human must act on."""
        return [f for f in self.findings if f.authority_class == GOVERNED]

    @property
    def autonomic(self) -> list[Finding]:
        """Findings the loop may resolve on its own."""
        return [f for f in self.findings if f.authority_class == AUTONOMIC]

    def of_type(self, finding_type: str) -> list[Finding]:
        return [f for f in self.findings if f.finding_type == finding_type]

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "waivers": [w.to_dict() for w in self.waivers],
            "counts": {
                "total": len(self.findings),
                "governed": len(self.governed),
                "autonomic": len(self.autonomic),
                "waivers": len(self.waivers),
            },
        }


# ---------------------------------------------------------------------------
# Artifact-side findings — MP-10, MP-11
# ---------------------------------------------------------------------------

#: GUID prefix of the requirements plane. ADR-004 §11 makes the scheme structural rather
#: than decorative, so reading the plane off the prefix is a lookup and not a heuristic —
#: the same move ``kg://anchor/`` and ``kg://odcs/`` already rely on.
_REQUIREMENTS_PREFIX = "kg://requirements/"


def _is_requirements_node(node_id: str) -> bool:
    return node_id.startswith(_REQUIREMENTS_PREFIX)


def _plane_dependencies(statement: dict[str, Any]) -> list[dict[str, Any]]:
    """Resolved dependencies that point at graph nodes.

    File inputs (the crawl-stage CALM/decorator/catalog documents) are recorded with
    ``file://`` URIs and are not plane nodes, so they are not cross-plane subjects.
    """
    deps = statement.get("predicate", {}).get("buildDefinition", {}).get(
        "resolvedDependencies", []
    )
    return [d for d in deps if str(d.get("uri", "")).startswith("kg://")]


def evaluate_artifacts(
    statements: list[dict[str, Any]],
    current_versions: dict[str, str],
) -> list[Finding]:
    """Compare each artifact's digests-as-read against the graph's current digests.

    Produces :data:`CONTROLS_NEWER_THAN_POLICY` and :data:`ORPHANED_POLICY`.
    """
    findings: list[Finding] = []
    for statement in statements:
        subjects = [s.get("name", "<unnamed>") for s in statement.get("subject", [])]
        artifact = ", ".join(subjects) or "<unnamed>"

        for dep in _plane_dependencies(statement):
            node_id = str(dep["uri"])
            as_read = f"sha256:{dep.get('digest', {}).get('sha256', '')}"
            current = current_versions.get(node_id)

            if current is None:
                findings.append(Finding(
                    finding_type=ORPHANED_POLICY,
                    subject=artifact,
                    node_id=node_id,
                    detail=(
                        "compiled from a plane node that no longer exists — the "
                        "enforcement outlives its authorization"
                    ),
                    # Removal *looks* like a contraction, and contractions are normally
                    # autonomic. It is not safe here: the enforcement may be
                    # load-bearing even though its authorization lapsed, and the
                    # revocation may itself be the error. This is a **governed
                    # contraction** — the rare inversion. Do not wire it autonomic on
                    # the reasoning that "contraction is always autonomic".
                    authority_class=GOVERNED,
                    remediation=REMEDIATION_ESCALATE,
                    evidence={"version_as_read": as_read},
                ))
                continue

            if current != as_read:
                if _is_requirements_node(node_id):
                    # The same observation, a different act. Recompiling a policy
                    # converges enforcement; **regenerating changes running software**,
                    # which expands risk somewhere else. Same inversion as MP-11 and
                    # MP-36, and routing it here rather than letting it fall through to
                    # the autonomic branch is the whole of MP-55: before this, a changed
                    # requirement was classified `autonomic / recompile`, which authorises
                    # a machine to regenerate an application unattended.
                    findings.append(Finding(
                        finding_type=REQUIREMENTS_NEWER_THAN_CODE,
                        subject=artifact,
                        plane=PLANE_REQUIREMENTS,
                        node_id=node_id,
                        detail=(
                            "the requirement changed after this artifact was generated "
                            "from it — a regeneration candidate, not a regeneration"
                        ),
                        authority_class=GOVERNED,
                        remediation=REMEDIATION_REGENERATE,
                        evidence={"version_as_read": as_read, "current_version": current},
                    ))
                    continue
                findings.append(Finding(
                    finding_type=CONTROLS_NEWER_THAN_POLICY,
                    subject=artifact,
                    node_id=node_id,
                    detail=(
                        "plane node changed since this artifact was compiled — the "
                        "estate is enforcing a superseded version"
                    ),
                    # Recompiling converges enforcement toward current authoring:
                    # reversible, low authority, contraction-shaped.
                    authority_class=AUTONOMIC,
                    remediation=REMEDIATION_RECOMPILE,
                    evidence={"version_as_read": as_read, "current_version": current},
                ))
    return findings


# ---------------------------------------------------------------------------
# Passport-side findings — MP-12, MP-13
# ---------------------------------------------------------------------------

def evaluate_passports(
    passports: list[dict[str, Any]],
    current_versions: dict[str, str],
    required_planes: dict[str, frozenset[str]] | None = None,
) -> tuple[list[Finding], list[Waiver]]:
    """Compare passport plane references against the graph's current digests.

    Produces :data:`STALE_ATTESTATION` and :data:`PLANE_MISSING`, plus the waiver list
    that keeps "not here on purpose" visibly distinct from "required and unauthored".

    v0.1 passports carry a single architecture reference and no plane map, so they are
    evaluated for staleness only — asking a v0.1 passport for its controls plane would
    report every one of them as missing a plane the format cannot express.
    """
    from .passport import PASSPORT_VERSION_V2, edge_id_of

    policy = required_planes if required_planes is not None else DEFAULT_REQUIRED_PLANES
    findings: list[Finding] = []
    waivers: list[Waiver] = []

    for passport in passports:
        subject = edge_id_of(passport)
        environment = passport.get("intent_metadata", {}).get("environment", "")

        if passport.get("passport_version") != PASSPORT_VERSION_V2:
            continue

        graph_refs = passport.get("graph_refs", {})
        for plane, ref in graph_refs.items():
            if ref.get("absent") == "policy":
                waivers.append(Waiver(subject, plane, ref.get("waived_by")))
                continue
            findings.extend(_staleness(subject, plane, ref, current_versions))

        for plane in sorted(policy.get(environment, frozenset())):
            if plane in graph_refs:
                continue
            findings.append(Finding(
                finding_type=PLANE_MISSING,
                subject=subject,
                plane=plane,
                detail=(
                    f"{environment} requires the {plane} plane and this edge has no "
                    f"authoring for it — absence with no waiver is a violation, not a "
                    f"governed statement"
                ),
                authority_class=GOVERNED,
                remediation=REMEDIATION_AUTHOR,
                evidence={"environment": environment},
            ))

    return findings, waivers


def _staleness(
    subject: str,
    plane: str,
    ref: dict[str, Any],
    current_versions: dict[str, str],
) -> list[Finding]:
    """STALE_ATTESTATION for one plane reference, when it is computable.

    A reference with no ``node_version`` is **not** a finding: it is a passport issued
    before the emitter captured digests (MP-14), and reporting it as stale would
    manufacture drift out of missing evidence.
    """
    as_read = ref.get("node_version")
    node_id = ref.get("node_id")
    if not as_read or not node_id:
        return []

    current = current_versions.get(node_id)
    if current is None or current == as_read:
        return []

    return [Finding(
        finding_type=STALE_ATTESTATION,
        subject=subject,
        plane=plane,
        node_id=node_id,
        detail=(
            "the passport references a plane node that has since changed — the "
            "signature still verifies because it attests the reference, not the "
            "referent's freshness"
        ),
        # The passport was never wrong; it is now *about the past*. A should-be claim
        # whose referent moved is resolved by RE-ISSUE — the platform re-signs against
        # current graph state, autonomically. **Not revoke.** Revoke asserts the *edge*
        # lost authorization, which is a claim about a different subject; routing
        # staleness there turns routine re-attestation into spurious loss of a grant.
        authority_class=AUTONOMIC,
        remediation=REMEDIATION_REISSUE,
        evidence={"version_as_read": as_read, "current_version": current},
    )]


# ---------------------------------------------------------------------------
# data_management — declared (ODCS) vs observed (OpenLineage) — MP-50
# ---------------------------------------------------------------------------

def _observed_and_contracted(
    kg_documents: list[dict[str, Any]],
) -> tuple[set[str], list[dict[str, Any]]]:
    """Collect observed OpenLineage dataset ids and contracted-dataset nodes from the KG.

    Uses :func:`~.kg_plane.index_nodes` so a node is found whether it is a standalone file
    or embedded in a Workload document's authored containers — the same walk
    ``node_versions`` runs, so the two halves are read from one graph consistently.
    """
    from .intake_odcs import NODE_TYPE_CONTRACTED_DATASET
    from .intake_openlineage import DATASET_ID_PREFIX, NODE_TYPE_DATASET
    from .kg_plane import index_nodes

    observed: set[str] = set()
    contracted: list[dict[str, Any]] = []
    for doc in kg_documents:
        for node in index_nodes(doc).values():
            node_type = node.get("@type")
            node_id = str(node.get("@id", ""))
            if node_type == NODE_TYPE_DATASET and node_id.startswith(DATASET_ID_PREFIX):
                observed.add(node_id)
            elif node_type == NODE_TYPE_CONTRACTED_DATASET:
                contracted.append(node)
    return observed, contracted


def evaluate_data_management(
    observed_dataset_ids: set[str] | list[str],
    contracted_dataset_nodes: list[dict[str, Any]],
) -> list[Finding]:
    """The `data_management` drift pair (ADR-011 §7b), joined on dataset identity.

    ``observed_dataset_ids`` are the OpenLineage dataset GUIDs lineage has authored;
    ``contracted_dataset_nodes`` are the ODCS ``ContractedDataset`` nodes (MP-49). The join
    key is derived **on read** — a contracted dataset's candidate OpenLineage ids come from
    :func:`~.intake_odcs.observed_dataset_ids`, never from a stored field — so refining the
    correspondence rule later cannot re-digest a contract and present it as drift.

    Two findings, two authority classes, and collapsing them would repeat the MP-11 mistake:

    * :data:`DATASET_OBSERVED_NOT_CONTRACTED` — data moving with no declared basis.
      **Governed**: acting on it means stopping a pipeline, and stopping a pipeline expands
      risk elsewhere, so a human acts even though it is detected autonomically.
    * :data:`CONTRACT_NEVER_OBSERVED` — a contract no run has ever exercised. **Autonomic to
      flag**: usually stale governance, but a contract nobody exercises is a control nobody
      tests, decaying into false assurance the way an ossified archetype suite does.

    A contracted dataset from which **no** candidate id can be derived (the contract names no
    server with a host) is unjoinable, not unobserved: it is skipped here and surfaced as a
    gap at intake instead, because "cannot be compared" must never read as "compared and
    absent".
    """
    from .intake_odcs import observed_dataset_ids as candidate_ids

    observed = set(observed_dataset_ids)
    findings: list[Finding] = []

    all_candidates: set[str] = set()
    per_contract: dict[str, set[str]] = {}
    for node in contracted_dataset_nodes:
        candidates = set(candidate_ids(node))
        all_candidates |= candidates
        contract = node.get("contract")
        if contract:
            per_contract.setdefault(str(contract), set()).update(candidates)

    for dataset_id in sorted(observed - all_candidates):
        findings.append(Finding(
            finding_type=DATASET_OBSERVED_NOT_CONTRACTED,
            subject=dataset_id,
            plane=PLANE_DATA_MANAGEMENT,
            node_id=dataset_id,
            detail=(
                "lineage shows data moving through a dataset no contract declares — data "
                "in motion with no declared basis"
            ),
            # Data is already flowing; the convergent action is to author the missing
            # contract, and the alternative — stopping the pipeline — expands risk
            # elsewhere. Either way a human decides: governed, not autonomic (MP-11).
            authority_class=GOVERNED,
            remediation=REMEDIATION_AUTHOR,
            evidence={},
        ))

    for contract_id in sorted(per_contract):
        candidates = per_contract[contract_id]
        if candidates and not (candidates & observed):
            findings.append(Finding(
                finding_type=CONTRACT_NEVER_OBSERVED,
                subject=contract_id,
                plane=PLANE_DATA_MANAGEMENT,
                node_id=contract_id,
                detail=(
                    "a contract exists and no run has ever exercised any dataset it "
                    "declares — a control nobody tests decays into false assurance"
                ),
                # Flagging is safe and usually surfaces stale governance; retiring or
                # wiring the contract is the owner's call, so it routes to them rather
                # than converging on its own.
                authority_class=AUTONOMIC,
                remediation=REMEDIATION_ESCALATE,
                evidence={},
            ))
    return findings


# ---------------------------------------------------------------------------
# Promotion-side findings — MP-36
# ---------------------------------------------------------------------------

def _suites_and_archetypes(
    kg_documents: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    from .intake_archetypes import NODE_TYPE_ARCHETYPE, NODE_TYPE_SUITE
    from .kg_plane import index_nodes

    suites: list[dict[str, Any]] = []
    archetypes: list[dict[str, Any]] = []
    for doc in kg_documents:
        for node in index_nodes(doc).values():
            kind = node.get("@type")
            if kind == NODE_TYPE_SUITE:
                suites.append(node)
            elif kind == NODE_TYPE_ARCHETYPE:
                archetypes.append(node)
    return suites, archetypes


def suite_digest_for(
    policy_uri: str,
    kg_documents: list[dict[str, Any]],
) -> str | None:
    """Current content digest of the suite the VSA pinned, or None if no suite exists.

    Computed on read from the suite node plus its persona members — never stored
    (MP-32). ``None`` means the graph has no suite at that URI, which is "policy
    gone", not "policy unchanged".
    """
    from .intake_archetypes import suite_digest

    suites, archetypes = _suites_and_archetypes(kg_documents)
    members_by_id = {n["@id"]: n for n in archetypes}
    for suite in suites:
        if suite.get("@id") != policy_uri:
            continue
        members = [members_by_id[i] for i in suite.get("archetype_ids") or []
                   if i in members_by_id]
        return suite_digest(str(suite["suite_version"]), members)
    return None


def evaluate_promotions(
    vsas: list[dict[str, Any]],
    kg_documents: list[dict[str, Any]],
) -> list[Finding]:
    """Compare each standing VSA's suite digest-as-read against the current suite.

    Only ``PASSED`` VSAs are promotions. A FAILED VSA is a quarantine record, not a
    standing grant, and is not this finding's subject.

    If the graph has **no** suite nodes, nothing is flagged — there is no current
    policy to be newer than the promotion. A VSA whose ``policy.uri`` does not
    resolve, or whose digest disagrees with the current content, is a finding.

    A PASSED VSA that pins **no** suite at all is also a finding, carrying
    ``comparable: False``. It is not silently passed over: "cannot be compared"
    must never read as "compared and unchanged", or an unpinned VSA becomes the
    safest kind to hold.
    """
    suites, _ = _suites_and_archetypes(kg_documents)
    if not suites:
        return []

    findings: list[Finding] = []
    for vsa in vsas:
        predicate = vsa.get("predicate") or {}
        if predicate.get("verificationResult") != "PASSED":
            continue
        policy = predicate.get("policy") or {}
        policy_uri = str(policy.get("uri") or "")
        as_read = (policy.get("digest") or {}).get("sha256")

        subjects = vsa.get("subject") or []
        artifact = subjects[0].get("uri", "<unnamed>") if subjects else "<unnamed>"

        # A standing promotion that cannot be compared is not a promotion that
        # compared clean. Skipping it here would make an unpinned VSA the safest
        # kind to hold, which is backwards — so it is raised, not passed over.
        if not policy_uri or not as_read:
            findings.append(Finding(
                finding_type=ARCHETYPES_NEWER_THAN_PROMOTION,
                subject=str(artifact),
                plane=PLANE_SUPPLY_CHAIN,
                node_id=policy_uri or None,
                detail=(
                    "this artifact holds a PASSED VSA that pins no archetype suite "
                    f"({'no policy.uri' if not policy_uri else 'no policy.digest.sha256'}), "
                    "so the promotion cannot be compared against the current suite at "
                    "all. Uncomparable is not unchanged (ADR-013 §4)"
                ),
                authority_class=GOVERNED,
                remediation=REMEDIATION_ESCALATE,
                evidence={
                    "policy_digest_as_read": as_read,
                    "current_suite_digest": None,
                    "comparable": False,
                    "evaluated_archetypes": list(
                        predicate.get("evaluatedArchetypes") or []
                    ),
                },
            ))
            continue

        current = suite_digest_for(policy_uri, kg_documents)

        if current == as_read:
            continue

        findings.append(Finding(
            finding_type=ARCHETYPES_NEWER_THAN_PROMOTION,
            subject=str(artifact),
            plane=PLANE_SUPPLY_CHAIN,
            node_id=policy_uri,
            detail=(
                (
                    "the archetype suite this artifact was promoted against is no "
                    "longer in the graph — the standing VSA attests against a policy "
                    "that cannot be read back"
                    if current is None else
                    "the archetype suite changed after this artifact was promoted — "
                    "the standing VSA attests against a superseded policy"
                )
                + ". Flagged automatically; re-validation or demotion is a human "
                "act (ADR-013 §4)"
            ),
            # Detection is a digest read and is autonomic. The *act* — forcing
            # re-validation or pulling the artifact from production — expands
            # risk elsewhere and is governed. authority_class names the act.
            authority_class=GOVERNED,
            remediation=REMEDIATION_ESCALATE,
            evidence={
                "policy_digest_as_read": as_read,
                "current_suite_digest": current,
                "comparable": True,
                "evaluated_archetypes": list(predicate.get("evaluatedArchetypes") or []),
            },
        ))
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def evaluate(
    kg_documents: list[dict[str, Any]],
    provenance_statements: list[dict[str, Any]] | None = None,
    passports: list[dict[str, Any]] | None = None,
    required_planes: dict[str, frozenset[str]] | None = None,
    vsas: list[dict[str, Any]] | None = None,
) -> DriftReport:
    """Evaluate cross-plane drift across artifacts, passports, promotions, and data_management."""
    from .kg_plane import node_versions

    current = node_versions(kg_documents)
    findings = evaluate_artifacts(provenance_statements or [], current)
    passport_findings, waivers = evaluate_passports(
        passports or [], current, required_planes
    )
    findings.extend(passport_findings)

    observed, contracted = _observed_and_contracted(kg_documents)
    findings.extend(evaluate_data_management(observed, contracted))
    findings.extend(evaluate_promotions(vsas or [], kg_documents))

    return DriftReport(findings=findings, waivers=waivers)
