"""Reverse diff — observed flows × passport claims (APP-030/031/032, Rung 3).

The money shot: it shows the graph knowing things the firewall doesn't. Given a set
of signed passports (declared edges) and a set of observed flows (a stand-in for
AuthMind / NetFlow, already identity-resolved), classify every edge:

  * observed ∧ no active grant        → SHADOW FLOW        (traffic with no claim)
  * grant ∧ (not observed ∨ expired)  → CONTRACTION CANDIDATE (claim should tighten)
  * grant ∧ observed ∧ current        → conformant
  * claim with no resolvable port     → UNADJUDICABLE      (the intent is underspecified)

Edge identity is the L4 `edge_id` shared with emission, so an observed tcp/8443 flow
matches a claim declared as HTTPS — the reason app protocol is *not* in the id.

Precedence note: an **expired but still-observed** grant is a CONTRACTION candidate, not a
shadow — a claim *did* exist, it just lapsed. Only traffic with no grant at all (or a
`revoke`) is a shadow. This keeps the two lists disjoint.

Port precision (APP-090/092). A claim whose port could not be resolved hashes to
``port=any``, which no concrete observed flow can ever equal. Matching those by edge_id
alone produced *two* false positives at once — a phantom SHADOW (the traffic looked
unclaimed) and a phantom CONTRACTION (the claim looked unobserved) — for one edge whose
only real problem was an underspecified declaration. So port=any claims are matched by
**scope** (src, dst, L4) instead, and split by what they mean:

  * ``port_wildcard``    — an author granted every port. Real permission: an observed flow
    on that scope is CONFORMANT, and the claim is flagged as broader than the traffic.
  * ``port_unspecified`` — nobody said. Not permission and not absence of permission, so
    the edge is reported UNADJUDICABLE rather than judged. The finding carries the port we
    actually observed, which is precisely the line the intent is missing.
"""
from __future__ import annotations

import csv
import glob
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .edge_id import edge_id_for_binding, edge_scope, edge_scope_for_binding
from .passport import edge_id_of

SHADOW = "SHADOW_FLOW"
CONTRACTION = "CONTRACTION_CANDIDATE"
CONFORMANT = "CONFORMANT"
UNADJUDICABLE = "UNADJUDICABLE"


@dataclass
class EffectiveClaim:
    """The authoritative claim for an edge_id (latest-issued wins; revoke supersedes)."""
    edge_id: str
    claim_type: str          # grant | revoke
    expires_at: int
    passport: dict[str, Any]

    @property
    def binding(self) -> dict[str, Any]:
        return self.passport.get("network_binding", {})

    @property
    def is_wildcard(self) -> bool:
        """An authored `any port` grant — permission, matched by scope."""
        return bool(self.binding.get("port_wildcard"))

    @property
    def is_unresolved(self) -> bool:
        """No port could be resolved — ignorance, never treated as permission."""
        return bool(self.binding.get("port_unspecified"))

    @property
    def scope(self) -> str | None:
        try:
            return edge_scope_for_binding(self.binding)
        except KeyError:
            return None


@dataclass
class DiffEntry:
    edge_id: str
    verdict: str
    detail: str
    source: str | None = None
    destination: str | None = None
    #: Populated on UNADJUDICABLE and wildcard-matched entries: the L4 port the
    #: fabric actually carried. On an unadjudicable finding this *is* the
    #: remediation — the value the intent should have declared.
    observed_port: int | None = None
    #: The claim's `network_binding.port_source`, so a report can distinguish a
    #: port declared in intent from one inferred or learned from the fabric.
    port_source: str | None = None


@dataclass
class DiffReport:
    shadow: list[DiffEntry] = field(default_factory=list)
    contraction: list[DiffEntry] = field(default_factory=list)
    conformant: list[DiffEntry] = field(default_factory=list)
    unadjudicable: list[DiffEntry] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        """Security findings only.

        Unadjudicable edges are a *declaration-quality* problem, not a security
        one — we deliberately do not know whether they are conformant. Failing
        the run on them would punish honesty about a gap that was previously
        being reported as two confident, wrong answers. They are surfaced
        separately (`has_gaps`) so a pipeline can gate on them by choice.
        """
        return bool(self.shadow or self.contraction)

    @property
    def has_gaps(self) -> bool:
        """True when some edge could not be judged for want of a declared port."""
        return bool(self.unadjudicable)

    def to_dict(self) -> dict[str, Any]:
        return {
            "shadow": [_entry_dict(e) for e in self.shadow],
            "contraction": [_entry_dict(e) for e in self.contraction],
            "conformant": [_entry_dict(e) for e in self.conformant],
            "unadjudicable": [_entry_dict(e) for e in self.unadjudicable],
        }


def _entry_dict(entry: DiffEntry) -> dict[str, Any]:
    """Serialize an entry, omitting the port fields where they say nothing.

    `observed_port` and `port_source` are absent on most rows; emitting them as
    nulls everywhere would bury the rows where they carry the remediation.
    """
    data = vars(entry)
    return {k: v for k, v in data.items() if v is not None or k not in _OMIT_IF_NONE}


_OMIT_IF_NONE = frozenset({"observed_port", "port_source"})


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_passports(passports_dir: str | Path) -> list[dict[str, Any]]:
    paths = sorted(glob.glob(str(Path(passports_dir) / "**" / "*.passport.json"), recursive=True))
    return [json.loads(Path(p).read_text()) for p in paths]


def load_observed_flows(path: str | Path) -> list[dict[str, Any]]:
    """Load observed flows from JSON (list or {"flows": [...]}) or CSV.

    Each flow is identity-resolved: source/destination workload URNs, transport, port.
    """
    path = Path(path)
    if path.suffix.lower() == ".csv":
        with path.open(newline="") as fh:
            rows = list(csv.DictReader(fh))
        for row in rows:
            if row.get("port") not in (None, ""):
                row["port"] = int(row["port"])
        return rows
    data = json.loads(path.read_text())
    return data.get("flows", data) if isinstance(data, dict) else data


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def flow_edge_id(flow: dict[str, Any]) -> str:
    """edge_id for an observed flow — same L4 tuple as a claim, so they can match."""
    binding = {
        "source_workload_urn": flow.get("source_workload_urn") or flow["source"],
        "destination_workload_urn": flow.get("destination_workload_urn") or flow["destination"],
        "transport": flow.get("transport", "tcp"),
        "port": flow.get("port"),
        "port_range": flow.get("port_range"),
        "port_unspecified": flow.get("port_unspecified"),
    }
    return edge_id_for_binding(binding)


def _effective_claims(passports: list[dict[str, Any]]) -> dict[str, EffectiveClaim]:
    """Collapse passports to one authoritative claim per edge_id.

    A `revoke` always wins (an edge marked for deletion is not granted); otherwise the
    latest-issued passport is authoritative.
    """
    claims: dict[str, EffectiveClaim] = {}
    for p in passports:
        eid = edge_id_of(p)
        claim_type = p["claim"]["claim_type"]
        issued = p["lifecycle"]["issued_at"]
        current = claims.get(eid)
        if current is None:
            claims[eid] = EffectiveClaim(eid, claim_type, p["lifecycle"]["expires_at"], p)
            continue
        if current.claim_type == "revoke":
            continue  # revoke sticks
        if claim_type == "revoke" or issued >= current.passport["lifecycle"]["issued_at"]:
            claims[eid] = EffectiveClaim(eid, claim_type, p["lifecycle"]["expires_at"], p)
    return claims


def _endpoints(binding_holder: dict[str, Any]) -> tuple[str | None, str | None]:
    nb = binding_holder.get("network_binding", binding_holder)
    return (
        nb.get("source_workload_urn") or nb.get("source"),
        nb.get("destination_workload_urn") or nb.get("destination"),
    )


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

def _flow_scope(flow: dict[str, Any]) -> str:
    src, dst = _endpoints(flow)
    return edge_scope(src or "", dst or "", flow.get("transport", "tcp"))


def diff(passports: list[dict[str, Any]], flows: list[dict[str, Any]], now: int) -> DiffReport:
    claims = _effective_claims(passports)
    observed: dict[str, dict[str, Any]] = {flow_edge_id(f): f for f in flows}
    report = DiffReport()

    # port=any claims cannot be matched by edge_id — a concrete flow always hashes
    # to its concrete port — so index them by scope instead (APP-092).
    wildcards: dict[str, EffectiveClaim] = {}
    unresolved: dict[str, EffectiveClaim] = {}
    for any_port_claim in claims.values():
        if any_port_claim.claim_type != "grant" or any_port_claim.scope is None:
            continue
        if any_port_claim.is_wildcard:
            wildcards[any_port_claim.scope] = any_port_claim
        elif any_port_claim.is_unresolved:
            unresolved[any_port_claim.scope] = any_port_claim

    #: scopes whose port=any claim was corroborated by real traffic
    wildcard_hits: set[str] = set()
    unresolved_hits: dict[str, list[int | None]] = {}

    for eid, flow in observed.items():
        claim = claims.get(eid)
        src, dst = _endpoints(flow)
        scope = _flow_scope(flow)
        if claim and claim.claim_type == "grant" and claim.expires_at > now:
            report.conformant.append(
                DiffEntry(eid, CONFORMANT, "flow matches current grant", src, dst,
                          port_source=claim.binding.get("port_source"))
            )
            continue
        if claim is None and scope in wildcards and wildcards[scope].expires_at > now:
            # A real grant covers this path — just more broadly than the traffic needs.
            wildcard_hits.add(scope)
            report.conformant.append(
                DiffEntry(
                    eid, CONFORMANT,
                    "flow covered by an any-port grant — narrowing candidate",
                    src, dst, observed_port=flow.get("port"),
                    port_source=wildcards[scope].binding.get("port_source"),
                )
            )
            continue
        if claim is None and scope in unresolved:
            # A claim exists for this path but declares no port, so we cannot say
            # whether it covers *this* port. Report the gap, not a guess.
            unresolved_hits.setdefault(scope, []).append(flow.get("port"))
            report.unadjudicable.append(
                DiffEntry(
                    unresolved[scope].edge_id, UNADJUDICABLE,
                    "claim declares no port; observed traffic cannot be adjudicated "
                    "against it — declare the port in intent",
                    src, dst, observed_port=flow.get("port"),
                    port_source=unresolved[scope].binding.get("port_source"),
                )
            )
            continue
        if claim is None or claim.claim_type == "revoke":
            why = "no claim for this flow" if claim is None else "flow contradicts a revoke"
            report.shadow.append(DiffEntry(eid, SHADOW, why, src, dst))
        # expired grant that is still observed → left to the contraction pass below

    for eid, claim in claims.items():
        if claim.claim_type != "grant":
            continue
        if claim.is_unresolved:
            # Never a contraction candidate: we do not know that it is unobserved,
            # only that we cannot tell. If no flow touched its scope at all, that
            # is still a gap rather than a finding.
            if claim.scope not in unresolved_hits:
                src, dst = _endpoints(claim.passport)
                report.unadjudicable.append(
                    DiffEntry(
                        eid, UNADJUDICABLE,
                        "claim declares no port and no traffic was observed on this "
                        "path — cannot distinguish unused from unobserved",
                        src, dst, port_source=claim.binding.get("port_source"),
                    )
                )
            continue
        expired = claim.expires_at <= now
        seen = eid in observed or (claim.is_wildcard and claim.scope in wildcard_hits)
        if not seen or expired:
            src, dst = _endpoints(claim.passport)
            why = "grant expired, no renewal" if expired else "granted but never observed"
            report.contraction.append(
                DiffEntry(eid, CONTRACTION, why, src, dst,
                          port_source=claim.binding.get("port_source"))
            )

    return report
