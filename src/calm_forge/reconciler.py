"""Drift reconciliation loop — propose and optionally execute remediation actions.

When drift is detected in fabric-state.json, reconcile() examines each violating
workload and proposes one of three actions:

  redeploy    — re-emit a DeploymentRequest (capability-ceiling violations with a
                pending request already in flight)
  update_kg   — correct the Workload's allowed_regions to match observed reality
                (region mismatch when Concert doesn't block the observed region)
  escalate    — append a structured record to _fabric/escalations.jsonl for
                human review (all other cases)

In dry_run=True mode (default) no state is written. In dry_run=False mode the
proposed action is executed.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypedDict


class ReconciliationProposal(TypedDict):
    workload_id: str
    action: str           # "redeploy" | "update_kg" | "escalate"
    reason: str
    deployment_request_id: str | None
    dry_run: bool
    violations: list[dict[str, Any]]


class RemediationProposal(TypedDict):
    workload_id: str
    proposed_changes: list[dict[str, Any]]
    rationale: str
    confidence: str       # "high" | "medium" | "low"


def reconcile(kg_dir: Path, dry_run: bool = True, propose: bool = False) -> dict[str, Any]:
    """Examine the fabric state and propose (or execute) drift remediation.

    Reads fabric-state.json when present; falls back to build_fabric_feed().

    Args:
        kg_dir:   KG directory containing the live knowledge graph.
        dry_run:  When True (default), return proposals without writing anything.
        propose:  When True, attach a RemediationProposal to each escalation record.

    Returns:
        dict with keys:
          proposals   list[ReconciliationProposal]
          executed    list[str]  — @ids of workloads where action was taken (dry_run=False only)
          dry_run     bool
    """
    feed = _load_feed(kg_dir)
    workloads = feed.get("workloads", [])

    proposals: list[ReconciliationProposal] = []
    for wl in workloads:
        if wl.get("drift_status") != "violation":
            continue
        proposal = _propose_action(wl, kg_dir)
        if propose and proposal["action"] == "escalate":
            proposal["remediation_proposal"] = propose_remediation(dict(proposal), kg_dir)  # type: ignore[typeddict-unknown-key]
        proposals.append(proposal)

    executed: list[str] = []
    if not dry_run:
        for proposal in proposals:
            _execute(proposal, kg_dir)
            executed.append(proposal["workload_id"])

    return {"proposals": proposals, "executed": executed, "dry_run": dry_run}


# ---------------------------------------------------------------------------
# Decision tree
# ---------------------------------------------------------------------------

def _propose_action(wl: dict[str, Any], kg_dir: Path) -> ReconciliationProposal:
    workload_id = wl.get("id") or wl.get("workload_id", "workload:unknown")
    violations = _collect_violations(wl, kg_dir)
    rules = {v.get("rule", "") for v in violations}
    severity_rules = {v.get("rule", "") for v in violations if v.get("severity") == "violation"}

    # Check for pending DeploymentRequest
    from .intake import load_deployment_requests
    pending = load_deployment_requests(kg_dir, workload_id=workload_id, status="pending")
    pending_req_id = pending[-1]["@id"] if pending else None

    # Rule 1: only capability-ceiling violations + pending request → redeploy
    capability_rules = {"capability-ceiling", "capability-ceiling-policy-required"}
    if severity_rules and severity_rules.issubset(capability_rules) and pending_req_id:
        return ReconciliationProposal(
            workload_id=workload_id,
            action="redeploy",
            reason=(
                f"capability-ceiling violation with pending deployment — "
                f"re-emitting DeploymentRequest {pending_req_id}"
            ),
            deployment_request_id=pending_req_id,
            dry_run=True,
            violations=violations,
        )

    # Rule 2: region mismatch and Concert doesn't block the observed region → update_kg
    region_rules = {"compliance-requires-region-constraint"}
    if severity_rules and severity_rules.issubset(region_rules):
        observed_regions = _observed_regions(wl)
        blocked = _concert_blocked_environments(kg_dir, workload_id)
        observed_not_blocked = [r for r in observed_regions if r not in blocked]
        if observed_regions and observed_not_blocked:
            return ReconciliationProposal(
                workload_id=workload_id,
                action="update_kg",
                reason=(
                    f"observed regions {observed_regions} not in declared allowed_regions — "
                    f"Concert does not block; correcting KG intent"
                ),
                deployment_request_id=None,
                dry_run=True,
                violations=violations,
            )

    # Default: escalate
    rule_names = sorted(rules) if rules else ["unknown"]
    return ReconciliationProposal(
        workload_id=workload_id,
        action="escalate",
        reason=f"unresolvable drift: {', '.join(rule_names)} — requires human review",
        deployment_request_id=pending_req_id,
        dry_run=True,
        violations=violations,
    )


# ---------------------------------------------------------------------------
# Action executors
# ---------------------------------------------------------------------------

def _execute(proposal: ReconciliationProposal, kg_dir: Path) -> None:
    proposal["dry_run"] = False
    action = proposal["action"]
    if action == "redeploy":
        _execute_redeploy(proposal, kg_dir)
    elif action == "update_kg":
        _execute_update_kg(proposal, kg_dir)
    else:
        _execute_escalate(proposal, kg_dir)


def _execute_redeploy(proposal: ReconciliationProposal, kg_dir: Path) -> None:
    """Re-emit artifacts from the existing DeploymentRequest as a new pending request."""
    from .intake import load_deployment_requests, write_deployment_request

    req_id = proposal["deployment_request_id"]
    if not req_id:
        return

    existing = load_deployment_requests(kg_dir, workload_id=proposal["workload_id"], status="pending")
    if not existing:
        return

    original = existing[-1]
    now = datetime.now(timezone.utc).isoformat()
    slug = proposal["workload_id"].replace("workload:", "")
    new_id = f"deploy-req:{slug}:reconcile-{abs(hash(now)) % 10**6:06d}"

    new_req = {
        **original,
        "@id": new_id,
        "requested_at": now,
        "requested_by": "calm-forge/reconciler",
        "status": "pending",
        "reconciled_from": req_id,
        "_provenance": {
            "authored_by": "calm-forge/reconciler",
            "authored_at": now,
        },
    }
    write_deployment_request(new_req, kg_dir)


def _execute_update_kg(proposal: ReconciliationProposal, kg_dir: Path) -> None:
    """Update the Workload node's allowed_regions to include observed regions."""
    workload_id = proposal["workload_id"]
    wl_dir = kg_dir / "workloads"
    if not wl_dir.exists():
        return

    observed = _observed_regions_from_placements(kg_dir, workload_id)
    if not observed:
        return

    for path in sorted(wl_dir.glob("*.json")):
        try:
            node = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if node.get("@id") != workload_id:
            continue
        current = node.get("allowed_regions", [])
        merged = sorted(set(current) | set(observed))
        if merged == sorted(current):
            return
        node["allowed_regions"] = merged
        node.setdefault("_reconciliation_history", []).append({
            "action": "update_kg",
            "previous_allowed_regions": current,
            "new_allowed_regions": merged,
            "reconciled_at": datetime.now(timezone.utc).isoformat(),
            "reason": proposal["reason"],
        })
        path.write_text(json.dumps(node, indent=2))
        return


def _execute_escalate(proposal: ReconciliationProposal, kg_dir: Path) -> None:
    """Append a structured escalation record to _fabric/escalations.jsonl."""
    fabric_dir = kg_dir / "_fabric"
    fabric_dir.mkdir(parents=True, exist_ok=True)
    escalation_file = fabric_dir / "escalations.jsonl"
    record = {
        "event_type": "calm.reconcile.escalated",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "workload_id": proposal["workload_id"],
        "reason": proposal["reason"],
        "action": "escalate",
        "violations": proposal["violations"],
        "deployment_request_id": proposal["deployment_request_id"],
    }
    with escalation_file.open("a") as fh:
        fh.write(json.dumps(record) + "\n")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_feed(kg_dir: Path) -> dict[str, Any]:
    fabric_state = kg_dir / "fabric-state.json"
    if fabric_state.exists():
        try:
            return json.loads(fabric_state.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    from .dashboard import build_fabric_feed
    return build_fabric_feed(kg_dir)


def _collect_violations(wl: dict[str, Any], kg_dir: Path) -> list[dict[str, Any]]:
    """Collect violation findings from the workload's placement drift states."""
    workload_id = wl.get("id") or wl.get("workload_id", "")
    place_dir = kg_dir / "placements"
    if not place_dir.exists():
        return []
    violations = []
    for path in sorted(place_dir.glob("*.json")):
        try:
            node = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if node.get("@type") != "Placement":
            continue
        if node.get("workload_id") != workload_id:
            continue
        for f in node.get("drift_state", {}).get("findings", []):
            if f.get("severity") == "violation":
                violations.append(f)
    return violations


def _observed_regions(wl: dict[str, Any]) -> list[str]:
    return [p.get("region") for p in wl.get("placements", []) if p.get("region")]


def _observed_regions_from_placements(kg_dir: Path, workload_id: str) -> list[str]:
    place_dir = kg_dir / "placements"
    if not place_dir.exists():
        return []
    regions = []
    for path in sorted(place_dir.glob("*.json")):
        try:
            node = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if node.get("workload_id") == workload_id:
            r = node.get("region", "")
            if r:
                regions.append(r)
    return regions


def _concert_blocked_environments(kg_dir: Path, workload_id: str) -> list[str]:
    from .intake import load_placement_policies
    blocked = []
    for p in load_placement_policies(kg_dir, workload_id=workload_id):
        blocked.extend(p.get("blocked_environments", []))
    return blocked


_RULE_REMEDIATION: dict[str, dict[str, Any]] = {
    "compliance-requires-region-constraint": {
        "field": "allowed_regions",
        "description": "Add region constraints matching observed placement regions",
        "confidence": "high",
    },
    "capability-ceiling": {
        "field": "declared_capabilities",
        "description": "Remove undeclared capabilities from component or extend declared set",
        "confidence": "high",
    },
    "capability-ceiling-policy-required": {
        "field": "declared_capabilities",
        "description": "Add required capability to declared set or remove component capability",
        "confidence": "high",
    },
    "pii-requires-compliance-scope": {
        "field": "compliance_scope",
        "description": "Add compliance scope (e.g. GDPR or HIPAA) covering PII capabilities",
        "confidence": "medium",
    },
    "holonomy-ceiling-violated": {
        "field": "components",
        "description": "Reduce component capability excess — align declared and component capability sets",
        "confidence": "medium",
    },
}


def propose_remediation(
    escalation: dict[str, Any],
    kg_dir: Path,
) -> RemediationProposal:
    """Produce a structured remediation proposal from an escalation record.

    Examines the escalation's violation rules and the workload's current KG node
    to generate field-level change suggestions with a rationale and confidence.

    Args:
        escalation: An escalation record dict (from load_escalations or produced
                    by _execute_escalate). Must have workload_id and violations.
        kg_dir:     KG directory root (used to read the current workload node).

    Returns:
        RemediationProposal with proposed_changes, rationale, and confidence.
    """
    workload_id = escalation.get("workload_id", "unknown")
    violations = escalation.get("violations", [])
    rules = [v.get("rule", "") for v in violations]

    proposed_changes: list[dict[str, Any]] = []
    rationale_parts: list[str] = []
    confidences: list[str] = []

    # Load current workload state for context
    workload = _load_workload_node(kg_dir, workload_id)
    observed_regions = _observed_regions_from_placements(kg_dir, workload_id)

    seen_fields: set[str] = set()
    for rule in rules:
        info = _RULE_REMEDIATION.get(rule)
        if not info or info["field"] in seen_fields:
            continue
        seen_fields.add(info["field"])

        change: dict[str, Any] = {
            "field": info["field"],
            "description": info["description"],
            "rule": rule,
        }

        # Attach concrete suggestion when we have enough context
        if info["field"] == "allowed_regions":
            current = workload.get("allowed_regions", []) if workload else []
            change["current_value"] = current
            if observed_regions:
                change["suggested_value"] = sorted(set(current) | set(observed_regions))

        elif info["field"] == "compliance_scope":
            current = workload.get("compliance_scope", []) if workload else []
            change["current_value"] = current
            change["suggested_value"] = current or ["<add-compliance-scope>"]

        proposed_changes.append(change)
        rationale_parts.append(info["description"])
        confidences.append(info["confidence"])

    if not proposed_changes:
        proposed_changes.append({
            "field": "unknown",
            "description": "Manual review required — no automated suggestion available",
            "rule": rules[0] if rules else "unknown",
        })
        rationale_parts.append("No automated suggestion available for this violation pattern")
        confidences.append("low")

    overall_confidence = (
        "high" if all(c == "high" for c in confidences)
        else "low" if all(c == "low" for c in confidences)
        else "medium"
    )

    return RemediationProposal(
        workload_id=workload_id,
        proposed_changes=proposed_changes,
        rationale="; ".join(rationale_parts),
        confidence=overall_confidence,
    )


def _load_workload_node(kg_dir: Path, workload_id: str) -> dict[str, Any] | None:
    workload_dir = kg_dir / "workloads"
    if not workload_dir.exists():
        return None
    slug = workload_id.replace("workload:", "").replace(":", "-")
    for path in workload_dir.glob("*.json"):
        try:
            node = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if node.get("@id") == workload_id or slug in path.stem:
            return node
    return None


def load_escalations(kg_dir: Path) -> list[dict[str, Any]]:
    """Load all escalation records from _fabric/escalations.jsonl."""
    escalation_file = kg_dir / "_fabric" / "escalations.jsonl"
    if not escalation_file.exists():
        return []
    records = []
    for line in escalation_file.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return records
