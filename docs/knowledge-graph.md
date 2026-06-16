# CALM Forge Knowledge Graph

The knowledge graph is CALM Forge's record of the world. It bridges declared intent (CALM specs) with observed reality (what's actually running) and is the substrate for drift detection, capability-based placement, and Day 2 governance.

---

## Two Distinct Things Called "The KG"

### 1. Reference Patterns (`src/calm_forge/knowledge_graph/`)

Authored `Workload` nodes in JSON-LD. These are the authoritative intent contracts — they carry policies, capability declarations, compliance scope, and typed predicate edges. They ship with the package and serve two purposes:

- **`calm-forge mcp` → `calm-forge/patterns` tool** — agents see these patterns and use them to drive generation
- **`calm-forge compile-policies`** — compiles Policy predicate nodes into the OPA bundle (`calm_violations.rego`, `calm_drift.rego`)

Current patterns:

| File | Purpose |
|------|---------|
| `3-tier-pci.json` | 3-tier PCI DSS v4 payments reference |
| `fraud-detection-pipeline.json` | Capability-based placement, confidential compute, anti-data-gravity |
| `brownfield-mcp-intake.json` | Brownfield MCP intake reference |
| `event-driven.json` | Event-driven architecture reference |
| `single-service.json` | Minimal single-service baseline |

### 2. Live KG (a directory of JSON-LD files)

Written by intake commands. After running `intake-acm`, `intake-ansible`, and `intake-tfe`, you get:

```
<kg-dir>/
├── environments/          ExecutionEnvironment nodes  (from ACM)
├── placements/            Placement nodes             (from AAP, drift_state written back)
├── workloads/             Workload nodes              (from TFE, provenance:reconstructed)
└── drift-events.json      JSONL event log             (from calm-forge drift --emit-events)
```

---

## Node Types

### ExecutionEnvironment

Populated by `intake-acm`. Represents a cluster or substrate that can host workloads.

```json
{
  "@type": "ExecutionEnvironment",
  "@id": "env:acm:prod-east-ocp-01",
  "provider_type": "openshift",
  "region": "us-east-1",
  "substrate": "x86",
  "labels": {"environment": "prod", "compliance": "pci"},
  "advertised_capabilities": ["http_read", "vault_dynamic_creds", "encryption_at_rest"],
  "status": "ready",
  "_provenance": {"authored_by": "calm-forge/intake-acm", ...}
}
```

Key fields: `advertised_capabilities` (matched against `required-capabilities` in CALM specs), `status` (`ready` / `degraded` / `unknown`), `labels`.

### Placement

Populated by `intake-ansible`. Represents an observed deployment — where a workload actually landed. Updated in-place by `calm-forge drift`.

```json
{
  "@type": "Placement",
  "@id": "placement:pci-multi-region-payments:prod-east-ocp-01",
  "workload_id": "workload:pci-multi-region-payments",
  "environment_id": "env:acm:prod-east-ocp-01",
  "region": "us-east-1",
  "namespace": "payments-prod",
  "attestation_level": "software",
  "observed_capabilities": ["http_read", "vault_dynamic_creds"],
  "drift_state": {
    "last_evaluated": "2026-05-03T12:00:00Z",
    "status": "ok",
    "deviation_hours": null,
    "findings": []
  },
  "_provenance": {"authored_by": "calm-forge/intake-ansible", ...}
}
```

`drift_state.status` values: `pending_first_evaluation` → `ok` / `violation`.

### Workload

Populated by `intake-tfe`. Represents a workload inferred from HCP Terraform workspace metadata — not declared via CALM.

```json
{
  "@type": "Workload",
  "@id": "workload:pci-payments-prod-us-east-1",
  "name": "pci-payments-prod-us-east-1",
  "terraform_version": "1.7.4",
  "vcs_repo": "org/payments-infra",
  "tags": ["pci", "prod", "payments"],
  "resource_types": ["aws_eks_cluster", "aws_rds_cluster"],
  "resource_count": 3,
  "review_required": true,
  "_provenance": {
    "authored_by": "calm-forge/intake-tfe",
    "provenance": "reconstructed"
  }
}
```

`review_required: true` on all `reconstructed` nodes — these represent workloads that exist but haven't been expressed as CALM intent yet.

---

## Relationships

The live KG implies relationships through ID references rather than explicit edge files:

- `Placement.workload_id` → references a `Workload` or CALM-spec workload slug
- `Placement.environment_id` → references an `ExecutionEnvironment`
- `ExecutionEnvironment.advertised_capabilities` ↔ `CALM node.required-capabilities` → capability match for placement resolution

Reference patterns carry explicit typed edges (`requires_capability`, `enforced_by`, `authored_under`) in their `edges` array.

---

## Exploring the KG

### `calm-forge kg status` (available now)

High-level summary of what's in a live KG directory:

```bash
calm-forge kg status --kg-dir /tmp/pci-drift-kg
```

```
Knowledge Graph: /tmp/pci-drift-kg
───────────────────────────────────────────────
  ExecutionEnvironment   3   ready: 3
  Placement              3   ok: 2  pending_first_evaluation: 1
  Workload               2   reconstructed · review required: 2
───────────────────────────────────────────────
  Drift events           1   last: 2026-05-04T01:21:41Z
  Last evaluated         2026-05-04T01:21:41Z
  Status                 CLEAN
```

### Reference patterns via Python

```python
from calm_forge.kg_loader import load_summaries, load_patterns
import json

# Summaries (what the MCP patterns tool returns)
for s in load_summaries():
    print(s["name"], "—", s["purpose"][:60])
    print("  policies:", s["policy_count"], "predicate types:", s["predicate_types"])
    print("  capabilities required:", s["capabilities_required"])

# Full pattern
patterns = load_patterns()
fraud = next(p for p in patterns if "fraud" in p["name"])
for edge in fraud["edges"]:
    print(edge["@type"], edge["from"], "→", edge.get("to", ""))
```

### Ad-hoc shell exploration

```bash
# All node types in a KG dir
find /tmp/pci-drift-kg -name "*.json" ! -name "drift-events.json" \
  | xargs python3 -c "
import json, sys
for f in sys.argv[1:]:
    d = json.load(open(f))
    print(d['@type'].ljust(25), d['@id'])
" 2>/dev/null

# All placements and their drift status
for f in /tmp/pci-drift-kg/placements/*.json; do
  python3 -c "
import json
d = json.load(open('$f'))
print(d['@id'], '→', d['drift_state']['status'], '|', d['region'])
"
done

# Which environments advertise confidential_compute
for f in /tmp/pci-drift-kg/environments/*.json; do
  python3 -c "
import json
d = json.load(open('$f'))
if 'confidential_compute' in d.get('advertised_capabilities', []):
    print(d['@id'], d['region'])
"
done
```

---

## Roadmap

### `calm-forge kg status` ✓ (Phase 1)
High-level summary: node counts, drift status breakdown, last evaluated timestamp.

### `calm-forge kg query` (Phase 2)
Predicate filter across node types:
```bash
calm-forge kg query --kg-dir /tmp/kg --type Placement --where drift_state.status=violation
calm-forge kg query --kg-dir /tmp/kg --type ExecutionEnvironment --where advertised_capabilities=confidential_compute
```

### `calm-forge/kg-status` MCP tool (Phase 2)
Exposes KG state to agents so they can decide whether to run intake, trigger drift evaluation, or flag reconstructed workloads for human review before acting.

---

## Design Notes

**Why flat JSON-LD files?** Simple, versionable, grep-able. No graph database required. The directory structure *is* the schema — `environments/`, `placements/`, `workloads/` are the node type namespaces. Phase 2 may introduce an in-process graph index for traversal, but the files stay authoritative.

**Why `provenance: reconstructed`?** Workloads populated from TFE have never been expressed as CALM intent. They exist in the KG as evidence of reality, not as declarations of intent. Tagging them `reconstructed` keeps the distinction visible — the drift engine and OPA can treat them differently from authored Workload nodes.

**Why is `drift_state` written back to Placement nodes?** The KG becomes the live record of intent-vs-reality, not just a snapshot. Downstream tools (EDA, dashboards, OPA) read `drift_state` directly from the node rather than rerunning evaluation. The `--no-writeback` flag preserves read-only evaluation for audit scenarios.
