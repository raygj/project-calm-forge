# AGENTS.md — CALM Forge Agent Bootstrap Guide

CALM Forge exposes its full pipeline as MCP (Model Context Protocol) tools. This guide documents every tool, their expected inputs and outputs, and the recommended call sequences for common tasks.

## Starting the MCP Server

```bash
calm-forge mcp
```

The server speaks stdio transport. All tool names are prefixed `calm-forge/`.

---

## Pipeline Phases

```
Intake → Author → Enforce → Generate → Observe → Close
```

| Phase | Tools |
|-------|-------|
| **Intake** (populate KG from existing infrastructure) | `kg-bootstrap`, `intake-acm`, `intake-ansible`, `intake-tfe`, `intake-concert` |
| **Author** (declare workload intent) | `interview`, `patterns` |
| **Enforce** (validate + diff) | `validate`, `validate-intent`, `diff` |
| **Generate** (produce governed artifacts) | `generate`, `backstage`, `catalog` |
| **Observe** (inspect live fabric) | `kg-status`, `kg-query`, `fabric-state`, `kg-federate-status`, `kg-federate-query` |
| **Close** (reconcile drift) | `reconcile`, `kg-export`, `kg-import` |

---

## Tool Reference

### `calm-forge/kg-status`

Check the health of a live KG before doing anything else.

```json
{
  "kg_dir": "/path/to/kg",
  "namespace": null
}
```

Returns: node counts, drift status breakdown (`CLEAN` / `VIOLATION` / `UNEVALUATED` / `NO_PLACEMENTS`), edge counts, last evaluated timestamp.

**Use this first.** If the KG is empty, run intake. If drift is stale, re-evaluate before generating artifacts.

---

### `calm-forge/kg-bootstrap`

Populate a fresh KG from multiple connected sources in one pass. Each source failure is isolated — others continue.

```json
{
  "kg_dir": "/path/to/kg",
  "sources": ["acm", "ansible", "concert"],
  "acm_fixture_path": "/path/to/acm-inventory.json",
  "ansible_fixture_path": "/path/to/aap-jobs.json",
  "concert_fixture_path": "/path/to/concert-risks.json",
  "concert_live": false,
  "namespace": null,
  "backstage_path": null,
  "terraform_state_paths": []
}
```

Sources: `"acm"`, `"ansible"`, `"concert"`, `"backstage"`, `"terraform"`

Returns: `{ sources_run, nodes_written, errors, total_nodes }`

---

### `calm-forge/intake-acm`

Populate `ExecutionEnvironment` nodes from an ACM cluster inventory.

```json
{
  "fixture": { "clusters": [...] },
  "output_dir": "/path/to/kg"
}
```

Returns: `{ environments: [{id, region, labels, capabilities}], count, written }`

See `examples/acm-inventory.json` for the fixture shape.

---

### `calm-forge/intake-ansible`

Populate `Placement` nodes from AAP job state. Pass the `environments` output from `intake-acm` to resolve cluster → environment IDs.

```json
{
  "fixture": { "jobs": [...] },
  "environments": [ /* output of intake-acm */ ],
  "output_dir": "/path/to/kg"
}
```

Returns: `{ placements: [{id, workload_id, environment_id, region, namespace}], count, written }`

---

### `calm-forge/intake-tfe`

Populate `Workload` nodes (tagged `provenance: reconstructed`) from HCP Terraform workspace metadata. These represent workloads inferred from infrastructure state — they are flagged `review_required: true` and should be promoted to authored intent via `interview`.

```json
{
  "fixture": { "workspaces": [...] },
  "output_dir": "/path/to/kg"
}
```

Returns: `{ workloads: [{id, name, tags, resource_count, review_required, provenance}], count, written }`

---

### `calm-forge/intake-concert`

Populate `PlacementPolicy` nodes from a Concert risk export. Policies with `blocked_environments` block deployment via `validate-intent`.

```json
{
  "fixture": { "applications": [...] },
  "output_dir": "/path/to/kg",
  "namespace": null,
  "live": false,
  "app_names": null
}
```

For live Concert API: set `live: true`. Requires `CALM_FORGE_CONCERT_URL` and `CALM_FORGE_CONCERT_API_KEY` env vars.

Returns: `{ policies: [{id, workload_id, risk_score, risk_level, blocked_environments, constraint}], count, blocking, written }`

---

### `calm-forge/patterns`

List known workload architecture patterns from the embedded knowledge graph.

```json
{
  "filter_text": "pci"
}
```

Returns: `{ patterns: [{name, purpose, tags, compliance_scope, capabilities_required}], total }`

Use this before `interview` to check whether a reference pattern covers the use case.

---

### `calm-forge/interview`

Author a new `Workload` KG node from a structured spec. Produces typed `requires_capability` and `authored_in` edges.

```json
{
  "spec": {
    "name": "payments-api",
    "purpose": "Real-time payment processing",
    "owner": "platform-engineering",
    "components": [
      { "name": "api-gateway", "capabilities": ["http_read", "http_write"] },
      { "name": "vault-consumer", "capabilities": ["vault_dynamic_creds"] }
    ],
    "compliance_scope": ["PCI-DSS-v4:req-3"],
    "allowed_regions": ["us-east-1", "eu-west-1"]
  },
  "output_dir": "/path/to/kg",
  "proposal": null,
  "kg_dir": null
}
```

When `proposal` is provided (from `reconcile` with `propose: true`), the spec is pre-populated from violation context:

```json
{
  "proposal": { /* RemediationProposal from reconcile */ },
  "kg_dir": "/path/to/kg",
  "output_dir": "/path/to/kg"
}
```

Returns: `{ node, summary: {id, components, declared_capabilities, requires_capability_edges, compliance_scope}, written }`

When `proposal` is provided, also returns `prefilled_fields` and `proposal_confidence`.

**Check `kg-status` first.** If a Workload with this name already exists, use `kg-query` to retrieve it rather than creating a duplicate.

---

### `calm-forge/validate`

Validate a CALM instantiation JSON for structural correctness.

```json
{
  "calm": { /* CALM instantiation dict */ }
}
```

Returns: `{ valid: bool, errors: [str] }`

---

### `calm-forge/validate-intent`

Validate CALM architecture intent against the OPA policy bundle. Catches compliance violations, concert-risk blocks, and capability ceiling violations before artifact generation.

```json
{
  "calm": { /* CALM instantiation dict */ },
  "decorator": { /* deployment decorator dict, optional */ }
}
```

Returns: `{ valid: bool, violations: [{rule, severity, message}] }`

Severity levels: `"error"` (blocks generation) and `"warning"` (informational).

If OPA is not installed, returns `valid: true` with a notice — install OPA for full enforcement.

---

### `calm-forge/diff`

Compute a structural diff between two CALM instantiation dicts.

```json
{
  "before": { /* CALM dict */ },
  "after":  { /* CALM dict */ }
}
```

Returns: added/removed/modified nodes and relationships, impact classification (`breaking` / `mutative` / `additive` / `none`), estimated Terraform operation counts, compliance-sensitive field changes, and a summary.

---

### `calm-forge/generate`

Generate governed artifacts from a CALM architecture + deployment decorator + module catalog.

```json
{
  "calm": { /* CALM instantiation dict */ },
  "decorator": { /* deployment decorator dict */ },
  "catalog": { /* module catalog dict */ },
  "full": false,
  "include_imports": false
}
```

Returns: `{ files: {filename: content}, file_count, attestation_sha, hcl_errors }`

Artifacts produced (depending on decorator config):
- Terraform HCL (Stacks-compatible)
- Vault policies
- OPA Rego bundle
- Ansible inventory
- Backstage catalog
- DCM application manifest

`attestation_sha` is a SHA-256 over all file contents — use for round-trip verification.

---

### `calm-forge/catalog`

Inspect a module catalog or retrieve catalog schema documentation.

```json
{ "catalog": { /* catalog dict or null for schema docs */ } }
```

Returns: `{ node_types, modules: [{node_type, default, variants, variant_count}], total, catalog_version, description }`

See `examples/fsi-3tier/catalog.json` for a reference catalog.

---

### `calm-forge/backstage`

Generate Backstage / Red Hat DevHub Software Catalog entities from a live KG.

```json
{
  "kg_dir": "/path/to/kg",
  "output_dir": "/path/to/catalog/output"
}
```

Returns: `{ entities: [{kind, apiVersion, metadata, spec}], count, resources, components, written }`

Entities use the `calm.io/` annotation namespace. Call `kg-status` first to verify the KG is populated.

---

### `calm-forge/kg-query`

Query the live KG with predicate filters and optional edge traversal.

```json
{
  "kg_dir": "/path/to/kg",
  "node_type": "Placement",
  "where": ["drift_state.status=violation", "region=us-east-1"],
  "follow": "manifests_as",
  "namespace": null
}
```

`node_type` accepts: `"Workload"`, `"Placement"`, `"ExecutionEnvironment"` (aliases: `"workload"`, `"placement"`, `"env"`).

`where` predicates use dot-path notation. Array fields use containment semantics: `"advertised_capabilities=confidential_compute"` matches any node where that value is in the array.

`follow` traverses a typed edge from each matched node. Currently supported: `"manifests_as"`.

Returns: `{ results: [node], count }`

---

### `calm-forge/fabric-state`

Return a full fabric state snapshot — all Workloads, Placements (with drift state and capability grants), ExecutionEnvironments, and PlacementPolicy alerts.

```json
{
  "kg_dir": "/path/to/kg",
  "namespace": null
}
```

Returns the complete fabric picture in one call. Use `kg-query` for targeted queries against large KGs.

---

### `calm-forge/kg-federate-status`

Return a federated status summary across multiple KG roots.

```json
{
  "roots": ["/kg/region-a", "/kg/region-b"],
  "namespace": null
}
```

Returns merged totals plus per-member breakdowns. Read-only.

---

### `calm-forge/kg-federate-query`

Query across multiple KG roots and return deduplicated results. Nodes with the same `@id` from multiple roots are deduplicated (last root wins). Each result node gains a `_federation_root` key.

```json
{
  "roots": ["/kg/region-a", "/kg/region-b"],
  "node_type": "Workload",
  "where": { "drift_state.status": "violation" }
}
```

Returns: list of matched nodes.

---

### `calm-forge/reconcile`

Run the drift reconciliation loop. Reads `fabric-state.json` (or builds a live feed), detects violations, and proposes or executes remediation.

```json
{
  "kg_dir": "/path/to/kg",
  "dry_run": true,
  "propose": false
}
```

Actions:
- `redeploy` — re-emit a `DeploymentRequest` for capability-ceiling violations with a pending deployment
- `update_kg` — correct the Workload's `allowed_regions` to match observed reality when Concert does not block the region
- `escalate` — write a structured record to `_fabric/escalations.jsonl` for human review

When `propose: true`, escalation records include a `RemediationProposal` with field-level change suggestions and confidence scores. Pass the proposal to `interview` to author an updated Workload node.

Returns: `{ proposals: [ReconciliationProposal], executed: [workload_id], dry_run }`

---

### `calm-forge/import`

Import existing HCP Terraform workspaces into CALM format for Stacks migration.

```json
{
  "tfe_host": "app.terraform.io",
  "tfe_token": "<token>",
  "org": "my-org",
  "workspace_filter": "payments",
  "no_tls_verify": false
}
```

Returns: `{ files: {filename: content}, file_count }`

Produces CALM JSON, Terraform import blocks, and a migration plan.

---

### `calm-forge/kg-export`

Export a KG directory to a portable bundle zip.

```json
{
  "kg_dir": "/path/to/kg",
  "output_path": "/path/to/kg-bundle.zip"
}
```

Returns: `{ bundle_path }`

---

### `calm-forge/kg-import`

Import a KG bundle into a target directory.

```json
{
  "bundle_path": "/path/to/kg-bundle.zip",
  "target_kg_dir": "/path/to/target-kg",
  "overwrite": false
}
```

Returns: `{ imported, skipped, conflicts }`

---

### `calm-forge/agent-run`

Run the full autonomous pipeline in one call. Executes in order: `kg-status` → `kg-query` (duplicate check) → `interview` → `validate-intent` → `generate` → `backstage`. Idempotent — safe to re-run with the same spec.

```json
{
  "kg_dir": "/path/to/kg",
  "spec": {
    "name": "payments-api",
    "purpose": "...",
    "owner": "...",
    "components": [...],
    "compliance_scope": [...],
    "allowed_regions": [...]
  },
  "calm": null,
  "decorator": { /* required for generate step */ },
  "catalog": { /* required for generate step */ },
  "output_dir": "/path/to/artifacts",
  "backstage_output_dir": "/path/to/catalog",
  "gitops_target": "/path/to/gitops"
}
```

Returns: `{ status, workload_id, workload_authored, violations, artifacts, catalog_entities, deployment_request_id, deployment_target, steps }`

`status` is `"success"`, `"blocked"` (validate-intent found errors), or `"error"`.

---

## Common Call Sequences

### Greenfield — New Workload

```
1. kg-status           → verify KG is ready
2. patterns            → find a reference pattern (optional)
3. kg-query (Workload) → confirm name doesn't already exist
4. interview           → author Workload node
5. validate-intent     → check policies
6. generate            → produce artifacts
7. backstage           → update catalog
```

Or collapse 3–7 into a single `agent-run` call.

### Brownfield — Existing Infrastructure

```
1. kg-bootstrap        → seed KG from acm + ansible + tfe + concert
2. kg-status           → verify nodes written, check drift
3. kg-query (Workload, where review_required=true)
                       → list reconstructed workloads needing promotion
4. interview           → promote each reconstructed workload to authored intent
5. validate-intent     → check compliance
```

### Drift Remediation

```
1. fabric-state        → get current drift picture
2. reconcile (dry_run=true, propose=true)
                       → review proposed actions and remediation proposals
3. interview           → if escalated, use the RemediationProposal to author an update
4. reconcile (dry_run=false)
                       → execute redeploy / update_kg actions
```

### Multi-Region Federation

```
1. kg-federate-status  → aggregate drift status across all regions
2. kg-federate-query   → find violations across the federation
3. reconcile           → per-region KG dirs
```

---

## KG Node Types

| Type | Directory | Description |
|------|-----------|-------------|
| `Workload` | `workloads/` | Declared service intent with capabilities and policies |
| `Placement` | `placements/` | Observed deployment of a Workload in an ExecutionEnvironment |
| `ExecutionEnvironment` | `environments/` | Target cluster or environment with advertised capabilities |
| `PlacementPolicy` | `policies/` | Concert risk policy controlling where a Workload may deploy |

Nodes are JSON-LD files. The graph lives on disk — no external database required.

## Reference Examples

| File | Contents |
|------|----------|
| `examples/fsi-3tier/catalog.json` | Module catalog for a 3-tier FSI stack |
| `examples/fsi-3tier/calm.json` | CALM instantiation for the same stack |
| `examples/acm-inventory.json` | ACM cluster fixture |
| `examples/aap-jobs.json` | Ansible/AAP job fixture |
| `examples/tfe-workspaces.json` | HCP Terraform workspace fixture |
