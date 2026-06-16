# CALM Forge — Architecture Decisions

This document distills the key architectural decisions that shaped CALM Forge. Each decision is recorded with its rationale and consequences.

---

## 1. The Pipeline Architecture — CALM Forge as MCP Server

CALM Forge is structured as three composable layers:

```
Human Intent (natural language)
    → Interviewer Agent  (captures intent, produces CALM spec)
        → CALM Forge MCP Server  (generates governed artifacts)
            → Product MCP Servers  (executes against TFE, Vault, Consul)
```

**Why this shape:** HashiCorp's Infragraph team ships MCP servers for TFE, Vault, Consul, and Vault Radar. CALM Forge does not duplicate that execution layer — it wraps CALM Forge as an MCP server that generates artifacts and delegates execution to product MCP servers. The separation of concerns is: intent capture, artifact generation, infrastructure execution.

**MCP tool contract:** `calm-forge/generate`, `calm-forge/validate`, `calm-forge/interview`, `calm-forge/kg-*` are the stable public API. The package naming convention `calm.violations` and `data.calm.violations` for OPA is a public contract from v0.5.0 onward.

**Key consequence:** The interviewer agent is the hardest and most valuable piece. It requires FSI domain knowledge baked into the question flow. The execution layer (ILM/SLM) is solved; the intent capture and architecture translation are the differentiator.

---

## 2. The Knowledge Graph — Intent Contract Format

CALM Forge compiles architecture intent to a typed Knowledge Graph before generating any artifacts. The KG is the intermediate representation — all output formats (Terraform, Vault, Ansible, OPA, Backstage, DCM) are compiled from it.

**Storage format:** JSON-LD. Fields are typed concepts with semantic context, not plain strings. Two systems using the same `@context` can compare graphs without a translation layer. The path to a graph database is an upgrade, not a rewrite.

**Node vocabulary (13 types):** `Workload`, `Agent`, `Capability`, `ExecutionEnvironment`, `Placement`, `Policy`, `Compliance`, `Role`, `Principal`, `Resource`, `ADR`, `Domain`, `Ticket`.

**`Workload` vs `Agent` — peer types, not subtypes:** A `Workload` is a design-time intent contract (declared capabilities, compliance scope, policies). An `Agent` is a runtime principal (SPIFFE ID, DPoP key, attestation bundle, TTL). Neither is a subtype of the other — subtype framing would require nulling fields on both sides. The relationship is generative: a Workload *becomes* an Agent at deployment boundary, linked by a `manifests_as` edge that carries `capabilities_granted`. The invariant enforced at this boundary: `capabilities_granted ⊆ declared_capabilities`. Runtime execution can never exceed design intent.

**Edge vocabulary (12 types):** `requires_capability`, `has_capability`, `manifests_as`, `satisfied_by`, `placed_on`, `enforced_by`, `prohibited_after`, `authored_under`, `satisfies`, `version_of`, `depends_on`, `delegates_to`.

**`delegates_to` carries bounded depth and intent scope.** Delegation chains are graph constraints, not ad-hoc policy strings. Delegation depth is enforceable because it is encoded in the graph schema.

**Drift state lives on `Placement`, not `Workload`.** `Workload` is the intent contract — it does not change when reality drifts. `Placement` is the resolved binding and carries `drift_state`, `observed_capabilities`, and `placed_at`. The diff engine's core operation: `Placement.observed_capabilities` vs `Workload.declared_capabilities`.

**Round-trip constraint:** Every `Workload` node must reconstruct to CALM JSON without information loss. This is validated by the test suite. A schema change that breaks round-trip is a breaking change requiring a `@context` version bump.

---

## 3. OPA Integration — Policy as Compiled Rego

OPA is integrated via CLI subprocess, not embedded library. The interface is narrow enough to swap to an OPA REST sidecar if evaluation latency becomes a constraint at scale. Graceful degradation: if `opa` binary is not found, validation skips with a warning rather than failing hard.

**Bundle architecture:** Three bundle sources in priority order — caller-supplied path/URL, `CALM_FORGE_OPA_BUNDLE` env var, built-in bundle at `opa_policies/`. Hot-reload via background watcher on local bundle mtime.

**KG-predicate-driven policy:** Policy conditions in the KG are typed predicates (`placement_constraint`, `capability_requirement`, `isolation_requirement`, `compliance_boundary`, `lifecycle_condition`, `drift_threshold`, `capability_ceiling`). These compile to Rego rule templates rather than being hand-authored strings. The authoring surface is semantic; the enforcement is compiled.

**Two evaluation passes:** Pre-generation gate validates CALM spec + decorator before the conversion engine runs (`calm.violations`). Post-placement drift check validates a `Placement` node against the Workload's Policy predicates on a schedule (`calm.drift`). Same bundle, different packages, different input shapes.

**Identity router integration path:** Policy predicate nodes compile to the same Rego rules that a compliant identity router or token exchange service loads at startup. One policy graph, two evaluation contexts — design-time gate and runtime enforcement. This is the architectural consequence of the KG being shared substrate between CALM Forge (design-time) and the runtime enforcement layer.

---

## 4. The Semantic Graph as Shared Substrate

The KG defined above is not just a CALM Forge artifact — it is shared substrate between design-time authoring (CALM Forge) and runtime enforcement (an identity router or compliant token exchange service with proof of possession, delegation depth, and intent verification).

Builders author in CALM DSL at design time. The identity router enforces policy at runtime. Both operate on the same node and edge schema. The compilation targets from the Semantic Graph are:

| Target | Purpose |
|---|---|
| Terraform HCL | Infrastructure provisioning |
| Vault policies | Secrets and dynamic credentials |
| Sentinel policy | HashiCorp policy-as-code gate |
| OPA Rego bundle | Runtime policy evaluation |
| Backstage catalog | Human-readable architecture catalog |
| DCM application config | Red Hat deployment context |

---

## 5. Geometric Validation — ManifoldEngine

The `InvariantEngine` protocol makes the validation computation layer injectable. The invariant logic (what is checked) is decoupled from the computation engine (how it is checked).

```python
class InvariantEngine(Protocol):
    def validate(self, graph: dict) -> list[dict]: ...
```

Two implementations ship:

**`OPAEngine`** (default): calls `check_graph_invariants(graph)` for pure-Python semantic rules, optionally calls `opa_gate.validate_intent` for Rego policy evaluation.

**`ManifoldEngine`**: a self-contained pure-Python holonomy check — no external SDK. The geometric framing is: meaning lives on a manifold, context-dependent transformations are parallel transport, inconsistency shows up as non-zero holonomy (a semantic "twist"). The implementation is tractable:

1. **Section excess** — a component claims a capability outside the workload's declared set  
   `curvature += len(excess) / max(len(declared), 1)`

2. **Gluing violations** — a `requires_capability` edge points to a capability the component's own section doesn't have  
   `curvature += 0.5` per violation

3. **Compliance drift** — regulated scope without region constraint, or PII capabilities without compliance scope  
   `curvature += 0.5` (region) or `+0.25` (compliance)

`curvature = 0` is holonomy = 0: the architecture is globally coherent. `curvature > 0` is a geometric measure of how far off it is, not just a binary pass/fail.

The curvature score is recorded per workload over time in `_fabric/curvature-history.jsonl`. Linear regression over a window produces a trend: `improving`, `stable`, `degrading`, or `insufficient-data`. This is the operational signal for the drift loop.

---

## Key Invariants

These invariants run through every design decision and are enforced at the code level:

1. **`capabilities_granted ⊆ declared_capabilities`** — runtime can never exceed design intent. Enforced at the `manifests_as` boundary by OPA and by ManifoldEngine section excess check.

2. **Drift state on `Placement`, not `Workload`** — the intent contract is immutable; drift is a property of a specific deployment.

3. **Round-trip fidelity** — CALM JSON → KG nodes → CALM JSON′ must be lossless.

4. **Policy provenance** — every Policy node carries `provenance: authored | reconstructed | inferred`. A `reconstructed` policy diverging from observed state is a schema gap, not a compliance violation.

5. **`holonomy = 0` as the coherence target** — curvature is measured, not estimated. Self-correction means finding the nearest stable section on the manifold.
