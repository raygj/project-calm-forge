# CALM Forge

[![CI](https://github.com/raygj/project-calm-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/raygj/project-calm-forge/actions/workflows/ci.yml)

Architecture intent to execution fabric — continuously.

## What This Is

This project is an architectural prototype for ideation and concept exploration. It is not tested or intended for production use as-is. The patterns and approaches demonstrated here inform workflow and product concepts, and standards conversations where relevant.

CALM Forge closes the gap between declared architecture intent and what is actually
running in your execution fabric. You author a workload spec in CALM (Common
Architecture Language Model), and CALM Forge compiles it to governed artifacts
(Terraform HCL, Terraform/Sentinel policy, Vault policies, Ansible inventory,
OPA Rego, Backstage catalog, DCM application config), deploys them via GitOps,
observes deployment completion, evaluates drift, reconciles violations, and
proposes remediation — in a loop.

The loop is closed. Intent declared is intent enforced.

## Quick Start

```bash
pip install calm-forge
calm-forge --help
```
## Integrations

CALM Forge sits upstream of execution engines and consumes selected outputs back as intake sources. Per-product integration notes — role, generated artifacts, intake shape, Day 2 loop — live in [`docs/integrations/`](./docs/integrations/):

- [Terraform](./docs/integrations/terraform.md) — generated HCL + `.tfstate` intake
- [Vault](./docs/integrations/vault.md) — generated policy + agentic runtime closed loop
- [Ansible](./docs/integrations/ansible.md) — generated inventory + AAP event intake
- [Backstage / DevHub](./docs/integrations/backstage.md) — generated catalog YAML + catalog intake (round-trip)
- [Concert](./docs/integrations/concert.md) — posture artifact emit + risk-decision intake

CALM Forge does not replace any of these products. Each retains its existing role as execution engine, policy authority, or operator surface; CALM Forge adds the typed semantic layer above them.

## Usage

```bash
# Generate governed artifacts from a CALM spec
calm-forge generate --calm instantiation.json --decorator decorator.json \
  --catalog catalog.json --output-dir ./output --full

# Validate architecture intent (semantic + OPA)
calm-forge validate-intent --architecture instantiation.json

# Seed the knowledge graph from existing infrastructure
calm-forge kg bootstrap --kg-dir /tmp/kg \
  --acm --acm-fixture examples/acm-inventory.json \
  --ansible --ansible-fixture examples/aap-jobs.json

# Run the MCP server (for agent tool-calling)
calm-forge mcp
```

## Architecture

```
Intent (CALM spec)
    │
    ▼
[interview]  →  Workload KG node
[validate-intent]  →  OPAEngine + ManifoldEngine (curvature score)
[generate]  →  HCL, Sentinel/tfpolicy, Vault, Ansible, DCM, Backstage
[deploy]  →  GitOps target  →  DeploymentRequest KG node
[observe]  →  deployment completion  →  DeploymentStatus KG node
[drift-check]  →  curvature-history.jsonl
[reconcile]  →  redeploy | update_kg | escalate + RemediationProposal
[interview]  ←  pre-loaded from proposal (closed loop)
```

Multi-environment federation, KG export/import bundles, and Backstage/Terraform
round-trip intake are included.

## The Knowledge Graph Planes

Intent is not one flat model. CALM Forge partitions the knowledge graph into typed
planes, each with its own declared side and its own intake adapters:

| Plane | What it holds | Intake adapters |
|---|---|---|
| `architecture` | CALM instantiation + decorator — the placement intent | ACM, Ansible AAP, HCP Terraform, Backstage |
| `controls` | Compliance controls stated as OSCAL | `intake-oscal` |
| `business_intent` | TOSCA service templates and policy types | `intake-tosca` |
| `data_management` | ODCS data contracts, observed lineage | `intake-odcs`, `intake-openlineage` |
| `supply_chain` | Archetype suites, CycloneDX vendor drops | `intake-archetypes`, `registry intake` |
| `requirements` | Generative intent, before it is architecture | `intake-requirements` |

Planes are committed by ADR, never by configuration. Nodes carry a plane only when
they are *authored*; reference nodes do not. Edges never store a plane at all — an
edge's plane is the plane of its authoring node, so a controls-plane fact *about* an
architecture-plane object stays unambiguous.

Drift is evaluated per plane, and cross-plane drift catches the cases where two
planes disagree about the same subject.

## Policy Generation

Policy is a compilation target, not a hand-written artifact. The same CALM intent
projects into two policy frameworks, selected with `--policy-framework`:

```bash
calm-forge generate --calm instantiation.json --decorator decorator.json \
  --catalog catalog.json --output-dir ./output --full \
  --policy-framework sentinel     # default
  #                  tfpolicy     # Terraform Policy [BETA upstream]
  #                  all          # emit both
```

`tfpolicy` writes `policies.policy.hcl` alongside `policies.policytest.hcl` — one
generated test per emitted policy, runnable with `tfpolicy test`. Both carry a
`[BETA]` marker, because Terraform Policy is beta upstream at HashiCorp and its
syntax may change before GA.

**Parity is by construction, not by review.** A single function, `predicates_for(metadata)`,
names which predicates a given CALM intent enforces. Both emitters and the parity
test derive from it, so Sentinel and tfpolicy enforce the same predicate set for the
same intent — or `tests/test_policy_parity.py` fails across every example carrying a
CALM instantiation. Neither projection is authoritative; both answer to the intent.

OPA Rego is emitted separately, through `validate-intent` rather than `generate`.

## Attested Policy Passports

A passport is a signed, per-edge claim about what a relationship is allowed to do —
Ed25519-signed, schema-conformant, and independently verifiable. The reverse diff
compares observed flows against passport claims, so the graph answers "is this edge
still entitled to exist?" rather than "was this edge declared once?".

```bash
# Emit a signed passport per relationship edge
calm-forge passport emit --calm instantiation.json --output-dir ./passports

# Verify signature + schema conformance
calm-forge passport verify ./passports/<edge-hash>.passport.json

# Reverse diff: observed flows vs claims. Reports SHADOW FLOW (traffic with
# no claim) and CONTRACTION CANDIDATE (a claim nothing is using).
calm-forge passport diff --passports ./passports --flows observed-flows.json

# Contraction: revoke every candidate the diff found; renew what is lapsing
calm-forge passport revoke --passports ./passports --from-diff ./diff.json
calm-forge passport renew  --passports ./passports --within-days 7
```

Signing identity is a locally generated Ed25519 key by default. With `--spire`,
`passport emit` signs with a live SPIRE X509-SVID from the Workload API, and the
issuer becomes the SVID's real SPIFFE id.

## The Gate

The Gate runs an artifact against its archetype checks and emits a signed
in-toto/SLSA verification summary attestation (VSA). Admission verifies the VSA
chain before an artifact is allowed forward.

```bash
# Run the checks; PASSED iff every check passes. FAILED writes a quarantine
# record and exits non-zero — fail closed for a promotion pipeline.
calm-forge gate run --spec examples/gate/payments-api-gate-spec.json \
  --output-dir ./out --key gate.pem

# Two signatures, one subject: the automated gate and the accountable human.
calm-forge gate countersign --envelope ./out/vsa.slsa.dsse.json \
  --anchor-ref kg://anchor/<id> --output ./out/vsa.countersigned.json

# Tier 3 admission: verify both signatures and enforce the digest pin.
calm-forge gate admit --envelope ./out/vsa.countersigned.json \
  --pull registry.example.com/payments-api@sha256:<digest>
```

## Semantic Conventions

The OpenTelemetry semantic-convention registry for CALM Forge lives in
[`semconv/`](./semconv/), checked and code-generated with
[Weaver](https://github.com/open-telemetry/weaver). `src/calm_forge/semconv.py` is
generated from the registry — CI regenerates it and fails on any diff, so the
emitted attribute names and the registry cannot drift apart.

## License

Apache 2.0 — see LICENSE.

## References

- [CALM — Common Architecture Language Model](https://calm.finos.org) — open standard for describing software architecture as machine-readable JSON, maintained by FINOS
- [DCM — Deployment Configuration Manager](https://github.com/dcm-project) — application-centric deployment model for hybrid cloud
- [Terraform Stacks](https://www.hashicorp.com/en/blog/terraform-stacks-explained) — HashiCorp's model for managing related Terraform configurations as a coordinated unit
- [Ansible Event-Driven Automation](https://www.redhat.com/en/technologies/management/ansible/event-driven-ansible) — Red Hat's event-driven automation layer for Ansible
