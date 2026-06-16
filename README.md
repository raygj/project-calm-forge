# CALM Forge

[![CI](https://github.com/raygj/project-calm-forge/actions/workflows/ci.yml/badge.svg)](https://github.com/raygj/project-calm-forge/actions/workflows/ci.yml)

Architecture intent to execution fabric — continuously.

## What This Is

This project is an architectural prototype for ideation and concept exploration. It is not tested or intended for production use as-is. The patterns and approaches demonstrated here inform workflow and product concepts, and standards conversations where relevant.

CALM Forge closes the gap between declared architecture intent and what is actually
running in your execution fabric. You author a workload spec in CALM (Common
Architecture Language Model), and CALM Forge compiles it to governed artifacts
(Terraform HCL, Vault policies, Ansible inventory, OPA Rego, Backstage catalog,
DCM application config), deploys them via GitOps, observes deployment completion,
evaluates drift, reconciles violations, and proposes remediation — in a loop.

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
[generate]  →  HCL, Vault, Ansible, DCM, Backstage
[deploy]  →  GitOps target  →  DeploymentRequest KG node
[observe]  →  deployment completion  →  DeploymentStatus KG node
[drift-check]  →  curvature-history.jsonl
[reconcile]  →  redeploy | update_kg | escalate + RemediationProposal
[interview]  ←  pre-loaded from proposal (closed loop)
```

Multi-environment federation, KG export/import bundles, and Backstage/Terraform
round-trip intake are included.

## License

Apache 2.0 — see LICENSE.

## References

- [CALM — Common Architecture Language Model](https://calm.finos.org) — open standard for describing software architecture as machine-readable JSON, maintained by FINOS
- [DCM — Deployment Configuration Manager](https://github.com/dcm-project) — application-centric deployment model for hybrid cloud
- [Terraform Stacks](https://www.hashicorp.com/en/blog/terraform-stacks-explained) — HashiCorp's model for managing related Terraform configurations as a coordinated unit
- [Ansible Event-Driven Automation](https://www.redhat.com/en/technologies/management/ansible/event-driven-ansible) — Red Hat's event-driven automation layer for Ansible
