# Integrations

CALM Forge is the authoring substrate. The CALM spec is the contract. Governed artifacts flow out to a small set of execution and observation engines, and selected outputs flow back in as intake sources to keep the knowledge graph current.

This directory documents how CALM Forge fits with each integration target. One file per product. Each note covers the role CALM Forge plays in the integration, what it produces, what it consumes, and what the Day 2 loop looks like.

| Integration | File | Role |
|---|---|---|
| HashiCorp Terraform | [terraform.md](./terraform.md) | Generated artifact + intake source (`.tfstate`) |
| HashiCorp Vault | [vault.md](./vault.md) | Generated policy + dynamic credential authoring |
| Red Hat Ansible | [ansible.md](./ansible.md) | Generated inventory + intake from AAP events |
| Backstage / DevHub | [backstage.md](./backstage.md) | Generated catalog YAML + intake from catalog |
| IBM Concert | [concert.md](./concert.md) | Posture consumer + risk-decision intake |

## What CALM Forge is not

CALM Forge does not replace any of these products. It does not own state, schedule deployments, enforce runtime policy, or observe infrastructure directly. Each execution engine retains its existing role. CALM Forge adds a typed semantic layer above them — declared intent expressed once, compiled to each engine's native artifact, with the knowledge graph as the cross-engine memory.

## What this is not (yet)

These notes describe the integration shape as implemented in the prototype. Tests pass against fixtures. The integrations have not been exercised end-to-end against live infrastructure. Treat each note as an architectural description, not a deployment guide.
