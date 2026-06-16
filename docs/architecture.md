# CALM Forge — Reference Implementation

> **Version:** 1.0 · **Date:** 2026-02-22 · **Status:** EXPERIMENTAL — Reference Code

---

## Purpose

The CALM Forge translates a CALM architecture instantiation (what the system should look like) and its deployment decorators (where it should land) into configuration files that provisioner/ILM control plane can execute. This is the bridge between architecture intent and infrastructure execution.

**This document contains working pseudocode and concrete examples. It is not production code. It demonstrates the translation is feasible and defines the integration contract.**

---

## The Translation Contract

```
INPUTS                              OUTPUTS
──────                              ───────
CALM Instantiation (JSON)     ───►  components.tfcomponent.hcl
CALM Deployment Decorator(s)  ───►  deployments.tfdeploy.hcl
Module Catalog (JSON)         ───►  providers.tfcomponent.hcl
Vault Policy Template         ───►  variables.tfcomponent.hcl
                                    vault-policy.hcl (generated)
                                    ansible-vars.yml (generated)
```

---

## Example: 3-Tier FSI Application

### Step 1: The CALM Pattern (What Good Looks Like)

This is authored by Platform Engineering — the golden path for a 3-tier FSI application.

```json
{
    "$schema": "https://calm.finos.org/release/1.2/meta/calm.json",
    "$id": "https://uhccp.internal/patterns/fsi-3tier-app.pattern.json",
    "title": "FSI 3-Tier Application Pattern",
    "description": "Standard 3-tier architecture for FSI workloads: web frontend, API service, database. Requires mTLS between tiers, encryption at rest, PCI-DSS compliant placement.",
    "properties": {
        "nodes": {
            "type": "array",
            "prefixItems": [
                {
                    "$ref": "https://calm.finos.org/release/1.2/meta/core.json#/defs/node",
                    "properties": {
                        "unique-id": { "const": "web-frontend" },
                        "node-type": { "const": "service" },
                        "name": { "const": "Web Frontend" },
                        "description": { "const": "Customer-facing web application" }
                    },
                    "required": ["unique-id", "node-type", "name"]
                },
                {
                    "$ref": "https://calm.finos.org/release/1.2/meta/core.json#/defs/node",
                    "properties": {
                        "unique-id": { "const": "api-service" },
                        "node-type": { "const": "service" },
                        "name": { "const": "API Service" },
                        "description": { "const": "Business logic and transaction processing" }
                    },
                    "required": ["unique-id", "node-type", "name"]
                },
                {
                    "$ref": "https://calm.finos.org/release/1.2/meta/core.json#/defs/node",
                    "properties": {
                        "unique-id": { "const": "database" },
                        "node-type": { "const": "database" },
                        "name": { "const": "Primary Database" }
                    },
                    "required": ["unique-id", "node-type", "name"]
                },
                {
                    "$ref": "https://calm.finos.org/release/1.2/meta/core.json#/defs/node",
                    "properties": {
                        "unique-id": { "const": "ocp-cluster" },
                        "node-type": { "const": "system" },
                        "name": { "const": "Target OCP Cluster" }
                    },
                    "required": ["unique-id", "node-type", "name"]
                }
            ],
            "minItems": 4,
            "maxItems": 4
        },
        "relationships": {
            "type": "array",
            "prefixItems": [
                {
                    "properties": {
                        "unique-id": { "const": "web-to-api" },
                        "relationship-type": {
                            "properties": {
                                "connects": {
                                    "properties": {
                                        "source": { "properties": { "node": { "const": "web-frontend" } } },
                                        "destination": { "properties": { "node": { "const": "api-service" } } }
                                    }
                                }
                            }
                        },
                        "protocol": { "const": "HTTPS" },
                        "authentication": { "const": "mTLS-vault-pki" }
                    }
                },
                {
                    "properties": {
                        "unique-id": { "const": "api-to-db" },
                        "relationship-type": {
                            "properties": {
                                "connects": {
                                    "properties": {
                                        "source": { "properties": { "node": { "const": "api-service" } } },
                                        "destination": { "properties": { "node": { "const": "database" } } }
                                    }
                                }
                            }
                        },
                        "protocol": { "const": "TLS" },
                        "authentication": { "const": "vault-dynamic-credentials" }
                    }
                },
                {
                    "properties": {
                        "unique-id": { "const": "deployed-on-ocp" },
                        "relationship-type": {
                            "properties": {
                                "deployed-in": {
                                    "properties": {
                                        "container": { "const": "ocp-cluster" },
                                        "nodes": {
                                            "const": ["web-frontend", "api-service", "database"]
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            ]
        },
        "metadata": {
            "properties": {
                "compliance-scope": { "enum": ["pci-dss", "sox", "general"] },
                "data-classification": { "enum": ["confidential", "internal", "public"] },
                "sla-tier": { "enum": ["platinum", "gold", "silver"] }
            },
            "required": ["compliance-scope", "data-classification", "sla-tier"]
        }
    },
    "required": ["nodes", "relationships", "metadata"]
}
```

### Step 2: The CALM Instantiation (A Concrete Request)

A developer (or agent) creates this — filling in the pattern with real values.

```json
{
    "$schema": "https://uhccp.internal/patterns/fsi-3tier-app.pattern.json",
    "$id": "https://uhccp.internal/architectures/payments-portal.architecture.json",
    "title": "Payments Portal — Production Architecture",
    "nodes": [
        {
            "unique-id": "web-frontend",
            "node-type": "service",
            "name": "Web Frontend",
            "description": "Customer-facing payments portal",
            "container-image": "registry.internal/payments/web:3.2.1",
            "replicas": 3,
            "cpu-request": "500m",
            "memory-request": "512Mi"
        },
        {
            "unique-id": "api-service",
            "node-type": "service",
            "name": "API Service",
            "description": "Payment processing API — PCI Zone 1",
            "container-image": "registry.internal/payments/api:3.2.1",
            "replicas": 3,
            "cpu-request": "1000m",
            "memory-request": "1Gi"
        },
        {
            "unique-id": "database",
            "node-type": "database",
            "name": "Primary Database",
            "description": "PostgreSQL — encrypted at rest, PCI cardholder data",
            "engine": "postgresql",
            "version": "15.4",
            "storage-class": "encrypted-ssd",
            "storage-size": "100Gi"
        },
        {
            "unique-id": "ocp-cluster",
            "node-type": "system",
            "name": "Target OCP Cluster",
            "description": "Resolved by Placement Engine"
        }
    ],
    "relationships": [
        {
            "unique-id": "web-to-api",
            "description": "Frontend calls API over HTTPS with mTLS",
            "relationship-type": {
                "connects": {
                    "source": { "node": "web-frontend", "interfaces": ["https-8443"] },
                    "destination": { "node": "api-service", "interfaces": ["https-8443"] }
                }
            },
            "protocol": "HTTPS",
            "authentication": "mTLS-vault-pki"
        },
        {
            "unique-id": "api-to-db",
            "description": "API connects to database with Vault dynamic credentials",
            "relationship-type": {
                "connects": {
                    "source": { "node": "api-service" },
                    "destination": { "node": "database", "interfaces": ["postgres-5432"] }
                }
            },
            "protocol": "TLS",
            "authentication": "vault-dynamic-credentials"
        },
        {
            "unique-id": "deployed-on-ocp",
            "description": "All components deployed on target OCP cluster",
            "relationship-type": {
                "deployed-in": {
                    "container": "ocp-cluster",
                    "nodes": ["web-frontend", "api-service", "database"]
                }
            }
        }
    ],
    "metadata": {
        "application-name": "payments-portal",
        "team": "payments-engineering",
        "cost-center": "CC-4521",
        "compliance-scope": "pci-dss",
        "data-classification": "confidential",
        "sla-tier": "platinum",
        "requestor": "vault:identity/oidc/jsmith",
        "request-timestamp": "2026-02-22T14:30:00Z"
    }
}
```

### Step 3: Placement Engine Output (Where It Lands)

The Placement Engine evaluates the instantiation and produces a deployment decorator. (See `../placement-engine/` for the decision logic.)

```json
{
    "$schema": "https://uhccp.internal/decorators/ocp-deployment.decorator.schema.json",
    "unique-id": "payments-portal-prod-placement-001",
    "type": "deployment",
    "target": ["payments-portal.architecture.json"],
    "applies-to": ["ocp-cluster"],
    "data": {
        "deployment-start-time": "2026-02-22T14:32:00Z",
        "deployment-status": "pending",
        "kubernetes": {
            "cluster": "prod-uksouth-ocp-01",
            "namespace": "payments-portal-prod",
            "helm-chart": "uhccp-3tier:1.4.0"
        },
        "cloud-provider": "azure",
        "region": "uksouth",
        "environment": "production",
        "placement-rationale-ref": "placement-rationale-payments-portal-prod-001.json"
    }
}
```

### Step 4: Module Catalog (The Mapping Table)

The module catalog maps CALM node types + metadata to pre-built Terraform modules. This is maintained by Platform Engineering.

```json
{
    "catalog-version": "1.0",
    "description": "CALM Forge Module Catalog — maps CALM node types to Terraform modules",
    "modules": {
        "service": {
            "default": "registry.terraform.io/calm-forge/ocp-service/v2.1.0",
            "variants": {
                "ocp-deployment": {
                    "source": "registry.terraform.io/calm-forge/ocp-deployment/v2.1.0",
                    "description": "Standard OCP Deployment with Service, Ingress, HPA",
                    "match": { "node-type": "service" }
                }
            }
        },
        "database": {
            "default": "registry.terraform.io/calm-forge/ocp-database/v1.3.0",
            "variants": {
                "postgresql-ocp": {
                    "source": "registry.terraform.io/calm-forge/crunchydata-postgres/v1.3.0",
                    "description": "CrunchyData PostgreSQL Operator on OCP",
                    "match": { "node-type": "database", "engine": "postgresql" }
                },
                "rds-postgresql": {
                    "source": "registry.terraform.io/calm-forge/aws-rds-postgres/v1.1.0",
                    "description": "AWS RDS PostgreSQL (for cloud-native deployments)",
                    "match": { "node-type": "database", "engine": "postgresql", "cloud-provider": "aws" }
                }
            }
        },
        "vault-pki": {
            "source": "registry.terraform.io/calm-forge/vault-pki-mtls/v1.0.0",
            "description": "Vault PKI for mTLS between services",
            "match": { "authentication": "mTLS-vault-pki" }
        },
        "vault-dynamic-creds": {
            "source": "registry.terraform.io/calm-forge/vault-dynamic-db-creds/v1.0.0",
            "description": "Vault dynamic database credentials",
            "match": { "authentication": "vault-dynamic-credentials" }
        }
    }
}
```

### Step 5: Generated Terraform Stack Configuration

The Generator reads the instantiation, decorator, and module catalog, and produces:

#### `components.tfcomponent.hcl`

```hcl
# ============================================================
# GENERATED BY: CALM Forge v0.1
# SOURCE:       payments-portal.architecture.json
# PATTERN:      fsi-3tier-app.pattern.json
# GENERATED:    2026-02-22T14:33:00Z
# DO NOT EDIT — regenerate from CALM source
# ============================================================

required_providers {
  kubernetes = {
    source  = "hashicorp/kubernetes"
    version = "~> 2.30"
  }
  vault = {
    source  = "hashicorp/vault"
    version = "~> 4.2"
  }
  helm = {
    source  = "hashicorp/helm"
    version = "~> 2.13"
  }
}

provider "kubernetes" "ocp" {
  config_path = var.kubeconfig_path
}

provider "vault" "this" {
  address = var.vault_addr
  token   = var.vault_token
}

provider "helm" "this" {
  kubernetes {
    config_path = var.kubeconfig_path
  }
}

# --- Component: web-frontend ---
# CALM node: web-frontend (service)
# Module: registry.terraform.io/calm-forge/ocp-deployment/v2.1.0
component "web_frontend" {
  source = "registry.terraform.io/calm-forge/ocp-deployment/v2.1.0"

  inputs = {
    name             = "web-frontend"
    namespace        = var.namespace
    container_image  = "registry.internal/payments/web:3.2.1"
    replicas         = 3
    cpu_request      = "500m"
    memory_request   = "512Mi"
    port             = 8443
    protocol         = "HTTPS"
    vault_pki_path   = component.vault_pki_mtls.outputs.pki_path
    vault_role       = "web-frontend"
    service_mesh     = true
  }

  providers = {
    kubernetes = provider.kubernetes.ocp
    vault      = provider.vault.this
  }
}

# --- Component: api-service ---
# CALM node: api-service (service)
# Module: registry.terraform.io/calm-forge/ocp-deployment/v2.1.0
component "api_service" {
  source = "registry.terraform.io/calm-forge/ocp-deployment/v2.1.0"

  inputs = {
    name             = "api-service"
    namespace        = var.namespace
    container_image  = "registry.internal/payments/api:3.2.1"
    replicas         = 3
    cpu_request      = "1000m"
    memory_request   = "1Gi"
    port             = 8443
    protocol         = "HTTPS"
    vault_pki_path   = component.vault_pki_mtls.outputs.pki_path
    vault_role       = "api-service"
    service_mesh     = true
    db_connection    = component.database.outputs.connection_string
    db_vault_path    = component.vault_dynamic_db_creds.outputs.creds_path
  }

  providers = {
    kubernetes = provider.kubernetes.ocp
    vault      = provider.vault.this
  }
}

# --- Component: database ---
# CALM node: database (database, engine=postgresql)
# Module: registry.terraform.io/calm-forge/crunchydata-postgres/v1.3.0
component "database" {
  source = "registry.terraform.io/calm-forge/crunchydata-postgres/v1.3.0"

  inputs = {
    name           = "payments-portal-db"
    namespace      = var.namespace
    version        = "15.4"
    storage_class  = "encrypted-ssd"
    storage_size   = "100Gi"
    vault_addr     = var.vault_addr
    encryption_key = var.vault_transit_key
  }

  providers = {
    kubernetes = provider.kubernetes.ocp
    vault      = provider.vault.this
    helm       = provider.helm.this
  }
}

# --- Component: vault-pki-mtls ---
# CALM relationship: web-to-api (authentication=mTLS-vault-pki)
# Module: registry.terraform.io/calm-forge/vault-pki-mtls/v1.0.0
component "vault_pki_mtls" {
  source = "registry.terraform.io/calm-forge/vault-pki-mtls/v1.0.0"

  inputs = {
    pki_mount_path    = "pki/payments-portal"
    allowed_domains   = ["web-frontend.${var.namespace}.svc", "api-service.${var.namespace}.svc"]
    max_ttl           = "24h"
    default_ttl       = "1h"
  }

  providers = {
    vault = provider.vault.this
  }
}

# --- Component: vault-dynamic-db-creds ---
# CALM relationship: api-to-db (authentication=vault-dynamic-credentials)
# Module: registry.terraform.io/calm-forge/vault-dynamic-db-creds/v1.0.0
component "vault_dynamic_db_creds" {
  source = "registry.terraform.io/calm-forge/vault-dynamic-db-creds/v1.0.0"

  inputs = {
    db_mount_path     = "database/payments-portal"
    db_connection_url = component.database.outputs.connection_string
    allowed_roles     = ["api-service"]
    default_ttl       = "1h"
    max_ttl           = "24h"
  }

  providers = {
    vault = provider.vault.this
  }
}
```

#### `variables.tfcomponent.hcl`

```hcl
# ============================================================
# GENERATED BY: CALM Forge v0.1
# ============================================================

variable "namespace" {
  type        = string
  description = "Kubernetes namespace for deployment"
}

variable "kubeconfig_path" {
  type        = string
  description = "Path to kubeconfig for target OCP cluster"
}

variable "vault_addr" {
  type        = string
  description = "Vault server address"
}

variable "vault_token" {
  type        = string
  description = "Vault authentication token"
  sensitive   = true
}

variable "vault_transit_key" {
  type        = string
  description = "Vault Transit key for database encryption at rest"
}

variable "environment" {
  type        = string
  description = "Deployment environment"
}
```

#### `deployments.tfdeploy.hcl`

```hcl
# ============================================================
# GENERATED BY: CALM Forge v0.1
# SOURCE:       payments-portal-prod-placement-001 (deployment decorator)
# PLACEMENT:    Placement Engine decision — see rationale ref
# ============================================================

identity_token "vault" {
  audience = ["vault.uhccp.internal"]
}

# --- Deployment: production (from CALM deployment decorator) ---
# Cluster: prod-uksouth-ocp-01
# Region:  uksouth (Azure)
# Reason:  PCI-DSS requires UK data residency, cluster has 40% headroom,
#          cost within budget envelope CC-4521
deployment "production" {
  inputs = {
    namespace         = "payments-portal-prod"
    kubeconfig_path   = "/etc/kubernetes/prod-uksouth-ocp-01.kubeconfig"
    vault_addr        = "https://vault.prod.uksouth.uhccp.internal:8200"
    vault_token       = identity_token.vault.jwt
    vault_transit_key = "payments-portal-transit"
    environment       = "production"
  }
}

# --- Deployment group: production gate ---
deployment_auto_approve "no_destroys" {
  check {
    condition = context.plan.changes.remove == 0
    reason    = "Plan would destroy ${context.plan.changes.remove} resources. Manual approval required."
  }
}

deployment_auto_approve "no_pci_scope_change" {
  check {
    condition = context.plan.applyable == true
    reason    = "PCI-scoped deployment requires manual approval for any infrastructure change."
  }
}

deployment_group "production_gate" {
  auto_approve_checks = [
    deployment_auto_approve.no_destroys
  ]
  # Note: PCI-scoped deployments always require manual approval
  # deployment_auto_approve.no_pci_scope_change is informational
}

# --- Staging deployment (auto-generated for pre-prod validation) ---
deployment "staging" {
  inputs = {
    namespace         = "payments-portal-staging"
    kubeconfig_path   = "/etc/kubernetes/staging-uksouth-ocp-01.kubeconfig"
    vault_addr        = "https://vault.staging.uksouth.uhccp.internal:8200"
    vault_token       = identity_token.vault.jwt
    vault_transit_key = "payments-portal-transit-staging"
    environment       = "staging"
  }
}
```

---

## Generator Pseudocode

```python
# calm_forge_generator.py — Reference Implementation
# NOT PRODUCTION CODE — demonstrates the translation logic

import json
from pathlib import Path
from dataclasses import dataclass


@dataclass
class GeneratorConfig:
    module_catalog_path: str
    output_dir: str
    vcs_repo: str           # Git repo for generated Stack config
    vcs_branch: str         # Branch to commit to
    vault_addr_template: str
    kubeconfig_template: str


def generate_stack(
    architecture_path: str,
    decorator_paths: list[str],
    config: GeneratorConfig
) -> dict:
    """
    Main entry point: CALM architecture + decorators → Terraform Stack files.

    Returns dict of generated file paths.
    """
    # 1. Load and validate inputs
    architecture = load_calm_architecture(architecture_path)
    decorators = [load_calm_decorator(p) for p in decorator_paths]
    catalog = load_module_catalog(config.module_catalog_path)

    # 2. Resolve modules for each node
    component_map = {}
    for node in architecture["nodes"]:
        module = resolve_module(node, decorators, catalog)
        component_map[node["unique-id"]] = {
            "node": node,
            "module": module
        }

    # 3. Resolve relationship-driven components (Vault PKI, dynamic creds, etc.)
    relationship_components = []
    for rel in architecture["relationships"]:
        rel_type = get_relationship_type(rel)
        if rel_type == "connects":
            auth = rel.get("authentication")
            if auth and auth in catalog["modules"]:
                relationship_components.append({
                    "relationship": rel,
                    "module": catalog["modules"][auth]
                })

    # 4. Generate .tfcomponent.hcl
    components_hcl = generate_components_hcl(
        component_map,
        relationship_components,
        architecture["metadata"]
    )

    # 5. Generate variables.tfcomponent.hcl
    variables_hcl = generate_variables_hcl(component_map, decorators)

    # 6. Generate .tfdeploy.hcl from deployment decorators
    deployments_hcl = generate_deployments_hcl(decorators, config)

    # 7. Write files
    output_files = write_stack_files(
        config.output_dir,
        components_hcl,
        variables_hcl,
        deployments_hcl
    )

    # 8. Commit to VCS (triggers HCP Terraform Stack run)
    commit_to_vcs(config.vcs_repo, config.vcs_branch, output_files)

    return output_files


def resolve_module(node: dict, decorators: list, catalog: dict) -> dict:
    """
    Map a CALM node to a Terraform module from the catalog.

    Resolution order:
    1. Exact match on node-type + all metadata keys
    2. Variant match on node-type + subset of metadata
    3. Default for node-type
    4. Error — no module found (pattern references unsupported node type)
    """
    node_type = node["node-type"]
    if node_type not in catalog["modules"]:
        raise ValueError(f"No module in catalog for node-type: {node_type}")

    type_entry = catalog["modules"][node_type]

    # Try variant matches (most specific first)
    if "variants" in type_entry:
        for variant_name, variant in type_entry["variants"].items():
            if matches_variant(node, decorators, variant["match"]):
                return variant

    # Fall back to default
    return {"source": type_entry["default"]}


def generate_components_hcl(
    component_map: dict,
    relationship_components: list,
    metadata: dict
) -> str:
    """
    Generate the .tfcomponent.hcl content.

    Each CALM node becomes a `component` block.
    Each authentication-bearing relationship becomes an additional component
    (e.g., Vault PKI, dynamic credentials).
    """
    lines = [
        f"# GENERATED BY: CALM Forge",
        f"# APPLICATION: {metadata.get('application-name', 'unknown')}",
        f"# COMPLIANCE:  {metadata.get('compliance-scope', 'general')}",
        ""
    ]

    # Providers block
    lines.extend(generate_providers_block(component_map))

    # Node-derived components
    for node_id, entry in component_map.items():
        node = entry["node"]
        module = entry["module"]
        lines.extend(generate_component_block(node, module, component_map))

    # Relationship-derived components
    for rc in relationship_components:
        lines.extend(generate_relationship_component(rc))

    return "\n".join(lines)


def generate_deployments_hcl(decorators: list, config: GeneratorConfig) -> str:
    """
    Generate the .tfdeploy.hcl content from CALM deployment decorators.

    Each decorator becomes a `deployment` block.
    PCI-scoped deployments get manual approval gates.
    """
    lines = [
        "# GENERATED BY: CALM Forge",
        "",
        'identity_token "vault" {',
        '  audience = ["vault.uhccp.internal"]',
        '}',
        ""
    ]

    for decorator in decorators:
        data = decorator["data"]
        env = data.get("environment", "default")
        k8s = data.get("kubernetes", {})

        lines.extend([
            f'deployment "{env}" {{',
            f'  inputs = {{',
            f'    namespace       = "{k8s.get("namespace", env)}"',
            f'    kubeconfig_path = "{config.kubeconfig_template.format(cluster=k8s.get("cluster", "default"))}"',
            f'    vault_addr      = "{config.vault_addr_template.format(env=env, region=data.get("region", "default"))}"',
            f'    vault_token     = identity_token.vault.jwt',
            f'    environment     = "{env}"',
            f'  }}',
            f'}}',
            ""
        ])

    return "\n".join(lines)
```

---

## Component Dependency Resolution

The Generator must resolve inter-component dependencies from CALM relationships. Terraform Stacks handles execution ordering via deferred actions, but the Generator must wire the references:

```
CALM Relationship                    Stacks Wiring
────────────────                     ─────────────
web-to-api (connects)           →    web_frontend.inputs.upstream_url =
                                       component.api_service.outputs.service_url

api-to-db (connects,            →    api_service.inputs.db_connection =
  auth=vault-dynamic-creds)            component.database.outputs.connection_string
                                     api_service.inputs.db_vault_path =
                                       component.vault_dynamic_db_creds.outputs.creds_path

deployed-in (ocp-cluster)       →    All components use provider.kubernetes.ocp
                                     Deployment block targets specific cluster

mTLS-vault-pki (auth)           →    Generates vault_pki_mtls component
                                     Services reference component.vault_pki_mtls.outputs.pki_path
```

**Key design rule:** CALM `connects` relationships where `source` references `destination` become `component.X.outputs.Y` references in the generated HCL. Stacks automatically defers the dependent component's plan until the dependency completes. The Generator doesn't need to manage execution order — just wire the references.

---

## Module Catalog Design Principles

1. **One module per CALM node-type + variant** — Platform Engineering maintains a catalog of pre-built, pre-approved Terraform modules. Each module is tested, security-reviewed, and versioned.

2. **Modules are opinionated** — A module for `database/postgresql-ocp` includes CrunchyData operator, backup configuration, monitoring integration, and Vault integration. The developer doesn't configure these — the module does.

3. **Modules expose standard outputs** — Every module exposes `connection_string`, `service_url`, or equivalent. The Generator relies on these for inter-component wiring.

4. **Catalog is version-locked** — A CALM pattern references a catalog version. Regenerating from the same pattern + catalog version always produces the same Stack configuration. Reproducibility is critical for compliance.

5. **Customer-extensible** — Customers can add modules to the catalog for their specific infrastructure. The Generator treats all modules identically.

---

## What This Enables

| Before (v1.0) | After (v2.0 with Generator) |
|---|---|
| Developer writes HCL manually | Developer selects CALM pattern, fills in parameters |
| Platform team reviews HCL PRs | Platform team curates CALM patterns and module catalog |
| Workspace per environment, manually coordinated | Stack per architecture, deployments per environment, auto-coordinated |
| No connection between architecture docs and infrastructure code | Architecture IS the input — generated code is derived artifact |
| Compliance audit reviews HCL + state | Compliance audit reviews CALM intent + placement rationale + generated code + state |

---

## Open Questions (for WALK Design Phase)

1. **Generator runtime:** CLI tool? API service? GitHub Action? TFE Run Task? — Likely starts as CLI, evolves to API service that the control plane orchestrates.

2. **Regeneration policy:** When the module catalog is updated, should all Stacks be regenerated? Or only on explicit request? — Likely: catalog update triggers regeneration for affected patterns, subject to governance gates.

3. **Escape hatches:** What if the generated HCL needs manual customization? — Options: (a) never allow it (pure generated), (b) allow override files that merge with generated config, (c) allow custom components alongside generated ones. Recommend (c) — custom components live in the same Stack but aren't managed by the Generator.

4. **Multi-stack architectures:** Complex systems that span multiple CALM patterns (e.g., payments portal + event bus + analytics pipeline). — CALM `composed-of` relationships map to inter-stack linking via `publish_output` / `upstream_input`.

---

---

## 07 — The Full Loop: Discovery → Inversion → Governance → Execution

> Absorbed from the [Convergent GitOps Architecture](../convergent-gitops/convergent_gitops.md) motion, which described this pipeline from the execution layer up. CALM completes the picture from the intent layer down.

### The Insight

The industry has two disconnected worlds:
- **Infrastructure-as-Code tools** (Terraform, Pulumi, CDK) — bottom-up. You describe resources, they deploy them.
- **Architecture-as-Code tools** (CALM, Structurizr, C4) — top-down. You describe architecture, they validate or visualize it.

Architecture lives in docs and diagrams. Infrastructure lives in HCL and YAML. They don't talk to each other.

The CALM Forge is the bridge. Combined with Terraform Search (GA in Terraform 1.14, HashiConf September 2025), the full loop becomes:

```
DISCOVER  (Terraform Search)          → "What do you actually have?"
            Account creds → scan → discover unmanaged resources → generate IaC

INVERT    (IaC → CALM)                → "Extract the architecture from the sprawl"
            Existing Terraform → CALM patterns + placement decorators
            (This is the true inversion: architecture-as-code FROM infrastructure-as-code)

GOVERN    (CALM patterns + policy)    → "Does it match what good looks like?"
            Pattern validation, compliance checks, placement constraints

EXECUTE   (CALM → Stacks → HCP TF)   → "Make it so"
            Generator produces .tfcomponent.hcl + .tfdeploy.hcl → Plan → Apply

ATTEST    (Native TFE + CALM)         → "Prove it happened"
            Run audit trail, Sentinel results, CALM provenance
```

### Why the Governance Gate Is Not a Motion

The original Convergent GitOps motion described the TFE governance gate (Plan → Sentinel/OPA → Apply) as a novel architecture. It isn't — that's product-native HCP Terraform behavior. Every TFE workspace already does this. What WAS novel was the framing: multiple actors producing intent that converges on a single gate.

CALM absorbs this insight: the architecture definition IS the intent. Whether a developer, ServiceNow CR, Waypoint UI, Concert decision, or AI agent produces the CALM instantiation, it all flows through the same CALM Forge-to-TFE pipeline. The multi-actor convergence is a property of CALM's open schema, not a separate architectural pattern.

### Multi-Actor Intent Sources

| Actor | How They Produce CALM Intent | Entry Point |
|---|---|---|
| **Developer** | Authors CALM instantiation JSON, git push | VCS → Generator → IaC pipeline |
| **Portal / Developer Hub** | No-code UI → CALM template instantiation | Portal API → Generator → IaC pipeline |
| **ITSM / Change Management** | Change Request → catalog item → CALM instantiation | Webhook → Generator → IaC pipeline |
| **Resiliency tooling** | Risk/resiliency decision → CALM placement decorator | API → Generator → IaC pipeline |
| **Optimization tooling** | Right-sizing recommendation → CALM resource mutation | Webhook → Generator → IaC pipeline |
| **Configuration management** | Playbook output → CALM configuration facts | Callback → Generator → IaC pipeline |
| **AI Agent (MCP)** | Autonomous decision → CALM instantiation | MCP → Generator → IaC pipeline |
| **Infrastructure discovery** | Existing infrastructure → reverse-engineer CALM | IaC → CALM inversion → catalog |

---

*This document defines the translation contract between CALM (intent) and Terraform Stacks (execution).*

*Last validated: 2026-02-22*
