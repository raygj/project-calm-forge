# Generated HCL Walkthrough

**Purpose:** Line-by-line explanation of what the generator produces and why. Use this to prep before the demo or hand it to a technical audience who wants to read the output themselves.

---

## `components.tfstack.hcl` — The Infrastructure

### Header Block (lines 1-7)
Traceability. Every generated file stamps where it came from — the source architecture (`payments-portal.architecture.json`), the pattern it instantiated (`fsi-3tier-app.pattern.json`), and the timestamp. If someone finds this HCL in a repo six months from now, they know exactly what produced it and that they shouldn't hand-edit it.

### Providers (lines 9-37)
Three providers — Kubernetes (for OCP), Vault (for secrets/PKI/transit), Helm (for CrunchyData operator). These are the standard set for any OCP + Vault deployment. The generator hard-codes these for now. WALK stage would derive them from the module catalog.

Key detail: the Kubernetes provider is named `"ocp"` — this maps to the `deployed-in` relationship in the CALM source. The architecture said "these nodes deploy on ocp-cluster," so the provider gets that identity.

### `web_frontend` component (lines 39-63)
The generator saw node `web-frontend` with `node-type: service` in the CALM instantiation. It checked the catalog, found the `ocp-deployment` variant matches `node-type: service`, and resolved to `registry.terraform.io/uhccp/ocp-deployment/v2.1.0`.

The interesting lines:
- **Line 54:** `vault_pki_path = component.vault_pki_mtls.outputs.pki_path` — this wasn't in the node definition. The generator saw that `web-frontend` is the **source** of the `web-to-api` relationship, which has `authentication: mTLS-vault-pki`. So it wired the PKI path in. The service will use this to fetch its mTLS certificate from Vault.
- **Lines 55-56:** `vault_role = "web-frontend"` and `service_mesh = true` — also derived from the mTLS relationship. The role name matches the CALM node ID.

### `api_service` component (lines 65-91)
Same module resolution as web_frontend (both are `service` type). But this node participates in **two** authentication relationships:

1. **mTLS** (destination of `web-to-api`) — gets `vault_pki_path`, `vault_role`, `service_mesh` — same pattern as web_frontend
2. **Vault dynamic credentials** (source of `api-to-db`) — gets two additional wires:
   - **Line 83:** `db_connection = component.database.outputs.connection_string` — the generator saw api-service connects to the database node, so it wired the database's connection string output into this component's input
   - **Line 84:** `db_vault_path = component.vault_dynamic_db_creds.outputs.creds_path` — and wired the Vault credentials path so the API service knows where to fetch its short-lived database credentials

This is the inter-component wiring that Terraform Stacks handles via deferred execution. The generator doesn't manage ordering — Stacks sees that `api_service` depends on `database` and `vault_dynamic_db_creds` outputs, and plans them in the right sequence.

### `database` component (lines 93-114)
The generator saw `node-type: database` with `engine: postgresql`. It checked catalog variants — `postgresql-ocp` matches `{node-type: database, engine: postgresql}` — and resolved to `registry.terraform.io/uhccp/crunchydata-postgres/v1.3.0`. Not the generic `ocp-database` module, not the AWS RDS variant (that requires `cloud-provider: aws` in the match). The most specific match wins.

- **Line 100:** `name = "payments-portal-db"` — derived from the application name in metadata + `-db`
- **Line 106:** `encryption_key = var.vault_transit_key` — the generator adds Vault Transit encryption for all database components. This is the encryption-at-rest posture.
- **Line 112:** `helm = provider.helm.this` — database gets the Helm provider (CrunchyData deploys via Helm operator). Services don't get Helm — only databases do.

### `vault_pki_mtls` component (lines 116-132)
This component doesn't come from a CALM **node**. It comes from a CALM **relationship**. The generator saw `web-to-api` has `authentication: mTLS-vault-pki`, searched the catalog for a module whose `match.authentication` equals `mTLS-vault-pki`, and found `vault-pki` -> `registry.terraform.io/uhccp/vault-pki-mtls/v1.0.0`.

- **Line 123:** `pki_mount_path = "pki/payments-portal"` — scoped to the application name
- **Line 124:** `allowed_domains` — lists both the source and destination nodes as Kubernetes service DNS names: `web-frontend.${var.namespace}.svc` and `api-service.${var.namespace}.svc`. Only these two services can get certificates from this PKI mount.
- Only needs the `vault` provider — it's a Vault-only resource.

### `vault_dynamic_db_creds` component (lines 134-151)
Same pattern — derived from the `api-to-db` relationship's `authentication: vault-dynamic-credentials`. The generator found `vault-dynamic-creds` in the catalog.

- **Line 142:** `db_connection_url = component.database.outputs.connection_string` — wires back to the database component. Vault needs the connection string to configure the database secrets engine.
- **Line 143:** `allowed_roles = ["api-service"]` — only the API service can request credentials. Derived from the relationship's source node.

---

## `variables.tfstack.hcl` — The Contract

Six variables. These are the deployment-time inputs — the things that change between environments:

| Variable | Why It Exists |
|----------|--------------|
| `namespace` | Kubernetes namespace — differs per environment (`payments-portal-prod` vs `-staging`) |
| `kubeconfig_path` | Which cluster to target — different kubeconfig per environment |
| `vault_addr` | Vault endpoint — each environment has its own Vault instance |
| `vault_token` | Auth token — marked `sensitive = true` so it never appears in plan output or state |
| `vault_transit_key` | Which Transit key encrypts the database at rest — different key per environment |
| `environment` | Label — used for tagging and conditional logic downstream |

The generator derives these from what the components actually reference. Every `var.X` in the components file has a corresponding variable definition here.

---

## `deployments.tfdeploy.hcl` — Where It Lands

### Identity token (lines 7-9)
Workload identity for Vault. Instead of passing a static token, the deployment uses `identity_token.vault.jwt` — a short-lived JWT that HCP Terraform exchanges for Vault access. The audience is scoped to `vault.uhccp.internal`.

### Production deployment (lines 11-25)
Derived from the deployment decorator JSON. The Placement Engine decided:
- **Cluster:** `prod-uksouth-ocp-01`
- **Region:** `uksouth` (Azure)
- **Why:** PCI-DSS data residency + cluster has 40% headroom + cost within budget envelope CC-4521

The generator turned that into concrete variable values — namespace, kubeconfig path, Vault address. The `vault_token` uses the identity token JWT rather than a static secret.

### PCI compliance gates (lines 27-48)
Because the CALM metadata says `compliance-scope: pci-dss`, the generator added three blocks:

1. **`no_destroys`** — blocks auto-approval if the plan would destroy any resources. Destructive changes in a PCI-scoped environment require a human.
2. **`no_pci_scope_change`** — informational check that flags any infrastructure change in PCI scope for manual review.
3. **`production_gate`** — groups the checks. The `no_destroys` check is enforced; the PCI scope check is documented but not blocking (the comment explains why — PCI deployments always require manual approval regardless).

If the compliance scope were `general` instead of `pci-dss`, none of these blocks would appear.

### Staging deployment (lines 50-60)
Auto-generated. The generator saw a production deployment and created a staging counterpart with:
- Namespace: `payments-portal-staging` (derived from app name)
- Separate kubeconfig, Vault instance, and Transit key
- No approval gates — staging is meant for fast iteration

This gives the team a pre-prod validation environment without anyone having to configure it.

---

## The Traceability Chain

Every block traces back to its CALM source:

```
CALM node: web-frontend          ->  component "web_frontend"
CALM node: api-service           ->  component "api_service"
CALM node: database              ->  component "database"
CALM relationship: web-to-api    ->  component "vault_pki_mtls"
CALM relationship: api-to-db     ->  component "vault_dynamic_db_creds"
CALM metadata: pci-dss           ->  deployment_auto_approve + deployment_group
CALM decorator: prod-placement   ->  deployment "production" + deployment "staging"
```

That's the contract. Architecture intent in, infrastructure code out, every block traceable to why it exists.
