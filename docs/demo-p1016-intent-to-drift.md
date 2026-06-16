# CALM Forge — Intent to Drift: Full Demo Talk Track

**Audience:** Platform / compliance / infrastructure teams  
**Duration:** ~5 minutes  
**Version:** v0.4 — 3 JSON files → 9 artifacts → KG intake → drift detection  
**Setup:** `cd /path/to/calm-forge && source .venv/bin/activate`

---

## The one-sentence framing

> "Every PCI workload produces a mountain of evidence artifacts at recertification time.
> We generate all of them from a single intent file — and then continuously verify that
> what you said would happen actually happened."

---

## Slide 1 — The problem (30s)

**On screen:** nothing yet — just the prompt

> "PCI DSS v4 recertification is expensive not because the controls are hard, but because
> the evidence is scattered. Your architecture doc says one thing. Your Terraform says
> another. Your Vault config is a third thing. Your Sentinel policies are a fourth.
> Nobody connects them — so the auditor asks 200 questions to reconstruct a picture
> that should already exist."
>
> "We solve that differently. Let me show you."

---

## Slide 2 — The input: 3 files (30s)

**Command:**
```bash
ls examples/pci-multiregion/
```

**On screen:** `instantiation.json  decorator.json  catalog.json`

> "Three files. The architecture as machine-readable JSON — a CALM instantiation.
> A deployment decorator with your environment context: regions, compliance tier, DCM
> placement overrides. And a module catalog that maps node types to your approved
> infrastructure modules.
>
> That's the entire interface. The developer doesn't touch HCL, Vault policy, or Sentinel."

---

## Slide 3 — Show the architecture (30s)

**Command:**
```bash
bash scripts/show-nodes.sh
```

**On screen:** 7 nodes — GLB, api-us-east, api-eu-west, db-primary, db-replica, infra-us-east, infra-eu-west

> "Seven nodes. Six relationships — mTLS between the load balancer and the API tier,
> Vault dynamic credentials between the APIs and the databases, deployed-in edges for
> both regions. Two regions. One spec.
>
> PCI metadata is in the instantiation — compliance scope, data residency, classification.
> Not in a comment. In the data."

---

## Slide 4 — Generate 9 artifacts (45s)

**Command:**
```bash
calm-forge generate \
  --calm examples/pci-multiregion/instantiation.json \
  --decorator examples/pci-multiregion/decorator.json \
  --catalog examples/pci-multiregion/catalog.json \
  --output-dir /tmp/pci-demo \
  --full
```

**Then:**
```bash
find /tmp/pci-demo -type f | sort
```

**On screen:**
```
/tmp/pci-demo/ansible/eda-rulebook.yml
/tmp/pci-demo/ansible/inventory.yml
/tmp/pci-demo/components.tfstack.hcl
/tmp/pci-demo/dcm/application.json
/tmp/pci-demo/deployments.tfdeploy.hcl
/tmp/pci-demo/sentinel/policies.sentinel
/tmp/pci-demo/variables.tfstack.hcl
/tmp/pci-demo/vault/pki-config.hcl
/tmp/pci-demo/vault/policies.hcl
```

> "Nine files. One command. Terraform Stack HCL — components, deployments, variables.
> Vault PKI config for req-4 TLS in transit. Vault dynamic credential policies for
> req-8 automated rotation. Sentinel compliance gates — enforced before any apply.
> Ansible inventory and an EDA rulebook. And one more thing."

---

## Slide 5 — The DCM placement contract (45s)

**Command:**
```bash
cat /tmp/pci-demo/dcm/application.json
```

**On screen:**
```json
{
  "name": "pci-multi-region-payments",
  "service": "container",
  "tier": 1,
  "zones": ["us-east-1", "eu-west-1"]
}
```

> "This is a ready-to-POST placement contract for Red Hat's dcm-placement-api.
> Four fields. Name, service type, compliance tier, and zones — derived directly
> from the CALM spec. No translation layer. This is what you hand to the DCM team.
>
> When DCM receives this, its OPA policies enforce that tier-1 workloads only land
> in approved zones. The enforcement happens at placement time. We declared the
> intent — DCM enforces it.
>
> That's the first half of the story."

---

## Slide 6 — The gap: did it land where you said? (15s)

**Command:**
```bash
echo '--- You declared intent. Did it land where you said it would? ---'
```

> "Here's the question every auditor asks: 'How do you *know* the workload is
> only running in us-east-1 and eu-west-1?' The answer used to be: 'We checked.'
> That's not evidence. Let me show you what evidence looks like."

---

## Slide 7 — Pull live cluster state from ACM (45s)

**Command:**
```bash
calm-forge intake-acm \
  --fixture examples/acm-inventory.json \
  --output-dir /tmp/pci-kg
```

**On screen:**
```
Wrote 3 ExecutionEnvironment node(s):
  /tmp/pci-kg/environments/prod-east-ocp-01.json    ← us-east-1, pci, vault_dynamic_creds
  /tmp/pci-kg/environments/prod-eu-west-ocp-01.json ← eu-west-1, pci
  /tmp/pci-kg/environments/dev-east-ocp-01.json     ← us-east-1, dev only
```

> "We read the cluster inventory from Red Hat ACM — in production this is a live API
> call, here we're using a fixture. Each cluster becomes an ExecutionEnvironment node
> in the knowledge graph: provider, region, advertised capabilities, compliance labels.
>
> Now we know what infrastructure exists. Next: what actually got deployed to it."

---

## Slide 8 — Pull deployment state from Ansible AAP (45s)

**Command:**
```bash
calm-forge intake-ansible \
  --fixture examples/aap-jobs.json \
  --env-dir /tmp/pci-kg/environments \
  --output-dir /tmp/pci-kg
```

**On screen:**
```
Wrote 3 Placement node(s):
  /tmp/pci-kg/placements/pci-multi-region-payments__prod-east-ocp-01.json
  /tmp/pci-kg/placements/pci-multi-region-payments__prod-eu-west-ocp-01.json
  /tmp/pci-kg/placements/fraud-detection-pipeline__prod-east-ocp-01.json
```

> "Ansible AAP job history tells us what was deployed, where, and when. Each
> successful job becomes a Placement node — workload ID, environment ID, region,
> namespace, timestamp, observed capabilities. The knowledge graph now has both
> sides: what the environment can do, and what actually landed on it."

---

## Slide 9 — Drift: the moment of truth (45s)

**Command:**
```bash
calm-forge drift \
  --workload examples/pci-multiregion/instantiation.json \
  --kg-dir /tmp/pci-kg
```

**On screen:**
```
Workload:  pci-multi-region-payments
Declared:  ['us-east-1', 'eu-west-1']
Observed:  ['us-east-1', 'eu-west-1']

DRIFT: OK — observed placements match declared intent
```

> "The drift evaluator compares declared zones from the CALM spec against observed
> placement regions from the KG. In this case: exact match. Green.
>
> But if someone ran an emergency deployment to us-west-2 — failover drill, incident
> response, mistake — the next run would surface:
>
> VIOLATION: Workload placed in 'us-west-2' — not in declared zones
>
> Exit code 1. CI fails. PagerDuty fires. The auditor gets a timestamped finding
> instead of a clean attestation."

---

## Slide 10 — Closing (30s)

> "What did we just do? We took a 7-node architecture spec and produced:
>
> — Terraform infrastructure, ready for plan
> — Vault credential rotation, per PCI req-8
> — Sentinel compliance gates, enforced before any apply
> — A DCM placement contract, ready to POST to the placement API
> — An EDA rulebook for Ansible event-driven response
> — A knowledge graph of what exists and what landed where
> — A continuous drift check between intent and reality
>
> That's your PCI DSS evidence package. No questionnaire. No spreadsheet.
> Intent in git. Placement enforced at deploy. Drift detected continuously.
> Every artifact traces back to the same source of truth."

---

## If they ask about DCM integration

> "The dcm/application.json artifact is a direct POST to dcm-placement-api.
> `POST /applications { name, service, tier, zones }`. OPA validates zones against
> their tier policies. Our tier 1 maps to their tier-1.rego. Our `allowed_regions`
> is their `zones`. We designed the field mapping deliberately — CALM Forge sits
> upstream, DCM enforces downstream. No joint roadmap required."

## If they ask about live vs fixture

> "The intake commands have a `--fixture` path for lab and demo use. In production
> you'd wire `intake-acm` to your ACM API endpoint with a token — same output shape,
> same KG nodes. The drift evaluator doesn't care where the placement nodes came from."

## If they ask about scheduling

> "This is designed to run on a schedule — post-deploy, nightly, or as a CI gate
> on CALM spec changes. When drift is detected, you have an exit code 1 and a
> structured finding JSON. Wire it to whatever alerting you already use."
