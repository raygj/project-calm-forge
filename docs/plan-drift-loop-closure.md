# Plan: Close the Drift Loop

**Goal:** Make drift detection a live feedback system, not a one-shot CLI check.
Two steps: write findings back into the KG, then emit structured events for EDA to consume.

---

## Step 1 — KG Writeback

**What:** After `evaluate_drift()` runs, update the `drift_state` field on each Placement
node in-place. The KG becomes the authoritative record of current drift state.

**Where:** `src/calm_forge/drift_evaluator.py` — add `write_drift_state()` function.

**Placement node `drift_state` after writeback:**
```json
{
  "last_evaluated": "2026-04-28T09:00:00Z",
  "status": "violation",
  "deviation_hours": null,
  "findings": [
    {
      "severity": "violation",
      "placement_id": "placement:pci-multi-region-payments:bad-cluster",
      "observed_region": "us-west-2",
      "declared_zones": ["us-east-1", "eu-west-1"],
      "message": "Workload placed in 'us-west-2' — not in declared zones"
    }
  ]
}
```

**CLI:** `calm-forge drift` writes back by default; `--no-writeback` flag to suppress.

**Tests:** verify `drift_state` is updated on the placement node JSON file after evaluation.

---

## Step 2 — EDA Event Emission

**What:** After writeback, emit a structured JSON event that Ansible EDA can consume
as a file-watcher or webhook source.

**Where:** `src/calm_forge/drift_evaluator.py` — add `emit_drift_event()` function.
`src/calm_forge/ansible_writer.py` — update generated EDA rulebook to include a
drift event source and a violation response rule.

**Event payload shape:**
```json
{
  "event_type": "calm.drift.evaluated",
  "timestamp": "2026-04-28T09:00:00Z",
  "workload": "pci-multi-region-payments",
  "status": "violation",
  "declared_zones": ["us-east-1", "eu-west-1"],
  "observed_regions": ["us-east-1", "eu-west-1", "us-west-2"],
  "findings": [...]
}
```

**Output options (CLI flags):**
- `--emit-events` — enable event emission (default: off)
- `--event-file /path/to/events.json` — append events to file (EDA file-watcher source)
- `--event-webhook https://...` — POST event to EDA webhook source

**Generated EDA rulebook addition:**
```yaml
sources:
  - ansible.eda.file_watcher:
      path: /var/log/calm-forge/drift-events.json

rules:
  - name: Respond to drift violation
    condition: event.calm.drift.status == "violation"
    action:
      run_playbook:
        name: drift-remediation.yml
        extra_vars:
          workload: "{{ event.calm.drift.workload }}"
          findings: "{{ event.calm.drift.findings }}"
```

**Tests:** verify event payload shape; verify generated rulebook contains drift source
and violation rule.

---

## Sequence after both steps

```
calm-forge drift \
  --workload examples/pci-multiregion/instantiation.json \
  --kg-dir /tmp/pci-kg \
  --emit-events \
  --event-file /tmp/calm-drift-events.json

→ Placement nodes updated (drift_state written back to KG)
→ Event appended to /tmp/calm-drift-events.json
→ EDA file-watcher fires
→ drift-remediation.yml runs if violation
→ Exit 0 (ok) or Exit 1 (violation)
```

---

## Backlog tickets

- **P1-021:** Drift KG writeback — `write_drift_state()`, `--no-writeback` flag, tests
- **P1-022:** EDA event emission — `emit_drift_event()`, `--emit-events` + `--event-file`
  flags, updated EDA rulebook template, tests
