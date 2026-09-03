# `semconv/` — the Forge semantic-convention registry

The `forge.*` telemetry namespace, authored as **registry-as-code** in upstream
OpenTelemetry semantic-convention YAML and tooled by
[OpenTelemetry Weaver](https://github.com/open-telemetry/weaver). This directory is the
**source of truth** for the namespace: the generated typed constants the emitters import
(MP-52) come from here, so an attribute that is not registered here cannot be emitted.

See **ADR-014** (the forge semconv registry) and **ADR-009 §1–2** (the passport
announcement contract these entries formalize).

## Layout

```
semconv/
  README.md                             ← this file
  forge/
    manifest.yaml                       ← Weaver registry manifest (name + schema_url)
    model/
      passport-attributes.yaml          ← the five resource attributes (ADR-009 §1)
      passport-events.yaml              ← the three log events (ADR-009 §2)
  templates/registry/python/            ← Weaver templates for the generated constants
```

## v0.1 content

Five resource attributes and three log events.

| Entry | Kind | Type |
|---|---|---|
| `forge.passport.id` | resource attribute | string |
| `forge.passport.edge_digest` | resource attribute | string |
| `forge.passport.expires` | resource attribute | int (unix epoch, seconds) |
| `forge.anchor.ref` | resource attribute | string (`kg://anchor/<id>`) |
| `forge.workload.urn` | resource attribute | string (`wl:<app>/<component>`) |
| `forge.passport.announced` | log event | — |
| `forge.passport.expiring` | log event | — |
| `forge.passport.superseded` | log event | — |

Everything ships at stability `development` (the current schema value for what ADR-014 §3
describes as the `experimental → stable` lifecycle). Placement is resource/log records
only — never metric datapoint attributes (cardinality). That rule is carried in each
attribute's `note` so the generated docs state it rather than leaving it to memory.

### `forge.anchor.ref`, not `forge.seal.ref`

ADR-010 §6 renamed `forge.seal.ref` → `forge.anchor.ref` (and `kg://seal/<id>` →
`kg://anchor/<id>`) **before** this registry existed. `forge.seal.ref` was never
registered, generated, or published, so it carries **no deprecation entry** — a
deprecation mark would imply an emitter once used it (ADR-014 A1).

## Validation and generation (Weaver)

`weaver registry check` gates every change. Weaver is a Rust binary — a toolchain
dependency, pinned by version **and** digest in `.github/pinned-binaries.env` — and
runs as its own `semconv` CI job, not a step in the Python test matrix (ADR-014 §1, A3;
MP-51). The same job regenerates the constants and fails on `git diff --exit-code`, so
the committed module cannot drift from the YAML.

The typed constants live at `src/calm_forge/semconv.py` and are **committed**. Emitters
import them (`calm_forge.passport_announce`); an unregistered attribute cannot be
emitted. Committing them keeps Weaver out of `pip install -e .` and the offline demo
(MP-52).

Local run once Weaver is installed:

```bash
scripts/generate-semconv.sh
```

That is `weaver --future registry check` followed by `weaver registry generate python`.

## Residency and promotion

The registry lives here, versioned and released with the primary emitter. The day a
second emitter (the Reasoner, the Gate runner, a downstream fabric) needs the vocabulary, it promotes
to a standalone repo with its own release cadence and consumers pin registry versions
(ADR-014 §3). The trigger is named so promotion is an act, not a debate.
