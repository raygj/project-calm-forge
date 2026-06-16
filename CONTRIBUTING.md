# Contributing

CALM Forge is a concept prototype — not a community-maintained library. This document explains how to engage with it.

## What this is

This repo demonstrates an approach to closing the gap between declared architecture intent and execution fabric state. It is shared for feedback and exploration, not as a production-ready framework.

## Feedback

If something sparks an idea, raises a question, or you want to discuss the approach — open an issue. That's the best place for it.

Pull requests are not being accepted at this time.

## Running it locally

```bash
pip install -e ".[dev]"
pytest
calm-forge --help
```

Requires Python 3.10+. OPA is optional — install it to enable full policy enforcement in `validate-intent`.

## Examples

The `examples/` directory has runnable scenarios:

```bash
calm-forge generate \
  --calm examples/fsi-3tier/calm.json \
  --decorator examples/fsi-3tier/decorator.json \
  --catalog examples/fsi-3tier/catalog.json \
  --output-dir /tmp/output --full
```

For the knowledge graph and drift loop, see `docs/demo-p1016-intent-to-drift.md`.
