---
title: Bulwark Agent Security
emoji: 🛡
colorFrom: indigo
colorTo: blue
sdk: streamlit
sdk_version: 1.32.0
app_file: app.py
pinned: true
license: apache-2.0
short_description: Live demo of Bulwark - AI agent security pipeline.
tags:
  - ai-security
  - prompt-injection
  - llm-security
  - guardrails
  - mcp
  - agent-security
  - hipaa
  - soc2
models:
  - AmbhariiLabs/injection-classifier
datasets:
  - deepset/prompt-injections
---

# Bulwark — Agent Security Framework

Live, in-browser demo of the **Bulwark** five-layer defense pipeline for
production AI agents.

This Space runs the same dashboard you'd run locally — paste suspect text
into the Playground, watch the sanitizer + injection detector layers fire
in real time, browse a pre-seeded encrypted audit trail, and see per-tool
metrics.

> **Try it:** open the Playground tab → pick the *Direct jailbreak*
> preset → watch both layers light up.

## What Bulwark does

Bulwark is an open-source (Apache 2.0) Python framework that wraps your
agent's tool executors with a defense-in-depth pipeline:

1. **Sanitizer** — strips invisible Unicode, hidden HTML, bidi overrides
2. **Injection detector** — pattern catalog + optional ML classifier
3. **Compartmentalized RBAC** — role × tool permissions, deny-by-default
4. **Human confirmation gate** — async approval for high-stakes actions
5. **Encrypted audit trail** — Fernet-authenticated, queryable, 7-yr retention

It's MCP-native, vendor-neutral (Anthropic / OpenAI / LangChain integrations
ship in the box), and maps directly to HIPAA / SOC 2 / NERC CIP / PCI / GDPR
controls.

## Repository

GitHub: [`anilatambharii/bulwark`](https://github.com/anilatambharii/bulwark)
PyPI: `pip install bulwark-agent-security`

## License

Apache 2.0 — same as the upstream repo.
