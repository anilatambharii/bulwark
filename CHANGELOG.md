# Changelog

All notable changes to Bulwark are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org).

## [Unreleased]

## [0.2.0] — 2026-06-03

### Changed

* **Layer 2 — Injection Detector**: honest documentation and improved ML integration.
  - Default detection mode is now clearly documented as **pattern-based** (23+ signatures,
    < 5 ms, no external deps). This has always been the runtime behavior; the docs now
    match it.
  - Optional ML mode (`enable_ml=True`, requires `[ml]` extra) now defaults to
    [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2) —
    a DeBERTa-v3 model specifically fine-tuned for prompt injection detection. Previously
    the default path pointed to a local placeholder directory.
  - `_ml_score` label handling extended to cover `LEGIT` / `INJECTION` output labels used
    by the protectai model family.
* README and ARCHITECTURE docs rewritten for Layer 2 to accurately describe what runs
  by default vs. what requires the `[ml]` extra.

### Added

* **7 new attack patterns** in `bulwark/utils/patterns.py` — catalog grows from 15 to 22:
  - `prompt_leak_directive` — extracts system prompt / hidden instructions.
  - `virtualization_jailbreak` — roleplay/persona framing to bypass policy.
  - `memory_poisoning` — directives to persist hostile context across sessions.
  - `special_token_injection` — LLM control tokens (`<|im_start|>`, `[INST]`, etc.).
  - `indirect_tool_invocation` — embedded directives to call specific tools.
  - `markdown_exfil_link` — markdown image/link exfiltration with templated params.
  - `context_window_overflow` — repetitive padding to push instructions out of attention.
  - Enhanced `markdown_exfil_link` (replaces earlier `exfiltration_url`) with broader
    coverage of template syntaxes.
* `pytest-timeout>=2.3` added to `[test]` dependencies; `--timeout=60` in pytest config
  prevents hanging tests from stalling CI.
* CI: `--cov-fail-under=90` now explicitly set in the CI pytest command so coverage
  regressions fail the build immediately. Codecov upload step marked `continue-on-error`
  so a missing token doesn't block the test matrix.

## [0.1.0] — 2026-05-02

### Added

* Initial public release.
* Five-layer defense pipeline: sanitizer, detector, RBAC, gates, audit.
* `guard()` API that wraps tool executors with the full pipeline.
* Compartmentalized RBAC with five default roles (research, write, email,
  financial, admin) and tool-level permissions.
* Encrypted audit trail with key rotation, redaction, retention, and
  forensic queries. In-memory and filesystem storage backends ship out
  of the box; custom backends implement the `AuditStorage` protocol.
* Async human-confirmation workflow with multi-channel notification and
  configurable timeout.
* MCP, Anthropic, OpenAI, and LangChain integrations (each gracefully
  degrades when its underlying SDK is not installed).
* Curated catalog of 15 prompt-injection signatures with severity weights.
* CLI: `bulwark scan`, `bulwark sanitize`, `bulwark genkey`.
* Compliance profiles: HIPAA, SOC 2, NERC CIP, PCI DSS, GDPR.
* Comprehensive test suite (>90% coverage target).
* Documentation: architecture, quickstart, API reference, compliance map,
  security policy, contributing guide.

[Unreleased]: https://github.com/anilatambharii/bulwark/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/anilatambharii/bulwark/releases/tag/v0.2.0
[0.1.0]: https://github.com/anilatambharii/bulwark/releases/tag/v0.1.0
