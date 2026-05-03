# Changelog

All notable changes to Bulwark are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org).

## [Unreleased]

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

[Unreleased]: https://github.com/bulwark-security/bulwark/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/bulwark-security/bulwark/releases/tag/v0.1.0
