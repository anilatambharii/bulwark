# Architecture

Bulwark implements **defense in depth** for AI agent tool calls. No single
layer is load-bearing; each is a check, and a determined attacker has to
defeat all five to achieve impact.

## Pipeline

```
        ┌──────────────┐
input ──▶│ 1 Sanitize   │──┐    (zero-permission isolate)
        └──────────────┘  │
                          ▼
                   ┌──────────────┐
                   │ 2 Detect     │   (patterns + opt. transformer)
                   └──────────────┘
                          │
                          ▼
                   ┌──────────────┐
                   │ 3 Authorize  │   (RBAC, deny by default)
                   └──────────────┘
                          │
                          ▼
                   ┌──────────────┐
                   │ 4 Confirm    │   (human gate, async)
                   └──────────────┘
                          │
                          ▼
                  ┌─────────────────┐
                  │ 5 Audit         │   (encrypted, queryable)
                  └─────────────────┘
                          │
                          ▼
                     tool runs
```

Order matters — earlier layers are cheaper, deny-fast. RBAC runs *first*
(~microseconds) so we never waste a 200 ms ML call on a request that wasn't
authorized to begin with.

## Layer 1 — Input Sanitizer

**File:** [`bulwark/core/sanitizer.py`](../bulwark/core/sanitizer.py)

The sanitizer's job is to strip *known-malicious encodings* before any other
component touches the text. Crucially, the sanitizer process is intended to
run with **zero outbound capability** — no file I/O, no network, no
subprocess. If somehow compromised by adversarial input, the blast radius is
limited to a return value the caller is free to drop.

### Dual-model pattern

The "dual-model" naming reflects the deployment shape:

1. A **fast, isolated model** (e.g. distilbert or a regex-only fallback)
   reads untrusted input and emits filtered text + a risk score.
2. The **agent model** consumes only the filtered text. It never sees the
   raw input directly.

This compartmentalization is borrowed from CapMan / SCION-style network
isolation: the privileged thing (the agent) only ever talks through the
unprivileged thing (the sanitizer).

### Operations performed

| Operation | Pattern | Reason |
|-----------|---------|--------|
| Unicode NFKC normalization | full-width → half-width | defeats `ｉｇｎｏｒｅ` style spoofing |
| HTML entity decoding | `&lt;system&gt;` → `<system>` | catches double-encoded payloads |
| Zero-width character removal | `U+200B-200D, FEFF, 2060` | classic smuggling channel |
| Bidi override removal | `U+202A-202E, 2066-2069` | Trojan Source style attacks |
| Hidden CSS removal | `font-size:0`, `opacity:0`, `display:none` | invisible-text injection |
| HTML tag stripping | any `<tag>...<\tag>` | structure-based smuggling |
| Control character removal | `U+0000-001F` minus tab/newline | terminal attacks |
| `data:` and `javascript:` URL neutralization | replaced with sentinel | content smuggling |

## Layer 2 — Injection Detector

**File:** [`bulwark/core/detector.py`](../bulwark/core/detector.py)

Returns a `DetectionResult` with a normalized score in `[0, 1]`.

### Phase 1 — Pattern catalog (always active)

A deterministic regex catalog
([`bulwark/utils/patterns.py`](../bulwark/utils/patterns.py)) of 22 curated
attack signatures. Each pattern carries a `severity` (LOW, MEDIUM, HIGH,
CRITICAL); the combiner picks the highest hit and adds a small bonus per
additional match. Runs in < 5 ms with no external dependencies.

Categories covered: role-marker overrides, jailbreak directives, system prompt
extraction, virtualization/roleplay jailbreaks, special token injection,
credential phishing, data-exfiltration via markdown/image links, memory
poisoning, indirect tool invocation, and context-window overflow attacks.

### Phase 2 — Transformer classifier (optional)

Activated with `DetectorConfig(enable_ml=True)` plus
`pip install bulwark-agent-security[ml]`.

Loads [`protectai/deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2)
from HuggingFace Hub — a DeBERTa-v3-base model fine-tuned specifically for
prompt injection detection. Adds recall on paraphrased attacks the pattern
catalog hasn't seen. Loaded lazily; if the model cannot be fetched the
detector silently continues with pattern-only scoring.

The two scores combine with configurable weights (`ml_weight`, `pattern_weight`).
If either signal reaches extreme confidence (`>= 0.85` pattern or `>= 0.95`
ML) the combined score is `max()` rather than a blend — strong signal wins.

### Why both?

Patterns are auditable: a security engineer can read the catalog and
understand exactly what gets blocked. The transformer adds reach for
paraphrased attacks the catalog hasn't seen. Together they neutralize each
other's failure modes — a regex-only detector is brittle against rewording;
an ML-only detector is a black box that auditors will not accept.

The key design choice: **the pattern phase is the default and the guaranteed
baseline**. You get deterministic, explainable security out of the box; you
opt into the transformer when you need the extra coverage and can accept the
additional dependency.

## Layer 3 — Compartmentalized RBAC

**File:** [`bulwark/core/rbac.py`](../bulwark/core/rbac.py)

The empirical lesson from 2024–2025 agent incidents was *not* that
permission models needed to be more expressive — it was that **agents
routinely had more privilege than their job required**. Bulwark's RBAC is
deliberately simple:

```
role × tool → allowed? + requires_confirmation?
```

Predefined roles encode the compartmentalization pattern:

* `RESEARCH` — read-only (DB read, URL fetch, web search).
* `WRITE`    — DB writes, but no email or payment.
* `EMAIL`    — send mail, but no DB writes or payment.
* `FINANCIAL` — payment processing — every action requires human confirmation.
* `ADMIN`    — break-glass — should only ever be assumed by humans.

Unknown tools are denied by default. Custom roles and per-tool overrides
are first-class.

## Layer 4 — Human Confirmation Gate

**File:** [`bulwark/core/gates.py`](../bulwark/core/gates.py)

For high-stakes actions (large payments, mass deletion, credential
changes) automated execution is unsafe regardless of how confident the
agent is. The gate:

1. Opens a `ConfirmationRequest`.
2. Dispatches to all registered notification channels (Slack webhook,
   email, custom webhook receiver, push).
3. Awaits an `asyncio.Event` until approve/deny/timeout.
4. Auto-denies on timeout (default 5 min, configurable).

The implementation uses `asyncio.Event`, not polling, so 1,000 pending
requests cost essentially zero CPU. Channel failures are logged and ignored
— a broken Slack webhook does not block an email approval.

## Layer 5 — Encrypted Audit Trail

**File:** [`bulwark/core/audit.py`](../bulwark/core/audit.py)

Every guarded tool call produces an `AuditEntry` containing:

```python
audit_id, timestamp (UTC),
agent_id, user_id,
tool_called, input_data, output_data,
risk_score, decision,            # approved / blocked / escalated / denied / error
source_data, reasoning_chain,
compliance_tags,                 # ["HIPAA", "SOC2", ...]
layer, duration_ms
```

### Storage

Pluggable via the `AuditStorage` protocol:

* `InMemoryAuditStorage` — default; fine for tests and short-lived agents.
* `FileAuditStorage` — append-only, one file per record. Pair with S3
  Object Lock or GCS Bucket Lock for true WORM.
* Custom — implement `append`, `read`, `scan` and you're done.

### Encryption

`Fernet` (AES-128-CBC + HMAC-SHA256) via the `cryptography` library —
authenticated, tamper-evident, FIPS-aware. Key rotation is supported by
passing a list of keys: the first encrypts new records; all decrypt old
ones.

### Redaction

`AuditConfig.redact_fields` lists field names that should be replaced with
`[REDACTED]` before persistence — by default `password`, `ssn`, `api_key`,
`token`, `secret`. The check is case-insensitive.

### Retention

`AuditTrail.purge_expired()` removes records older than
`retention_days`. HIPAA defaults to 7 years; SOC 2 to 1 year; NERC CIP to
3 years.

## Cross-cutting concerns

### Outbound exfiltration scanning

Tools listed in `guard(outbound_tools=[...])` have their *output* re-scanned
by the detector before being returned to the caller. This catches the most
common exfiltration pattern: an agent reads a poisoned document, the
document tells it to email an attacker, the email body contains the smuggled
secret. Bulwark catches it at the `send_email` boundary.

### Async everywhere

Every I/O surface is `async def`. CPU-bound work (regex, ML inference) is
synchronous within the function but dispatched through `asyncio.to_thread`
when ML is loaded so it never blocks the event loop.

### Type safety

`mypy --strict` clean. Pydantic v2 models throughout for config + result
types — invalid configs fail at construction time, not at first use.
