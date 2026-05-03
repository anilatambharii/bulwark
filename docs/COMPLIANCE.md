# Compliance Guide

Bulwark gives you the *evidence* auditors need; you still own the
*controls* that produce it. This document maps Bulwark's surfaces to
specific clauses in HIPAA, SOC 2, NERC CIP, PCI DSS, and GDPR so a control
narrative can cite Bulwark by line number.

> **Disclaimer.** This is engineering guidance, not legal advice. Compliance
> certification requires a qualified auditor reviewing your *deployed*
> configuration, not the framework in isolation.

## HIPAA (Health Insurance Portability and Accountability Act)

| HIPAA Safeguard | Bulwark surface | Notes |
|-----------------|-----------------|-------|
| §164.308(a)(1)(ii)(D) Information system activity review | `AuditTrail.query()` | Forensic queries by agent, user, tool, time window. |
| §164.308(a)(4) Information access management | `RBACEnforcer` | Role-per-agent + tool-level allowlist. |
| §164.308(a)(5)(ii)(C) Log-in monitoring | `AuditEntry.user_id`, `agent_id` | Every action attributed. |
| §164.312(a)(1) Access control | `RBACConfig` + `deny_unknown_tools=True` | Default-deny on unknown tools. |
| §164.312(b) Audit controls | `AuditTrail` | Encrypted, immutable when paired with WORM storage. |
| §164.312(c)(1) Integrity | Fernet HMAC + `AuditError` on tamper | Authenticated encryption. |
| §164.312(d) Person/entity authentication | `BulwarkConfig.user_id` + IdP integration | Pass through your auth subject. |
| §164.312(e)(1) Transmission security | TLS at app layer + Fernet at rest | Standard combination. |
| §164.316(b)(2)(i) 6-year retention | `AuditConfig.retention_days = 2555` (7-year default) | Exceeds HIPAA minimum. |

### PHI redaction

Add patient-specific fields to `AuditConfig.redact_fields`:

```python
AuditConfig(redact_fields=[
    "ssn", "dob", "mrn", "patient_name", "patient_id",
    "diagnosis_code", "insurance_id",
])
```

Redacted fields are replaced with `[REDACTED]` *before* the entry is
written, so the encryption layer never sees the cleartext.

## SOC 2 — Trust Services Criteria

| TSC Criterion | Bulwark surface |
|---------------|-----------------|
| CC6.1 Logical access security | `RBACEnforcer` |
| CC6.6 Restricted execution | `BulwarkSecuredExecutor` (deny-fast) |
| CC6.7 Restricted transmission | `outbound_tools` exfiltration scan |
| CC6.8 Prevention of malicious code | `InjectionDetector` |
| CC7.2 System monitoring | `AuditTrail` + `metrics` per executor |
| CC7.3 Anomaly evaluation | `min_risk` and `decision="blocked"` queries |
| CC7.4 Incident response | `HumanGate` (manual override path) |
| CC8.1 Change management | Pinned `bulwark` version + reproducible config |
| A1.2 Availability monitoring | `BulwarkSecuredExecutor.metrics` |
| C1.1 Confidentiality | Fernet at rest + redaction |

For Type II evidence, run `bulwark` for the audit period with
`storage_path` pointing at append-only object storage; the auditor's
sample is `await audit.query(start_time=..., end_time=...)`.

## NERC CIP (Critical Infrastructure Protection)

Relevant for utilities running OT-adjacent agents.

| CIP Standard | Bulwark surface |
|--------------|-----------------|
| CIP-005-7 R1 Electronic Security Perimeter | `RBACEnforcer` boundary between IT and OT roles |
| CIP-005-7 R2 Interactive Remote Access | `HumanGate` for OT command execution |
| CIP-007-6 R4.1 Logging | `AuditTrail` with `compliance_tag="NERC_CIP"` |
| CIP-007-6 R4.3 Log retention (90 days minimum) | `retention_days >= 1095` (3 years) |
| CIP-008-6 R1 Cyber security incident response | Forensic queries on `audit_id` |
| CIP-013-2 R1.2 Vendor risk assessment | Pinned dependencies + SBOM (see below) |

### OT/IT compartmentalization

```python
# IT-side agent
it_config = BulwarkConfig(agent_role=AgentRole.RESEARCH)

# OT-side agent — restricted by custom RBAC
from bulwark import RBACConfig, ToolPermission, AgentRole
ot_perms = [
    ToolPermission(tool_name="read_scada", allowed_roles={AgentRole.RESEARCH}),
    ToolPermission(tool_name="set_breaker", allowed_roles={AgentRole.ADMIN},
                   requires_confirmation=True),
]
ot_config = BulwarkConfig(
    agent_role=AgentRole.RESEARCH,
    rbac_config=RBACConfig(permissions=ot_perms, deny_unknown_tools=True),
    compliance=["NERC_CIP"],
)
```

## PCI DSS 4.0

| PCI Requirement | Bulwark surface |
|-----------------|-----------------|
| 3.5 Render PAN unreadable | `redact_fields=["credit_card", "pan", "cvv"]` |
| 7.2 Restrict access by role | `RBACEnforcer` |
| 8.6 Multi-factor for non-console admin | `HumanGate` for `change_credentials` |
| 10.2 Audit log content | `AuditEntry` (user, action, timestamp, source, decision) |
| 10.4 Time-sync | UTC timestamps via `datetime.now(timezone.utc)` |
| 10.5.5 Audit log integrity | Fernet HMAC |
| 10.7 Audit log retention (1 year) | Default `retention_days=2555` exceeds. |
| 11.5 Detect intrusions | `InjectionDetector` |

## GDPR

| GDPR Article | Bulwark surface |
|--------------|-----------------|
| Art. 5(1)(c) Data minimization | Field truncation in `AuditEntry` (16 KiB cap per field) |
| Art. 17 Right to erasure | `AuditTrail.purge_expired()` + custom by-subject purge |
| Art. 25 Privacy by design | Default redact list includes PII fields |
| Art. 30 Records of processing | `AuditTrail.query()` |
| Art. 32 Security of processing | Fernet encryption + `deny_unknown_tools` |
| Art. 33 Breach notification (72h) | Forensic query against `decision="blocked"` |

### Right-to-erasure helper

```python
async def erase_subject(audit: AuditTrail, user_id: str) -> int:
    entries = await audit.query(user_id=user_id)
    purged = 0
    for entry in entries:
        # uses backend deletion if supported
        await audit._delete(entry.audit_id)  # noqa: SLF001
        purged += 1
    return purged
```

## SBOM and supply chain

Bulwark's runtime dependencies are deliberately small and well-known:

* `pydantic` — config validation, MIT
* `cryptography` — Fernet, BSD/Apache-2.0
* `httpx` — HTTP client (notification channels), BSD-3
* `python-jose` — JWT for optional signed audit chains, MIT

Optional extras (transformers, torch, anthropic, openai, mcp, langchain)
are isolated to the `[ml]`, `[anthropic]`, etc. groups so a minimal
deployment carries only what it uses.

Generate an SBOM:

```bash
pip install cyclonedx-bom
cyclonedx-py -o bulwark-sbom.xml
```

## Audit-defensible deployment checklist

- [ ] Pin `bulwark-agent-security==<version>` in `pyproject.toml`.
- [ ] Generate audit key via `bulwark genkey` and store in your KMS.
- [ ] Mount `storage_path` on append-only object storage (S3 Object Lock, GCS Bucket Lock).
- [ ] Set `retention_days` to your longest applicable regime (HIPAA: 2555).
- [ ] Configure `redact_fields` for every PII / PHI / cardholder field.
- [ ] Set `alert_mode="interrupt"` in production (only loosen with risk acceptance).
- [ ] Wire at least two `HumanGate` notification channels for redundancy.
- [ ] Schedule `purge_expired()` on a cron after the retention window.
- [ ] Export SBOM and dependency report to your GRC tool quarterly.
