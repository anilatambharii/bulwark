# Security Policy

Bulwark is a security framework. Vulnerabilities in Bulwark itself are
particularly important — a flaw here may compromise the protection Bulwark
provides to its users' agents. We take responsible disclosure seriously
and respond fast.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ |
| < 0.1   | ❌ |

Once 1.0 ships, the latest minor version and the previous minor will be
supported for security fixes.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Email **security@bulwark.dev** with:

1. A description of the vulnerability.
2. A minimal proof-of-concept (PoC).
3. The affected Bulwark versions, Python versions, and dependency versions.
4. Your assessment of impact (CVSS vector if you can produce one — not required).
5. Whether you would like public credit, and under what name.

If you prefer encrypted communication, our PGP key fingerprint is published
at https://bulwark.dev/.well-known/security.txt. We respond from the same
address; verify the signature before acting on instructions.

## Response timeline

| Step | Target |
|------|--------|
| Acknowledgment | within 48 hours |
| Initial triage and severity assessment | within 5 business days |
| Patch development | depends on severity (see below) |
| Coordinated disclosure | typically 30–90 days from acknowledgment |

| Severity (CVSS) | Patch target |
|-----------------|--------------|
| Critical (9.0–10.0) | Within 7 days; emergency release. |
| High (7.0–8.9)      | Within 30 days. |
| Medium (4.0–6.9)    | Next minor release. |
| Low (0.1–3.9)       | Best-effort, batched into the next release. |

## Scope

In scope:

* Code in this repository (`bulwark/`).
* Default configurations shipped with Bulwark.
* Documentation that materially misleads operators about Bulwark's
  guarantees.

Out of scope:

* Vulnerabilities in third-party dependencies — please report those
  upstream; we will track and bump.
* Vulnerabilities in user-controlled configuration (e.g., a customer who
  picks `alert_mode="log"` and then experiences an injection). We document
  the trade-offs; we cannot prevent operators from accepting risk.
* Denial-of-service through unbounded input — Bulwark documents
  `max_length` as the boundary. Inputs that exceed this and are still
  accepted upstream are an integration bug, not a Bulwark bug.

## Hall of fame

Researchers who responsibly disclose validated vulnerabilities will be
publicly acknowledged here unless they request anonymity.

| Researcher | CVE / advisory | Year |
|------------|----------------|------|
| _Be the first._ | | |

## Standards alignment

Bulwark's disclosure process aligns with:

* [ISO/IEC 29147:2018](https://www.iso.org/standard/72311.html) — vulnerability disclosure
* [ISO/IEC 30111:2019](https://www.iso.org/standard/69725.html) — vulnerability handling
* [CISA Coordinated Vulnerability Disclosure](https://www.cisa.gov/coordinated-vulnerability-disclosure-process)

## Thank you

Security research is real work. We respect the people who do it well, and
we will treat your disclosure with the seriousness it deserves.
