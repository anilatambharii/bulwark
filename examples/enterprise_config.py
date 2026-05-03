"""Enterprise / regulated-industry configuration example.

Shows how to wire Bulwark for a HIPAA + SOC 2 + NERC CIP environment:

* Encrypted, file-backed audit trail with 7-year retention.
* Multi-channel human confirmation gate (email + Slack webhook stub).
* Conservative thresholds for payment + deletion.
* Outbound exfiltration scanning for any tool that sends data externally.
"""

from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

import httpx

from bulwark import AgentRole, AuditTrail, BulwarkConfig, HumanGate, guard
from bulwark.core.audit import AuditConfig, FileAuditStorage
from bulwark.core.gates import ConfirmationRequest, GateConfig
from bulwark.utils.crypto import generate_audit_key

logger = logging.getLogger(__name__)


# ----------------------------------------------------- notification channels


async def slack_webhook_channel(webhook_url: str, request: ConfirmationRequest) -> None:
    """Post pending confirmations to Slack via Incoming Webhook."""
    payload = {
        "text": (
            f":warning: *Bulwark approval needed*\n"
            f"• action: `{request.action}`\n"
            f"• agent: `{request.agent_id}`\n"
            f"• risk: `{request.risk_score:.2f}`\n"
            f"• request_id: `{request.request_id}`\n"
            f"• reason: {request.reason or '_no reason given_'}"
        )
    }
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.post(webhook_url, json=payload)
    except Exception as exc:
        logger.warning("Slack notification failed: %s", exc)


async def email_channel_stub(request: ConfirmationRequest) -> None:
    """Replace with your SMTP / SES / SendGrid send."""
    logger.info("[email] approval needed: %s (request_id=%s)", request.action, request.request_id)


# ------------------------------------------------------------- tool stubs


async def read_phi(args: dict[str, Any]) -> dict[str, Any]:
    """Pretend PHI lookup — guarded by RBAC + audit + redaction."""
    return {"patient_id": args["patient_id"], "diagnosis": "[redacted]"}


async def post_to_partner_api(args: dict[str, Any]) -> dict[str, Any]:
    """Outbound — re-scanned for exfiltration."""
    return {"sent": True}


async def process_payment(args: dict[str, Any]) -> dict[str, Any]:
    """Always requires human confirmation per default RBAC policy."""
    return {"charged_usd": args["amount"]}


# ----------------------------------------------------------------- builder


def build_enterprise_stack(
    audit_path: Path,
    encryption_key: str,
    slack_webhook: str | None = None,
) -> tuple[dict[str, Any], AuditTrail]:
    audit_cfg = AuditConfig(
        encryption_key=encryption_key,
        retention_days=2555,  # HIPAA
        compliance_mode=["HIPAA", "SOC2", "NERC_CIP"],
        redact_fields=["ssn", "dob", "mrn", "password", "api_key", "credit_card"],
    )
    audit_trail = AuditTrail(audit_cfg, storage=FileAuditStorage(audit_path))

    gate_cfg = GateConfig(
        financial_threshold=100.0,
        data_deletion_threshold=1,
        credential_change=True,
        timeout_minutes=15.0,  # generous for human in the loop
    )
    gate = HumanGate(gate_cfg)
    gate.add_channel(email_channel_stub)
    if slack_webhook:
        async def slack(req: ConfirmationRequest) -> None:
            await slack_webhook_channel(slack_webhook, req)
        gate.add_channel(slack)

    config = BulwarkConfig(
        alert_mode="interrupt",
        threshold=0.6,  # tighter for regulated env
        compliance=["HIPAA", "SOC2", "NERC_CIP"],
        agent_role=AgentRole.WRITE,
        agent_id="patient-record-agent-01",
        user_id="alice@hospital.example",
    )

    secured = guard(
        executors={
            "read_database": read_phi,
            "post_webhook": post_to_partner_api,
            "process_payment": process_payment,
        },
        config=config,
        outbound_tools=["post_webhook"],
        audit=audit_trail,
        gate=gate,
    )
    return secured, audit_trail


async def main() -> None:
    logging.basicConfig(level=logging.INFO)

    with tempfile.TemporaryDirectory() as tmp:
        audit_path = Path(tmp) / "audit"
        encryption_key = os.environ.get("BULWARK_AUDIT_KEY") or generate_audit_key()
        slack_webhook = os.environ.get("SLACK_WEBHOOK_URL")

        secured, audit = build_enterprise_stack(audit_path, encryption_key, slack_webhook)

        print(f"Audit storage:    {audit_path}")
        print(f"Encryption key:   {encryption_key[:6]}...  (set BULWARK_AUDIT_KEY to persist)")
        print(f"Slack channel:    {'enabled' if slack_webhook else 'disabled'}")

        # Allowed call
        result = await secured["read_database"]({"patient_id": "P-1234"})
        print(f"\nPHI read: {result}")

        # Forensic query
        entries = await audit.query(compliance_tag="HIPAA")
        print(f"\nHIPAA-tagged entries: {len(entries)}")


if __name__ == "__main__":
    asyncio.run(main())
