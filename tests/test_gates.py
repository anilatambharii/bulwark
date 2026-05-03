"""Tests for :mod:`bulwark.core.gates`."""

from __future__ import annotations

import asyncio

import pytest

from bulwark.core.gates import (
    ConfirmationRequest,
    ConfirmationStatus,
    GateConfig,
    HumanGate,
)


class TestPolicy:
    def test_payment_above_threshold_needs_confirmation(self, gate: HumanGate) -> None:
        assert gate.needs_confirmation("process_payment", {"amount": 1000})

    def test_payment_below_threshold_skips_gate(self, gate: HumanGate) -> None:
        assert not gate.needs_confirmation("process_payment", {"amount": 5})

    def test_deletion_needs_confirmation(self, gate: HumanGate) -> None:
        assert gate.needs_confirmation("delete_records", {"count": 5})

    def test_credential_change_always_gated(self, gate: HumanGate) -> None:
        assert gate.needs_confirmation("change_credentials")

    def test_unknown_action_passes(self, gate: HumanGate) -> None:
        assert not gate.needs_confirmation("read_email", {})


class TestApprovalFlow:
    async def test_approve_resolves_pending(self) -> None:
        gate = HumanGate(GateConfig(timeout_minutes=1.0))

        async def approver(req: ConfirmationRequest) -> None:
            # External approver simulates webhook callback
            await asyncio.sleep(0.05)
            await gate.approve(req.request_id, approver="alice", note="ok")

        gate.add_channel(approver)
        decision = await gate.request_confirmation(
            agent_id="a", action="process_payment", parameters={"amount": 1000},
        )
        assert decision.approved
        assert decision.approver == "alice"
        assert decision.status == ConfirmationStatus.APPROVED

    async def test_deny_returns_false(self) -> None:
        gate = HumanGate(GateConfig(timeout_minutes=1.0))

        async def denier(req: ConfirmationRequest) -> None:
            await gate.deny(req.request_id, approver="bob", note="suspicious")

        gate.add_channel(denier)
        decision = await gate.request_confirmation(
            agent_id="a", action="delete_records", parameters={"count": 100},
        )
        assert not decision.approved
        assert decision.status == ConfirmationStatus.DENIED


class TestTimeout:
    async def test_timeout_auto_denies(self) -> None:
        gate = HumanGate(GateConfig(timeout_minutes=0.01))  # ~0.6s
        decision = await gate.request_confirmation(
            agent_id="a", action="process_payment", parameters={"amount": 1000},
        )
        assert decision.status == ConfirmationStatus.TIMEOUT
        assert not decision.approved

    async def test_late_approval_after_timeout_ignored(self) -> None:
        gate = HumanGate(GateConfig(timeout_minutes=0.01))
        captured: dict[str, str] = {}

        async def slow_approver(req: ConfirmationRequest) -> None:
            captured["id"] = req.request_id

        gate.add_channel(slow_approver)
        decision = await gate.request_confirmation(
            agent_id="a", action="process_payment", parameters={"amount": 1000}
        )
        assert decision.status == ConfirmationStatus.TIMEOUT
        # Approving after timeout should report False (not pending anymore)
        result = await gate.approve(captured["id"], approver="late")
        assert result is False


class TestAutoApprove:
    async def test_low_risk_bypasses(self) -> None:
        gate = HumanGate(
            GateConfig(timeout_minutes=0.01, auto_approve_low_risk=True, low_risk_threshold=0.3)
        )
        decision = await gate.request_confirmation(
            agent_id="a", action="process_payment", parameters={"amount": 1000},
            risk_score=0.05,
        )
        assert decision.approved
        assert decision.approver == "auto-approval-policy"


class TestNotificationFailures:
    async def test_failing_channel_does_not_block_approval(self) -> None:
        gate = HumanGate(GateConfig(timeout_minutes=1.0))

        async def broken(_req: ConfirmationRequest) -> None:
            raise RuntimeError("network down")

        async def good(req: ConfirmationRequest) -> None:
            await gate.approve(req.request_id, approver="ops")

        gate.add_channel(broken)
        gate.add_channel(good)
        decision = await gate.request_confirmation(
            agent_id="a", action="delete_records", parameters={"count": 5},
        )
        assert decision.approved


class TestPendingList:
    async def test_lists_open_requests(self) -> None:
        gate = HumanGate(GateConfig(timeout_minutes=0.5))

        async def kick_off() -> None:
            await gate.request_confirmation(
                agent_id="a", action="delete_records", parameters={"count": 3},
            )

        task = asyncio.create_task(kick_off())
        await asyncio.sleep(0.05)
        pending = await gate.list_pending()
        assert len(pending) == 1
        # Resolve so the task can finish
        await gate.deny(pending[0].request_id, approver="t")
        await task
