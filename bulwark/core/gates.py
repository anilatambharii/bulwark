"""Layer 5 — Human Confirmation Gates.

When a tool call is high-stakes (large payment, mass deletion, credential
change), automatic execution is unsafe regardless of how confident the agent
is. The :class:`HumanGate` provides an asynchronous workflow:

1. The framework opens a :class:`ConfirmationRequest` and dispatches it to
   one or more notification channels (email, Slack webhook, custom callback).
2. A human responds via :meth:`HumanGate.approve` or :meth:`HumanGate.deny`
   — typically wired to a webhook receiver.
3. The original ``await`` returns ``True`` (approve), ``False`` (deny), or
   times out and auto-denies.

The implementation deliberately uses :class:`asyncio.Event` rather than
polling so a thousand pending requests cost essentially zero CPU.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Awaitable, Callable

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


NotificationCallback = Callable[["ConfirmationRequest"], Awaitable[None]]


class ConfirmationStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    EXPIRED = "expired"


class GateConfig(BaseModel):
    """Configuration for the human-confirmation gate."""

    financial_threshold: float = Field(default=100.0, ge=0.0)
    """Dollar amount above which payment processing requires confirmation."""

    data_deletion_threshold: int = Field(default=1, ge=0)
    """Record count at or above which deletion requires confirmation."""

    credential_change: bool = True
    """Always require confirmation for credential changes."""

    timeout_minutes: float = Field(default=5.0, gt=0)
    """Auto-deny after this many minutes."""

    auto_approve_low_risk: bool = False
    """If True, requests with risk_score < 0.2 bypass the gate."""

    low_risk_threshold: float = Field(default=0.2, ge=0.0, le=1.0)


class ConfirmationRequest(BaseModel):
    """A pending request for human approval."""

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    agent_id: str
    action: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    reason: str = ""
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    status: ConfirmationStatus = ConfirmationStatus.PENDING

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or datetime.now(timezone.utc)) >= self.expires_at


class ConfirmationDecision(BaseModel):
    """A resolved confirmation outcome."""

    request_id: str
    status: ConfirmationStatus
    approver: str | None = None
    note: str | None = None
    resolved_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def approved(self) -> bool:
        return self.status == ConfirmationStatus.APPROVED


class _PendingEntry:
    """Internal — bookkeeping for a single pending confirmation."""

    __slots__ = ("request", "event", "decision")

    def __init__(self, request: ConfirmationRequest) -> None:
        self.request = request
        self.event = asyncio.Event()
        self.decision: ConfirmationDecision | None = None


class HumanGate:
    """Async approval workflow for high-stakes actions.

    Notification channels are registered via :meth:`add_channel`; each is an
    awaitable that receives a :class:`ConfirmationRequest`. Handlers can
    notify Slack, send email, push to a webhook, or anything else — failures
    in any one channel do not block the others.
    """

    def __init__(self, config: GateConfig | None = None) -> None:
        self.config = config or GateConfig()
        self._pending: dict[str, _PendingEntry] = {}
        self._lock = asyncio.Lock()
        self._channels: list[NotificationCallback] = []

    # ------------------------------------------------------------------ public

    def add_channel(self, callback: NotificationCallback) -> None:
        """Register a notification callback (Slack, email, webhook, etc.)."""

        self._channels.append(callback)

    def needs_confirmation(self, action: str, parameters: dict[str, Any] | None = None) -> bool:
        """Decide whether a tool call needs human approval based on policy."""

        params = parameters or {}
        action = action.lower()

        if action in {"process_payment", "transfer_funds", "issue_refund"}:
            amount = float(params.get("amount", 0) or 0)
            return amount >= self.config.financial_threshold

        if action in {"delete_records", "drop_table", "purge_data"}:
            count = int(params.get("count", params.get("records", 0)) or 0)
            return count >= self.config.data_deletion_threshold

        if action in {"change_credentials", "rotate_secret", "update_password", "grant_access"}:
            return self.config.credential_change

        return False

    async def request_confirmation(
        self,
        agent_id: str,
        action: str,
        parameters: dict[str, Any] | None = None,
        risk_score: float = 0.0,
        reason: str = "",
        timeout_minutes: float | None = None,
    ) -> ConfirmationDecision:
        """Open a confirmation request and await its resolution.

        If ``auto_approve_low_risk`` is enabled and the score is below the
        threshold, the request is approved immediately without notifying.
        Otherwise it dispatches to all registered channels and blocks on an
        :class:`asyncio.Event` until approval, denial, or timeout.
        """

        if self.config.auto_approve_low_risk and risk_score < self.config.low_risk_threshold:
            return ConfirmationDecision(
                request_id="auto",
                status=ConfirmationStatus.APPROVED,
                approver="auto-approval-policy",
                note="risk below threshold",
            )

        timeout = timeout_minutes if timeout_minutes is not None else self.config.timeout_minutes
        request = ConfirmationRequest(
            agent_id=agent_id,
            action=action,
            parameters=parameters or {},
            risk_score=risk_score,
            reason=reason,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=timeout),
        )
        entry = _PendingEntry(request)

        async with self._lock:
            self._pending[request.request_id] = entry

        await self._notify(request)

        try:
            await asyncio.wait_for(entry.event.wait(), timeout=timeout * 60)
            assert entry.decision is not None
            return entry.decision
        except asyncio.TimeoutError:
            timeout_decision = ConfirmationDecision(
                request_id=request.request_id,
                status=ConfirmationStatus.TIMEOUT,
                note=f"Auto-denied after {timeout} minutes.",
            )
            async with self._lock:
                pending = self._pending.get(request.request_id)
                if pending and pending.decision is None:
                    pending.decision = timeout_decision
                    pending.request.status = ConfirmationStatus.TIMEOUT
                    pending.event.set()
            return timeout_decision
        finally:
            async with self._lock:
                self._pending.pop(request.request_id, None)

    async def approve(self, request_id: str, *, approver: str, note: str | None = None) -> bool:
        """Approve a pending request. Returns True if the request was found and pending."""

        return await self._resolve(request_id, ConfirmationStatus.APPROVED, approver, note)

    async def deny(self, request_id: str, *, approver: str, note: str | None = None) -> bool:
        """Deny a pending request. Returns True if the request was found and pending."""

        return await self._resolve(request_id, ConfirmationStatus.DENIED, approver, note)

    async def list_pending(self) -> list[ConfirmationRequest]:
        """Snapshot of currently pending requests."""

        async with self._lock:
            return [entry.request for entry in self._pending.values()]

    # ----------------------------------------------------------------- private

    async def _resolve(
        self,
        request_id: str,
        status: ConfirmationStatus,
        approver: str,
        note: str | None,
    ) -> bool:
        async with self._lock:
            entry = self._pending.get(request_id)
            if entry is None or entry.decision is not None:
                return False
            entry.decision = ConfirmationDecision(
                request_id=request_id,
                status=status,
                approver=approver,
                note=note,
            )
            entry.request.status = status
            entry.event.set()
        return True

    async def _notify(self, request: ConfirmationRequest) -> None:
        if not self._channels:
            logger.info(
                "No notification channels registered; confirmation will rely on direct API calls.",
            )
            return
        results = await asyncio.gather(
            *(self._safe_notify(ch, request) for ch in self._channels),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, BaseException):
                logger.warning("Notification channel raised: %s", result)

    @staticmethod
    async def _safe_notify(channel: NotificationCallback, request: ConfirmationRequest) -> None:
        try:
            await channel(request)
        except Exception as exc:
            logger.warning("Channel callback failed: %s", exc)
