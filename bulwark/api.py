"""Main Bulwark API — :func:`guard` wraps tool executors with the five-layer pipeline.

The wrapping is structured as a small dataclass-style executor object so each
guarded tool has stable identity for testing and introspection. The pipeline
order is fixed: RBAC → sanitize → detect → gate → execute → audit. Each layer
short-circuits the rest on denial.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from pydantic import BaseModel, ConfigDict, Field, field_validator

from bulwark.core.audit import AuditConfig, AuditEntry, AuditTrail
from bulwark.core.detector import DetectorConfig, InjectionDetector
from bulwark.core.gates import GateConfig, HumanGate
from bulwark.core.rbac import AgentRole, RBACConfig, RBACEnforcer
from bulwark.core.sanitizer import InputSanitizer, SanitizerConfig
from bulwark.exceptions import (
    ConfigurationError,
    ConfirmationDeniedError,
    InjectionDetectedError,
    PermissionDeniedError,
)

logger = logging.getLogger(__name__)

ToolExecutor = Callable[..., Any]
"""A guarded executor takes ``args`` (any signature) and returns either a value or an awaitable."""

AlertMode = str  # 'log' | 'alert' | 'interrupt'


class BulwarkConfig(BaseModel):
    """Top-level Bulwark configuration.

    Most fields default to safe production values; you usually only need to
    override ``agent_role`` and ``compliance``.
    """

    alert_mode: AlertMode = Field(default="interrupt")
    threshold: float = Field(default=0.7, ge=0.0, le=1.0)
    compliance: list[str] = Field(default_factory=list)
    agent_role: AgentRole = AgentRole.RESEARCH
    agent_id: str = "default"
    user_id: str = "default"

    sanitizer_config: SanitizerConfig = Field(default_factory=SanitizerConfig)
    detector_config: DetectorConfig | None = None
    rbac_config: RBACConfig = Field(default_factory=RBACConfig)
    audit_config: AuditConfig = Field(default_factory=AuditConfig)
    gate_config: GateConfig = Field(default_factory=GateConfig)

    model_config = ConfigDict(arbitrary_types_allowed=True)

    @field_validator("alert_mode")
    @classmethod
    def _validate_alert_mode(cls, v: str) -> str:
        if v not in {"log", "alert", "interrupt"}:
            raise ConfigurationError("alert_mode must be one of: log, alert, interrupt")
        return v

    @field_validator("compliance")
    @classmethod
    def _normalize(cls, v: list[str]) -> list[str]:
        return [s.upper().replace("-", "_") for s in v]

    def build_detector_config(self) -> DetectorConfig:
        if self.detector_config is not None:
            return self.detector_config
        return DetectorConfig(threshold=self.threshold)


@dataclass
class BulwarkSecuredExecutor:
    """A single guarded tool executor.

    Returned from :func:`guard` keyed by tool name. Calling the instance runs
    the full five-layer pipeline; introspection attributes (``tool_name``,
    ``is_outbound``, ``original``) help with debugging and metrics.
    """

    tool_name: str
    original: ToolExecutor
    config: BulwarkConfig
    sanitizer: InputSanitizer
    detector: InjectionDetector
    rbac: RBACEnforcer
    audit: AuditTrail
    gate: HumanGate
    is_outbound: bool = False
    metrics: dict[str, int] = field(
        default_factory=lambda: {
            "calls": 0,
            "approved": 0,
            "blocked": 0,
            "escalated": 0,
            "denied": 0,
        }
    )

    async def __call__(self, args: dict[str, Any] | None = None, /, **kwargs: Any) -> Any:
        if args is None:
            args = kwargs
        elif kwargs:
            args = {**args, **kwargs}

        self.metrics["calls"] += 1
        start = time.perf_counter()
        agent_id = self.config.agent_id
        user_id = self.config.user_id
        compliance_tags = list(self.config.compliance)

        # Layer 1 — RBAC
        if not self.rbac.check_permission(self.config.agent_role, self.tool_name):
            self.metrics["denied"] += 1
            await self._record(
                args=args,
                output={},
                risk_score=1.0,
                decision="denied",
                source=["rbac:role-not-authorized"],
                layer="rbac",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
            raise PermissionDeniedError(
                f"Agent role '{self.config.agent_role.value}' is not authorized for tool '{self.tool_name}'.",
                role=self.config.agent_role.value,
                tool=self.tool_name,
            )

        # Layer 2 — Sanitization
        sanitizer_result = await self.sanitizer.sanitize(_args_to_text(args))

        # Layer 3 — Injection detection
        detection = await self.detector.detect(sanitizer_result.filtered_text)

        # Layer 4 — Decision based on detection + alert mode
        if detection.is_injection:
            if self.config.alert_mode == "interrupt":
                self.metrics["blocked"] += 1
                await self._record(
                    args=args,
                    output={},
                    risk_score=detection.score,
                    decision="blocked",
                    source=[f"detector:{name}" for name in detection.patterns]
                    or ["detector:ml-only"],
                    layer="detector",
                    duration_ms=(time.perf_counter() - start) * 1000,
                    reasoning=detection.explanation,
                )
                raise InjectionDetectedError(
                    f"Prompt injection detected (score={detection.score:.2f}) "
                    f"for tool '{self.tool_name}': {detection.explanation}",
                    score=detection.score,
                    patterns=detection.patterns,
                )
            if self.config.alert_mode == "alert":
                logger.warning(
                    "Bulwark alert — possible injection on %s (score=%.2f, patterns=%s)",
                    self.tool_name,
                    detection.score,
                    detection.patterns,
                )

        # Layer 5 — Human confirmation gate
        gate_required = self.gate.needs_confirmation(
            self.tool_name, args
        ) or self.rbac.requires_confirmation(self.tool_name)
        if gate_required:
            decision = await self.gate.request_confirmation(
                agent_id=agent_id,
                action=self.tool_name,
                parameters=args,
                risk_score=detection.score,
                reason=detection.explanation,
            )
            if not decision.approved:
                self.metrics["escalated"] += 1
                await self._record(
                    args=args,
                    output={},
                    risk_score=detection.score,
                    decision="escalated",
                    source=[f"gate:{decision.status.value}"],
                    layer="gate",
                    duration_ms=(time.perf_counter() - start) * 1000,
                )
                raise ConfirmationDeniedError(
                    f"Human confirmation {decision.status.value} for '{self.tool_name}'.",
                    action=self.tool_name,
                    reason=decision.status.value,
                )

        # Execute the original tool
        try:
            result = self.original(args)
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:
            await self._record(
                args=args,
                output={"error": str(exc)},
                risk_score=detection.score,
                decision="error",
                source=[f"executor:{type(exc).__name__}"],
                layer="executor",
                duration_ms=(time.perf_counter() - start) * 1000,
            )
            raise

        # Outbound exfiltration check — re-scan the *output* of tools that
        # send data externally so a poisoned response can't smuggle PII.
        if self.is_outbound:
            outbound_text = _args_to_text(args) + " " + str(result)[:4096]
            outbound_detection = await self.detector.detect(outbound_text)
            if outbound_detection.is_injection and self.config.alert_mode == "interrupt":
                self.metrics["blocked"] += 1
                await self._record(
                    args=args,
                    output={"result": _truncate(result)},
                    risk_score=outbound_detection.score,
                    decision="blocked",
                    source=[
                        f"outbound:{name}" for name in outbound_detection.patterns
                    ]
                    or ["outbound:ml-only"],
                    layer="outbound",
                    duration_ms=(time.perf_counter() - start) * 1000,
                    reasoning=outbound_detection.explanation,
                )
                raise InjectionDetectedError(
                    f"Outbound exfiltration risk on '{self.tool_name}' "
                    f"(score={outbound_detection.score:.2f}): {outbound_detection.explanation}",
                    score=outbound_detection.score,
                    patterns=outbound_detection.patterns,
                )

        self.metrics["approved"] += 1
        await self._record(
            args=args,
            output={"result": _truncate(result)},
            risk_score=detection.score,
            decision="approved",
            source=[f"detector:{p}" for p in detection.patterns],
            layer=None,
            duration_ms=(time.perf_counter() - start) * 1000,
        )
        return result

    async def _record(
        self,
        *,
        args: dict[str, Any],
        output: dict[str, Any],
        risk_score: float,
        decision: str,
        source: list[str],
        layer: str | None,
        duration_ms: float,
        reasoning: str | None = None,
    ) -> None:
        try:
            await self.audit.log(
                AuditEntry(
                    audit_id=str(uuid.uuid4()),
                    timestamp=datetime.now(timezone.utc),
                    agent_id=self.config.agent_id,
                    user_id=self.config.user_id,
                    tool_called=self.tool_name,
                    input_data=args,
                    output_data=output,
                    risk_score=risk_score,
                    decision=decision,
                    source_data=source,
                    reasoning_chain=reasoning,
                    compliance_tags=list(self.config.compliance),
                    layer=layer,
                    duration_ms=duration_ms,
                )
            )
        except Exception as exc:  # pragma: no cover — audit must never crash the request
            logger.error("Audit logging failed: %s", exc)


def guard(
    executors: dict[str, ToolExecutor],
    config: BulwarkConfig | None = None,
    outbound_tools: list[str] | None = None,
    *,
    audit: AuditTrail | None = None,
    gate: HumanGate | None = None,
) -> dict[str, BulwarkSecuredExecutor]:
    """Wrap a dict of tool executors with the Bulwark security pipeline.

    Args:
        executors: Mapping of ``tool_name -> callable``. Callables may be
            sync or async; the wrapper handles both. Each callable should
            accept a single ``args: dict`` argument.
        config: Top-level :class:`BulwarkConfig`. Defaults are production-safe.
        outbound_tools: Names of tools whose return values should be re-scanned
            for exfiltration (e.g. ``send_email``, ``post_webhook``).
        audit: Optional shared :class:`AuditTrail`. If omitted, a new one is
            built from ``config.audit_config``. Sharing a trail across
            ``guard()`` calls keeps a single forensic timeline.
        gate: Optional shared :class:`HumanGate`.

    Returns:
        A dict of :class:`BulwarkSecuredExecutor` instances callable like
        the originals but with the full pipeline applied.

    Raises:
        ConfigurationError: if ``executors`` is empty or contains non-callables.
    """

    if not executors:
        raise ConfigurationError("guard() requires at least one executor.")
    for name, fn in executors.items():
        if not callable(fn):
            raise ConfigurationError(f"Executor '{name}' is not callable.")
        if not name or not isinstance(name, str):
            raise ConfigurationError("Tool names must be non-empty strings.")

    cfg = config or BulwarkConfig()
    outbound = set(outbound_tools or [])

    sanitizer = InputSanitizer(cfg.sanitizer_config)
    detector = InjectionDetector(cfg.build_detector_config())
    rbac = RBACEnforcer(cfg.rbac_config)
    audit_trail = audit or AuditTrail(cfg.audit_config)
    human_gate = gate or HumanGate(cfg.gate_config)

    return {
        name: BulwarkSecuredExecutor(
            tool_name=name,
            original=fn,
            config=cfg,
            sanitizer=sanitizer,
            detector=detector,
            rbac=rbac,
            audit=audit_trail,
            gate=human_gate,
            is_outbound=name in outbound,
        )
        for name, fn in executors.items()
    }


def _args_to_text(args: dict[str, Any]) -> str:
    """Flatten ``args`` into a single string for sanitization / detection."""

    parts: list[str] = []
    for k, v in args.items():
        parts.append(f"{k}={_render(v)}")
    return " | ".join(parts)


def _render(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)) or value is None:
        return str(value)
    try:
        import json

        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return str(value)


def _truncate(value: Any, *, limit: int = 1000) -> str:
    s = str(value)
    return s if len(s) <= limit else s[:limit] + "...[truncated]"
