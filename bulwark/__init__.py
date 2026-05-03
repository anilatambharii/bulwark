"""Bulwark Agent Security Framework.

The defensive barrier for production AI agents. Bulwark wraps your tool
executors with a five-layer defense pipeline (sanitizer, detector, RBAC,
audit trail, human gate) so you can ship agents into HIPAA, SOC 2, and
NERC CIP environments without re-inventing security plumbing per project.

Quickstart
----------

.. code-block:: python

    from bulwark import BulwarkConfig, guard, AgentRole

    async def fetch_url(args): ...
    async def send_email(args): ...

    secured = guard(
        executors={"fetch_url": fetch_url, "send_email": send_email},
        config=BulwarkConfig(agent_role=AgentRole.RESEARCH),
        outbound_tools=["send_email"],
    )

    result = await secured["fetch_url"]({"url": "https://example.com"})

The same call against ``send_email`` raises :class:`PermissionDeniedError`
because the ``RESEARCH`` role is not authorized to send mail.
"""

from __future__ import annotations

from bulwark.api import BulwarkConfig, BulwarkSecuredExecutor, guard
from bulwark.core import (
    AgentRole,
    AuditConfig,
    AuditEntry,
    AuditTrail,
    ConfirmationDecision,
    ConfirmationRequest,
    ConfirmationStatus,
    DetectionResult,
    DetectorConfig,
    GateConfig,
    HumanGate,
    InjectionDetector,
    InputSanitizer,
    RBACConfig,
    RBACEnforcer,
    SanitizerConfig,
    SanitizerResult,
    ToolPermission,
)
from bulwark.exceptions import (
    AuditError,
    BulwarkError,
    ConfigurationError,
    ConfirmationDeniedError,
    InjectionDetectedError,
    PermissionDeniedError,
    SecurityError,
)

__version__ = "0.1.0"

__all__ = [
    "AgentRole",
    "AuditConfig",
    "AuditEntry",
    "AuditError",
    "AuditTrail",
    "BulwarkConfig",
    "BulwarkError",
    "BulwarkSecuredExecutor",
    "ConfigurationError",
    "ConfirmationDecision",
    "ConfirmationDeniedError",
    "ConfirmationRequest",
    "ConfirmationStatus",
    "DetectionResult",
    "DetectorConfig",
    "GateConfig",
    "HumanGate",
    "InjectionDetectedError",
    "InjectionDetector",
    "InputSanitizer",
    "PermissionDeniedError",
    "RBACConfig",
    "RBACEnforcer",
    "SanitizerConfig",
    "SanitizerResult",
    "SecurityError",
    "ToolPermission",
    "__version__",
    "guard",
]
