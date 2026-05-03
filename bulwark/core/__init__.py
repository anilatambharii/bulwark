"""Bulwark's five-layer defense core.

Each module here implements one layer of the defense-in-depth architecture:

* :mod:`bulwark.core.sanitizer` — strips obvious malicious payloads before
  any model ever sees the input.
* :mod:`bulwark.core.detector` — ML + regex injection detection.
* :mod:`bulwark.core.rbac` — compartmentalized tool permissions per agent role.
* :mod:`bulwark.core.audit` — encrypted, queryable audit trail.
* :mod:`bulwark.core.gates` — async human-confirmation workflow.
"""

from bulwark.core.audit import AuditConfig, AuditEntry, AuditTrail
from bulwark.core.detector import DetectionResult, DetectorConfig, InjectionDetector
from bulwark.core.gates import (
    ConfirmationDecision,
    ConfirmationRequest,
    ConfirmationStatus,
    GateConfig,
    HumanGate,
)
from bulwark.core.rbac import AgentRole, RBACConfig, RBACEnforcer, ToolPermission
from bulwark.core.sanitizer import InputSanitizer, SanitizerConfig, SanitizerResult

__all__ = [
    "AgentRole",
    "AuditConfig",
    "AuditEntry",
    "AuditTrail",
    "ConfirmationDecision",
    "ConfirmationRequest",
    "ConfirmationStatus",
    "DetectionResult",
    "DetectorConfig",
    "GateConfig",
    "HumanGate",
    "InjectionDetector",
    "InputSanitizer",
    "RBACConfig",
    "RBACEnforcer",
    "SanitizerConfig",
    "SanitizerResult",
    "ToolPermission",
]
