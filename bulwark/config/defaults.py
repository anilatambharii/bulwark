"""Default security policies and compliance profiles.

These factory functions return *fresh* config instances on every call so that
mutation by one consumer never leaks into another. Compliance profiles encode
opinionated, audit-defensible defaults for HIPAA, SOC 2, and NERC CIP.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bulwark.core.audit import AuditConfig
    from bulwark.core.detector import DetectorConfig
    from bulwark.core.gates import GateConfig
    from bulwark.core.rbac import ToolPermission
    from bulwark.core.sanitizer import SanitizerConfig


class ComplianceMode(str, Enum):
    """Compliance regimes that ship with first-class support."""

    HIPAA = "hipaa"
    SOC2 = "soc2"
    NERC_CIP = "nerc_cip"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"


COMPLIANCE_PROFILES: dict[ComplianceMode, dict[str, object]] = {
    ComplianceMode.HIPAA: {
        "retention_days": 2555,  # 7 years
        "require_encryption": True,
        "require_human_confirmation_for_phi": True,
        "audit_log_immutable": True,
    },
    ComplianceMode.SOC2: {
        "retention_days": 365,
        "require_encryption": True,
        "require_human_confirmation_for_phi": False,
        "audit_log_immutable": True,
    },
    ComplianceMode.NERC_CIP: {
        "retention_days": 1095,  # 3 years
        "require_encryption": True,
        "require_human_confirmation_for_phi": False,
        "audit_log_immutable": True,
        "ot_isolation_required": True,
    },
    ComplianceMode.PCI_DSS: {
        "retention_days": 365,
        "require_encryption": True,
        "require_human_confirmation_for_phi": False,
        "audit_log_immutable": True,
    },
    ComplianceMode.GDPR: {
        "retention_days": 1095,
        "require_encryption": True,
        "require_human_confirmation_for_phi": False,
        "audit_log_immutable": True,
        "right_to_erasure": True,
    },
}


def default_sanitizer_config() -> "SanitizerConfig":
    from bulwark.core.sanitizer import SanitizerConfig

    return SanitizerConfig()


def default_detector_config() -> "DetectorConfig":
    from bulwark.core.detector import DetectorConfig

    return DetectorConfig()


def default_audit_config() -> "AuditConfig":
    from bulwark.core.audit import AuditConfig

    return AuditConfig()


def default_gate_config() -> "GateConfig":
    from bulwark.core.gates import GateConfig

    return GateConfig()


def default_rbac_permissions() -> list["ToolPermission"]:
    """Return the sensible-default RBAC permission set.

    The defaults reflect the 'least privilege per agent role' compartmentalization
    pattern: research agents get read-only; write agents get database writes
    but no email; email agents get send_email but no payment; financial agents
    get payment processing but always require human confirmation.
    """

    from bulwark.core.rbac import AgentRole, ToolPermission

    all_roles = {AgentRole.RESEARCH, AgentRole.WRITE, AgentRole.EMAIL, AgentRole.FINANCIAL}

    return [
        ToolPermission(
            tool_name="read_database",
            allowed_roles=all_roles,
        ),
        ToolPermission(
            tool_name="fetch_url",
            allowed_roles={AgentRole.RESEARCH, AgentRole.WRITE},
        ),
        ToolPermission(
            tool_name="search_web",
            allowed_roles={AgentRole.RESEARCH},
        ),
        ToolPermission(
            tool_name="write_database",
            allowed_roles={AgentRole.WRITE, AgentRole.FINANCIAL},
        ),
        ToolPermission(
            tool_name="delete_records",
            allowed_roles={AgentRole.WRITE, AgentRole.FINANCIAL},
            requires_confirmation=True,
        ),
        ToolPermission(
            tool_name="send_email",
            allowed_roles={AgentRole.EMAIL},
        ),
        ToolPermission(
            tool_name="process_payment",
            allowed_roles={AgentRole.FINANCIAL},
            requires_confirmation=True,
        ),
        ToolPermission(
            tool_name="change_credentials",
            allowed_roles={AgentRole.FINANCIAL},
            requires_confirmation=True,
        ),
    ]
