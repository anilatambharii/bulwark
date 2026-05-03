"""Tests for :mod:`bulwark.config.defaults` and :mod:`bulwark.models`."""

from __future__ import annotations

from bulwark.config import COMPLIANCE_PROFILES, ComplianceMode
from bulwark.config.defaults import (
    default_audit_config,
    default_detector_config,
    default_gate_config,
    default_rbac_permissions,
    default_sanitizer_config,
)
from bulwark.core.audit import AuditConfig
from bulwark.core.detector import DetectorConfig
from bulwark.core.gates import GateConfig
from bulwark.core.rbac import AgentRole, ToolPermission
from bulwark.core.sanitizer import SanitizerConfig


class TestFactories:
    def test_sanitizer_factory_returns_fresh_instance(self) -> None:
        a = default_sanitizer_config()
        b = default_sanitizer_config()
        assert isinstance(a, SanitizerConfig)
        assert a is not b

    def test_detector_factory(self) -> None:
        cfg = default_detector_config()
        assert isinstance(cfg, DetectorConfig)
        assert 0.0 <= cfg.threshold <= 1.0

    def test_audit_factory(self) -> None:
        cfg = default_audit_config()
        assert isinstance(cfg, AuditConfig)
        assert cfg.retention_days >= 1

    def test_gate_factory(self) -> None:
        cfg = default_gate_config()
        assert isinstance(cfg, GateConfig)
        assert cfg.financial_threshold > 0

    def test_rbac_permissions_factory(self) -> None:
        perms = default_rbac_permissions()
        assert all(isinstance(p, ToolPermission) for p in perms)
        # Read access for everyone, payment requires confirmation
        names = {p.tool_name for p in perms}
        assert "read_database" in names
        assert "process_payment" in names
        payment = next(p for p in perms if p.tool_name == "process_payment")
        assert payment.requires_confirmation
        assert AgentRole.FINANCIAL in payment.allowed_roles


class TestComplianceProfiles:
    def test_hipaa_seven_year_retention(self) -> None:
        assert COMPLIANCE_PROFILES[ComplianceMode.HIPAA]["retention_days"] == 2555

    def test_all_modes_require_encryption(self) -> None:
        for profile in COMPLIANCE_PROFILES.values():
            assert profile["require_encryption"] is True

    def test_nerc_cip_requires_ot_isolation(self) -> None:
        assert COMPLIANCE_PROFILES[ComplianceMode.NERC_CIP]["ot_isolation_required"] is True

    def test_gdpr_right_to_erasure(self) -> None:
        assert COMPLIANCE_PROFILES[ComplianceMode.GDPR]["right_to_erasure"] is True


class TestModelsModule:
    def test_path_constant_exposed(self) -> None:
        from bulwark.models import INJECTION_CLASSIFIER_PATH

        # Path object that resolves under the package
        assert "injection_classifier" in str(INJECTION_CLASSIFIER_PATH)
