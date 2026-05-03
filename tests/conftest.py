"""Shared pytest fixtures."""

from __future__ import annotations

from typing import Any

import pytest

from bulwark.api import BulwarkConfig
from bulwark.core.audit import AuditConfig, AuditTrail, InMemoryAuditStorage
from bulwark.core.detector import DetectorConfig, InjectionDetector
from bulwark.core.gates import GateConfig, HumanGate
from bulwark.core.rbac import AgentRole, RBACConfig, RBACEnforcer
from bulwark.core.sanitizer import InputSanitizer, SanitizerConfig
from bulwark.utils.crypto import generate_audit_key


@pytest.fixture
def sanitizer() -> InputSanitizer:
    return InputSanitizer(SanitizerConfig())


@pytest.fixture
def detector() -> InjectionDetector:
    return InjectionDetector(DetectorConfig(threshold=0.7))


@pytest.fixture
def rbac() -> RBACEnforcer:
    return RBACEnforcer(RBACConfig(default_role=AgentRole.RESEARCH))


@pytest.fixture
def audit_trail() -> AuditTrail:
    return AuditTrail(AuditConfig(), storage=InMemoryAuditStorage())


@pytest.fixture
def encrypted_audit() -> AuditTrail:
    return AuditTrail(
        AuditConfig(encryption_key=generate_audit_key()),
        storage=InMemoryAuditStorage(),
    )


@pytest.fixture
def gate() -> HumanGate:
    return HumanGate(GateConfig(timeout_minutes=0.05))  # 3-second timeout for tests


@pytest.fixture
def config() -> BulwarkConfig:
    return BulwarkConfig(
        agent_role=AgentRole.RESEARCH,
        compliance=["HIPAA", "SOC2"],
    )


@pytest.fixture
def fake_executor() -> Any:
    async def _exec(args: dict[str, Any]) -> dict[str, Any]:
        return {"echoed": args}

    return _exec
