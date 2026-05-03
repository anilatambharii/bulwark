"""Tests for :mod:`bulwark.core.rbac`."""

from __future__ import annotations

import pytest

from bulwark.core.rbac import AgentRole, RBACConfig, RBACEnforcer, ToolPermission
from bulwark.exceptions import ConfigurationError


class TestDefaultPermissions:
    def test_research_can_read_database(self, rbac: RBACEnforcer) -> None:
        assert rbac.check_permission(AgentRole.RESEARCH, "read_database")

    def test_research_cannot_write(self, rbac: RBACEnforcer) -> None:
        assert not rbac.check_permission(AgentRole.RESEARCH, "write_database")

    def test_research_cannot_send_email(self, rbac: RBACEnforcer) -> None:
        assert not rbac.check_permission(AgentRole.RESEARCH, "send_email")

    def test_email_role_can_send(self, rbac: RBACEnforcer) -> None:
        assert rbac.check_permission(AgentRole.EMAIL, "send_email")

    def test_email_cannot_pay(self, rbac: RBACEnforcer) -> None:
        assert not rbac.check_permission(AgentRole.EMAIL, "process_payment")

    def test_financial_payment_requires_confirmation(self, rbac: RBACEnforcer) -> None:
        assert rbac.check_permission(AgentRole.FINANCIAL, "process_payment")
        assert rbac.requires_confirmation("process_payment")

    def test_unknown_tool_denied_by_default(self, rbac: RBACEnforcer) -> None:
        assert not rbac.check_permission(AgentRole.RESEARCH, "rm_minus_rf")
        assert not rbac.check_permission(AgentRole.FINANCIAL, "rm_minus_rf")


class TestStringRoles:
    def test_string_role_accepted(self, rbac: RBACEnforcer) -> None:
        assert rbac.check_permission("research", "read_database")

    def test_invalid_string_role_denied(self, rbac: RBACEnforcer) -> None:
        assert not rbac.check_permission("nonexistent", "read_database")


class TestCustomConfig:
    def test_custom_permission_overrides_default(self) -> None:
        custom = ToolPermission(
            tool_name="read_database",
            allowed_roles={AgentRole.FINANCIAL},  # only financial
        )
        rbac = RBACEnforcer(RBACConfig(permissions=[custom]))
        assert rbac.check_permission(AgentRole.FINANCIAL, "read_database")
        assert not rbac.check_permission(AgentRole.RESEARCH, "read_database")

    def test_deny_unknown_disabled(self) -> None:
        rbac = RBACEnforcer(
            RBACConfig(permissions=[ToolPermission(tool_name="x", allowed_roles=set())],
                       deny_unknown_tools=False)
        )
        # Unknown tool now allowed for any role
        assert rbac.check_permission(AgentRole.RESEARCH, "completely_unknown")


class TestRuntimeMutation:
    def test_grant_adds_permission(self, rbac: RBACEnforcer) -> None:
        rbac.grant("custom_tool", {AgentRole.RESEARCH})
        assert rbac.check_permission(AgentRole.RESEARCH, "custom_tool")
        assert not rbac.check_permission(AgentRole.WRITE, "custom_tool")

    def test_grant_with_confirmation(self, rbac: RBACEnforcer) -> None:
        rbac.grant("danger_zone", {AgentRole.ADMIN}, confirmation=True)
        assert rbac.requires_confirmation("danger_zone")

    def test_revoke_removes(self, rbac: RBACEnforcer) -> None:
        rbac.grant("tmp", {AgentRole.RESEARCH})
        assert rbac.check_permission(AgentRole.RESEARCH, "tmp")
        rbac.revoke("tmp")
        assert not rbac.check_permission(AgentRole.RESEARCH, "tmp")

    def test_grant_empty_name_raises(self, rbac: RBACEnforcer) -> None:
        with pytest.raises(ConfigurationError):
            rbac.grant("", {AgentRole.RESEARCH})


class TestAuthorizedTools:
    def test_lists_tools_for_role(self, rbac: RBACEnforcer) -> None:
        tools = rbac.authorized_tools(AgentRole.RESEARCH)
        assert "read_database" in tools
        assert "send_email" not in tools
        assert tools == sorted(tools)  # alphabetized

    def test_invalid_role_returns_empty(self, rbac: RBACEnforcer) -> None:
        assert rbac.authorized_tools("not_a_role") == []


class TestValidation:
    def test_tool_name_with_spaces_rejected(self) -> None:
        with pytest.raises(ValueError):
            ToolPermission(tool_name="bad name", allowed_roles=set())

    def test_empty_tool_name_rejected(self) -> None:
        with pytest.raises(ValueError):
            ToolPermission(tool_name="", allowed_roles=set())

    def test_tool_permission_frozen(self) -> None:
        perm = ToolPermission(tool_name="x", allowed_roles={AgentRole.RESEARCH})
        with pytest.raises((TypeError, ValueError)):
            perm.tool_name = "y"  # type: ignore[misc]
