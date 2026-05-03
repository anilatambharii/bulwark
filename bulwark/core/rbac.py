"""Layer 3 — Compartmentalized RBAC.

Bulwark's RBAC follows a *zero-trust-by-default* posture: an unknown tool is
denied to every role. Permissions are explicit, declarative, and immutable
once a config is built.

The model is intentionally simple — roles, tools, and a confirmation flag —
because the empirically-observed failure mode in agent stacks is not "the
permission model wasn't expressive enough" but "the agent had email access
when all it needed was read access."
"""

from __future__ import annotations

from enum import Enum
from typing import Iterable

from pydantic import BaseModel, Field, field_validator, model_validator


class AgentRole(str, Enum):
    """Predefined agent roles. Custom roles are allowed via ``RBACConfig.custom_roles``."""

    RESEARCH = "research"
    """Read-only — query data, fetch URLs, no side effects."""

    WRITE = "write"
    """Database writes allowed; no email, no payments."""

    EMAIL = "email"
    """Email send allowed; no database writes, no payments."""

    FINANCIAL = "financial"
    """Payment processing — every action requires human confirmation."""

    ADMIN = "admin"
    """Break-glass role — should only be assumed by humans, not autonomous agents."""


class ToolPermission(BaseModel):
    """Authorize a single tool for a set of roles."""

    tool_name: str = Field(min_length=1)
    allowed_roles: set[AgentRole] = Field(default_factory=set)
    requires_confirmation: bool = False
    description: str = ""

    model_config = {"frozen": True}

    @field_validator("tool_name")
    @classmethod
    def _no_whitespace(cls, v: str) -> str:
        if v.strip() != v or " " in v:
            raise ValueError("tool_name must not contain leading/trailing whitespace or spaces")
        return v


class RBACConfig(BaseModel):
    """Configuration for the RBAC enforcer."""

    default_role: AgentRole = AgentRole.RESEARCH
    permissions: list[ToolPermission] = Field(default_factory=list)
    deny_unknown_tools: bool = True

    @model_validator(mode="after")
    def _populate_defaults(self) -> "RBACConfig":
        if not self.permissions:
            from bulwark.config.defaults import default_rbac_permissions

            object.__setattr__(self, "permissions", default_rbac_permissions())
        return self


class RBACEnforcer:
    """Enforces compartmentalized tool access for an agent role.

    .. code-block:: python

        rbac = RBACEnforcer(RBACConfig(default_role=AgentRole.RESEARCH))
        rbac.check_permission(AgentRole.RESEARCH, "read_database")  # True
        rbac.check_permission(AgentRole.RESEARCH, "send_email")      # False
        rbac.requires_confirmation("process_payment")                # True
    """

    def __init__(self, config: RBACConfig | None = None) -> None:
        self.config = config or RBACConfig()
        self._permission_map: dict[str, frozenset[AgentRole]] = {}
        self._confirmation_required: set[str] = set()
        self._descriptions: dict[str, str] = {}
        self._build()

    # ------------------------------------------------------------------ public

    def check_permission(self, role: AgentRole | str, tool_name: str) -> bool:
        """Return ``True`` iff ``role`` may invoke ``tool_name``."""

        if not isinstance(role, AgentRole):
            try:
                role = AgentRole(role)
            except ValueError:
                return False
        if tool_name not in self._permission_map:
            return not self.config.deny_unknown_tools
        return role in self._permission_map[tool_name]

    def requires_confirmation(self, tool_name: str) -> bool:
        """Return ``True`` if a tool requires human confirmation."""

        return tool_name in self._confirmation_required

    def authorized_tools(self, role: AgentRole | str) -> list[str]:
        """List tools accessible to ``role``."""

        if not isinstance(role, AgentRole):
            try:
                role = AgentRole(role)
            except ValueError:
                return []
        return sorted(
            tool for tool, roles in self._permission_map.items() if role in roles
        )

    def grant(self, tool_name: str, roles: Iterable[AgentRole], *, confirmation: bool = False) -> None:
        """Add or replace a permission entry at runtime.

        Useful for plugin-style extensions; logs an :class:`bulwark.exceptions.ConfigurationError`
        if the tool name is empty.
        """

        from bulwark.exceptions import ConfigurationError

        if not tool_name:
            raise ConfigurationError("Cannot grant a permission with an empty tool name.")
        self._permission_map[tool_name] = frozenset(roles)
        if confirmation:
            self._confirmation_required.add(tool_name)
        else:
            self._confirmation_required.discard(tool_name)

    def revoke(self, tool_name: str) -> None:
        """Remove a tool from the permission map."""

        self._permission_map.pop(tool_name, None)
        self._confirmation_required.discard(tool_name)
        self._descriptions.pop(tool_name, None)

    # ----------------------------------------------------------------- private

    def _build(self) -> None:
        for perm in self.config.permissions:
            self._permission_map[perm.tool_name] = frozenset(perm.allowed_roles)
            if perm.requires_confirmation:
                self._confirmation_required.add(perm.tool_name)
            if perm.description:
                self._descriptions[perm.tool_name] = perm.description
