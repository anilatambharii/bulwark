"""Bulwark exception hierarchy.

All Bulwark errors inherit from :class:`BulwarkError` so callers can catch the
whole framework with a single ``except`` clause when needed.
"""

from __future__ import annotations

from typing import Any


class BulwarkError(Exception):
    """Base class for every Bulwark-raised exception."""


class SecurityError(BulwarkError):
    """Raised when a security policy denies an operation.

    This is the canonical exception thrown by guarded executors when input
    sanitization, injection detection, RBAC, or human-confirmation gates
    refuse to let a tool call proceed.
    """

    def __init__(
        self,
        message: str,
        *,
        layer: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.layer = layer
        self.details = details or {}


class InjectionDetectedError(SecurityError):
    """Raised when prompt injection is detected and ``alert_mode='interrupt'``."""

    def __init__(
        self,
        message: str,
        *,
        score: float,
        patterns: list[str],
    ) -> None:
        super().__init__(
            message, layer="detector", details={"score": score, "patterns": patterns}
        )
        self.score = score
        self.patterns = patterns


class PermissionDeniedError(SecurityError):
    """Raised when RBAC blocks a tool call."""

    def __init__(self, message: str, *, role: str, tool: str) -> None:
        super().__init__(message, layer="rbac", details={"role": role, "tool": tool})
        self.role = role
        self.tool = tool


class ConfirmationDeniedError(SecurityError):
    """Raised when a human-confirmation gate denies or times out."""

    def __init__(self, message: str, *, action: str, reason: str) -> None:
        super().__init__(
            message, layer="gate", details={"action": action, "reason": reason}
        )
        self.action = action
        self.reason = reason


class ConfigurationError(BulwarkError):
    """Raised for invalid or inconsistent Bulwark configuration."""


class AuditError(BulwarkError):
    """Raised when the audit trail cannot be written or read."""
