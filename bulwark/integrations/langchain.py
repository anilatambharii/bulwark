"""LangChain integration.

Provides a Bulwark-protected tool wrapper compatible with LangChain's
``BaseTool`` interface. Tools wrapped via :func:`secure_tool` invoke the
five-layer pipeline before the underlying tool runs.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from bulwark.api import BulwarkConfig, BulwarkSecuredExecutor, guard
from bulwark.core.audit import AuditTrail
from bulwark.core.gates import HumanGate

logger = logging.getLogger(__name__)


def secure_tool(
    name: str,
    func: Callable[..., Any],
    config: BulwarkConfig | None = None,
    *,
    is_outbound: bool = False,
    audit: AuditTrail | None = None,
    gate: HumanGate | None = None,
) -> BulwarkSecuredExecutor:
    """Wrap a single LangChain-style tool function with Bulwark.

    The wrapped callable accepts a single ``args: dict`` parameter, matching
    LangChain's ``StructuredTool.func`` signature when ``args_schema`` is a
    pydantic model.
    """

    secured = guard(
        {name: func},
        config or BulwarkConfig(),
        outbound_tools=[name] if is_outbound else None,
        audit=audit,
        gate=gate,
    )
    return secured[name]


def secure_toolkit(
    tools: dict[str, Callable[..., Any]],
    config: BulwarkConfig | None = None,
    *,
    outbound_tools: list[str] | None = None,
    audit: AuditTrail | None = None,
    gate: HumanGate | None = None,
) -> dict[str, BulwarkSecuredExecutor]:
    """Wrap a LangChain toolkit (dict of tools) with Bulwark."""

    return guard(
        tools,
        config or BulwarkConfig(),
        outbound_tools=outbound_tools,
        audit=audit,
        gate=gate,
    )
