"""MCP (Model Context Protocol) integration.

Bulwark wraps an existing MCP server's tool registry so every tool call
flows through the five-layer pipeline before the underlying handler runs.
The integration is lightweight: we don't reimplement MCP, we proxy it.

Two surfaces are exposed:

1. :func:`secure_tools` — a low-level adapter that takes a dict of
   ``tool_name -> handler`` (the shape MCP servers maintain internally) and
   returns a guarded version. Works with *any* server framework.

2. :class:`BulwarkMCPProxy` — a server-side wrapper that, given an MCP
   :class:`Server` instance, intercepts ``call_tool`` and runs Bulwark
   first. Use this when you control the MCP server.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from bulwark.api import BulwarkConfig, BulwarkSecuredExecutor, guard
from bulwark.core.audit import AuditTrail
from bulwark.core.gates import HumanGate

logger = logging.getLogger(__name__)


def secure_tools(
    handlers: dict[str, Callable[[dict[str, Any]], Any]],
    config: BulwarkConfig | None = None,
    *,
    outbound_tools: list[str] | None = None,
    audit: AuditTrail | None = None,
    gate: HumanGate | None = None,
) -> dict[str, BulwarkSecuredExecutor]:
    """Wrap an MCP-style tool dict with Bulwark's pipeline.

    Args:
        handlers: ``tool_name -> async callable`` mapping.
        config: Optional :class:`BulwarkConfig`.
        outbound_tools: Names of tools whose return values should be re-scanned.
        audit: Optional shared :class:`AuditTrail`.
        gate: Optional shared :class:`HumanGate`.
    """

    return guard(handlers, config or BulwarkConfig(), outbound_tools, audit=audit, gate=gate)


class BulwarkMCPProxy:
    """Wrap an MCP ``Server`` so every ``call_tool`` is guarded.

    Lazy-imports ``mcp`` so this module is safe to import without the extra.
    Construct with an existing MCP ``Server`` instance and a
    :class:`BulwarkConfig`; the proxy registers a hook that runs Bulwark
    before any tool handler executes.
    """

    def __init__(
        self,
        server: Any,
        config: BulwarkConfig | None = None,
        *,
        outbound_tools: list[str] | None = None,
    ) -> None:
        self.server = server
        self.config = config or BulwarkConfig()
        self.outbound_tools = set(outbound_tools or [])
        self._secured: dict[str, BulwarkSecuredExecutor] = {}
        self._audit = AuditTrail(self.config.audit_config)
        self._gate = HumanGate(self.config.gate_config)

    def register(self, name: str, handler: Callable[[dict[str, Any]], Any]) -> BulwarkSecuredExecutor:
        """Register and return a guarded handler for ``name``."""

        secured = guard(
            {name: handler},
            self.config,
            outbound_tools=[name] if name in self.outbound_tools else None,
            audit=self._audit,
            gate=self._gate,
        )[name]
        self._secured[name] = secured
        return secured

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        """Dispatch to a secured handler, raising if the tool isn't registered."""

        if name not in self._secured:
            raise KeyError(f"Tool '{name}' is not registered with the Bulwark MCP proxy.")
        return await self._secured[name](arguments)

    @property
    def audit(self) -> AuditTrail:
        return self._audit

    @property
    def gate(self) -> HumanGate:
        return self._gate
