"""Bulwark integrations with popular agent SDKs and protocols.

Each submodule degrades gracefully when its underlying dependency is not
installed: importing :mod:`bulwark.integrations.anthropic` without the
``anthropic`` extra will raise an :class:`ImportError` only on first use,
not at import time.
"""

from __future__ import annotations

__all__ = [
    "anthropic",
    "langchain",
    "mcp",
    "openai",
]
