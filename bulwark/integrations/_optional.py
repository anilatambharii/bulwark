"""Helper for lazy/optional imports across integration modules."""

from __future__ import annotations

import importlib
from typing import Any


def require(module_name: str, extra_name: str) -> Any:
    """Import ``module_name`` or raise an actionable :class:`ImportError`.

    Args:
        module_name: The dotted module to import (e.g. ``"anthropic"``).
        extra_name: The pip extra users should install (e.g. ``"anthropic"``)
            so the error message can tell them exactly what to run.
    """

    try:
        return importlib.import_module(module_name)
    except ImportError as exc:
        raise ImportError(
            f"The '{module_name}' package is required for this integration. "
            f"Install it with: pip install bulwark-agent-security[{extra_name}]"
        ) from exc
