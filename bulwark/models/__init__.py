"""Bulwark fine-tuned model artifacts.

The injection classifier directory is created at install time by the model
fetch script (``scripts/fetch_models.py``) or downloaded on first use. The
detector falls back to pattern-only mode when no model is present, so this
package is safe to import even on a fresh checkout.
"""

from __future__ import annotations

from pathlib import Path

INJECTION_CLASSIFIER_PATH = Path(__file__).parent / "injection_classifier"

__all__ = ["INJECTION_CLASSIFIER_PATH"]
