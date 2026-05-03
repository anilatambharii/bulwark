"""Layer 1 — Input Sanitizer (dual-model pattern).

The sanitizer strips well-known malicious encodings (zero-width characters,
hidden HTML, bidi overrides, smuggled tool envelopes) *before* any reasoning
model touches the text. It intentionally has zero outbound capability: no
filesystem, no network, no subprocess. If it is somehow compromised, the
blast radius is limited to a return value the caller is free to drop.

Two-pass design:

1. **Lexical scrub** — fast regex-driven removal of obviously hostile
   patterns. Always runs.
2. **Optional ML re-rank** — when ``transformers`` is installed and a model
   path is provided, an additional classifier scores residual risk. The
   sanitizer never *executes* anything based on this score; it only tags
   the result so downstream layers can decide.

Performance target: < 100 ms / call on a typical 4 KiB input.
"""

from __future__ import annotations

import asyncio
import html
import re
import unicodedata
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field, field_validator

from bulwark.utils.patterns import ATTACK_PATTERNS, AttackPattern

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Iterable

# Sanitizer-specific scrubbing patterns (separate from the detector catalog
# because these are *cleanup* operations rather than risk signals).
_ZERO_WIDTH_RE = re.compile(r"[​-‍﻿⁠]")
_BIDI_OVERRIDE_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069]")
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_HTML_TAG_RE = re.compile(r"<[^>]{1,400}>", re.DOTALL)
_HTML_HIDDEN_STYLE_RE = re.compile(
    r"style\s*=\s*\"[^\"]*?(?:font-size\s*:\s*0|opacity\s*:\s*0|"
    r"display\s*:\s*none|visibility\s*:\s*hidden)[^\"]*\"",
    re.IGNORECASE,
)
_DATA_URL_RE = re.compile(r"data:[^,\s]{1,200},", re.IGNORECASE)
_JS_URL_RE = re.compile(r"javascript\s*:", re.IGNORECASE)


class SanitizerConfig(BaseModel):
    """Configuration for the input sanitizer."""

    model_name: str = Field(
        default="distilbert-base-uncased",
        description="HuggingFace model name used for ML re-rank when ML is enabled.",
    )
    max_length: int = Field(default=8192, ge=1, le=131072)
    enable_ml: bool = Field(
        default=False,
        description="Run optional ML re-rank when transformers is installed.",
    )
    strip_html: bool = True
    strip_zero_width: bool = True
    strip_bidi: bool = True
    normalize_unicode: bool = True
    decode_html_entities: bool = True
    device: str = "cpu"

    @field_validator("device")
    @classmethod
    def _validate_device(cls, v: str) -> str:
        v = v.lower()
        if v not in {"cpu", "cuda", "mps", "auto"}:
            raise ValueError("device must be one of: cpu, cuda, mps, auto")
        return v


class SanitizerResult(BaseModel):
    """Outcome of a sanitization pass."""

    filtered_text: str = Field(description="Sanitized text safe for downstream consumption.")
    risk_score: float = Field(ge=0.0, le=1.0)
    detected_patterns: list[str] = Field(default_factory=list)
    bytes_removed: int = 0
    truncated: bool = False
    is_safe: bool = True

    model_config = {"frozen": True}


class InputSanitizer:
    """Dual-model sanitizer with zero outbound permissions.

    The instance never opens a socket, writes to disk, or spawns a process.
    Calling :meth:`sanitize` is therefore safe to do on fully untrusted text
    without supervision.
    """

    def __init__(self, config: SanitizerConfig | None = None) -> None:
        self.config = config or SanitizerConfig()
        self._patterns: tuple[AttackPattern, ...] = ATTACK_PATTERNS
        self._ml_pipeline: Any | None = None
        if self.config.enable_ml:
            self._ml_pipeline = self._try_load_ml()

    # ------------------------------------------------------------------ public

    async def sanitize(self, untrusted_input: str) -> SanitizerResult:
        """Strip malicious encodings from ``untrusted_input`` and score residual risk.

        The implementation is async to give callers a uniform await-everywhere
        API; the lexical pass is CPU-bound and runs synchronously, while any
        ML pass is dispatched to a thread to avoid blocking the event loop.
        """

        if not isinstance(untrusted_input, str):
            untrusted_input = str(untrusted_input)

        original_len = len(untrusted_input)
        text = untrusted_input
        truncated = False
        if len(text) > self.config.max_length:
            text = text[: self.config.max_length]
            truncated = True

        text = self._lexical_scrub(text)
        detected = self._detect(text)

        risk = self._score_risk(detected)
        if self._ml_pipeline is not None:
            ml_risk = await asyncio.to_thread(self._ml_score, text)
            risk = max(risk, ml_risk)

        return SanitizerResult(
            filtered_text=text,
            risk_score=risk,
            detected_patterns=[p.name for p in detected],
            bytes_removed=max(0, original_len - len(text)),
            truncated=truncated,
            is_safe=risk < 0.5 and not truncated,
        )

    def sanitize_sync(self, untrusted_input: str) -> SanitizerResult:
        """Synchronous wrapper for non-async callers."""

        return asyncio.run(self.sanitize(untrusted_input))

    # ----------------------------------------------------------------- private

    def _lexical_scrub(self, text: str) -> str:
        cfg = self.config
        if cfg.normalize_unicode:
            text = unicodedata.normalize("NFKC", text)
        if cfg.decode_html_entities:
            text = html.unescape(text)
        if cfg.strip_zero_width:
            text = _ZERO_WIDTH_RE.sub("", text)
        if cfg.strip_bidi:
            text = _BIDI_OVERRIDE_RE.sub("", text)
        text = _CONTROL_CHARS_RE.sub("", text)
        if cfg.strip_html:
            text = _HTML_HIDDEN_STYLE_RE.sub("", text)
            text = _HTML_TAG_RE.sub("", text)
        text = _DATA_URL_RE.sub("data-url-removed:", text)
        text = _JS_URL_RE.sub("javascript-removed:", text)
        return text

    def _detect(self, text: str) -> list[AttackPattern]:
        return [p for p in self._patterns if p.matches(text)]

    @staticmethod
    def _score_risk(detected: "Iterable[AttackPattern]") -> float:
        weighted = sum(p.severity.value for p in detected)
        if weighted == 0:
            return 0.0
        # Normalize: a single CRITICAL match (severity 4) -> ~0.8; multiple
        # criticals saturate quickly toward 1.0.
        score = 1.0 - (1.0 / (1.0 + 0.55 * weighted))
        return min(1.0, max(0.0, score))

    def _try_load_ml(self) -> Any | None:
        try:  # pragma: no cover — exercised only when transformers is installed
            from transformers import pipeline  # type: ignore[import-not-found]

            return pipeline(
                "text-classification",
                model=self.config.model_name,
                device=self.config.device if self.config.device != "auto" else None,
            )
        except Exception:  # pragma: no cover
            return None

    def _ml_score(self, text: str) -> float:  # pragma: no cover — needs ML extras
        if self._ml_pipeline is None:
            return 0.0
        try:
            result = self._ml_pipeline(text[: self.config.max_length])
            if not result:
                return 0.0
            entry = result[0] if isinstance(result, list) else result
            label = str(entry.get("label", "")).lower()
            score = float(entry.get("score", 0.0))
            if any(tag in label for tag in ("inject", "unsafe", "malicious", "label_1")):
                return score
            return 0.0
        except Exception:
            return 0.0
