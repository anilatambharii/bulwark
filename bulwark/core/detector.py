"""Layer 2 — Injection Detector (ML classifier + pattern matching).

The detector returns a single normalized risk score and the list of patterns
that contributed to it. ML scoring is *additive* on top of pattern matching:
when a fine-tuned classifier is available it adds discrimination on novel
phrasings the regex catalog cannot anticipate. When it is not available,
the detector still operates — the framework degrades gracefully.

Performance target: < 50 ms / call without ML; < 200 ms / call with a
distilled BERT-class classifier on CPU.
"""

from __future__ import annotations

import asyncio
from typing import Any

from pydantic import BaseModel, Field, field_validator

from bulwark.utils.patterns import ATTACK_PATTERNS, AttackPattern, PatternSeverity


class DetectorConfig(BaseModel):
    """Configuration for :class:`InjectionDetector`."""

    model_path: str = Field(
        default="bulwark/models/injection_classifier",
        description="Path to a fine-tuned HF classifier directory (optional).",
    )
    threshold: float = Field(
        default=0.7,
        ge=0.0,
        le=1.0,
        description="Score >= threshold is treated as an injection.",
    )
    enable_ml: bool = Field(
        default=False,
        description="Run the ML classifier when transformers is installed.",
    )
    pattern_matching: bool = True
    ml_weight: float = Field(default=0.6, ge=0.0, le=1.0)
    pattern_weight: float = Field(default=0.4, ge=0.0, le=1.0)
    device: str = "cpu"

    @field_validator("device")
    @classmethod
    def _validate_device(cls, v: str) -> str:
        v = v.lower()
        if v not in {"cpu", "cuda", "mps", "auto"}:
            raise ValueError("device must be one of: cpu, cuda, mps, auto")
        return v


class DetectionResult(BaseModel):
    """Structured detection outcome."""

    score: float = Field(ge=0.0, le=1.0)
    ml_score: float = Field(default=0.0, ge=0.0, le=1.0)
    pattern_score: float = Field(default=0.0, ge=0.0, le=1.0)
    patterns: list[str] = Field(default_factory=list)
    severities: dict[str, str] = Field(default_factory=dict)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    is_injection: bool = False
    explanation: str = ""

    model_config = {"frozen": True}


class InjectionDetector:
    """Two-phase injection detector.

    Phase 1 — *ML classifier*: a fine-tuned BERT-class model produces a
    real-valued injection probability when ``enable_ml=True`` and the
    transformers extra is installed.

    Phase 2 — *Pattern catalog*: deterministic regex matches against the
    curated catalog in :mod:`bulwark.utils.patterns`. Cheap, transparent,
    and always available.

    Final score combines both signals with configurable weights.
    """

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()
        self._patterns: tuple[AttackPattern, ...] = ATTACK_PATTERNS
        self._ml_pipeline: Any | None = None
        if self.config.enable_ml:
            self._ml_pipeline = self._try_load_ml()

    # ------------------------------------------------------------------ public

    async def detect(self, text: str) -> DetectionResult:
        """Score ``text`` for injection likelihood.

        The pattern phase always runs synchronously. The ML phase, when
        enabled, runs in a thread to avoid blocking the event loop.
        """

        if not isinstance(text, str):
            text = str(text)

        pattern_hits: list[AttackPattern] = []
        if self.config.pattern_matching:
            pattern_hits = [p for p in self._patterns if p.matches(text)]
        pattern_score = self._aggregate_pattern_score(pattern_hits)

        ml_score = 0.0
        if self._ml_pipeline is not None:
            ml_score = await asyncio.to_thread(self._ml_score, text)

        final_score = self._combine(pattern_score, ml_score)
        confidence = self._confidence(pattern_hits, ml_score)
        explanation = self._explain(pattern_hits, ml_score, final_score)

        return DetectionResult(
            score=final_score,
            ml_score=ml_score,
            pattern_score=pattern_score,
            patterns=[p.name for p in pattern_hits],
            severities={p.name: p.severity.name for p in pattern_hits},
            confidence=confidence,
            is_injection=final_score >= self.config.threshold,
            explanation=explanation,
        )

    def detect_sync(self, text: str) -> DetectionResult:
        """Synchronous wrapper for non-async callers."""

        return asyncio.run(self.detect(text))

    # ----------------------------------------------------------------- private

    @staticmethod
    def _aggregate_pattern_score(hits: list[AttackPattern]) -> float:
        if not hits:
            return 0.0
        max_severity = max(h.severity.value for h in hits)
        # Severity → base score: LOW=0.24, MEDIUM=0.48, HIGH=0.72, CRITICAL=0.96.
        # A single HIGH thus lands just past the default 0.7 threshold; a single
        # CRITICAL is a clear flag; multiple hits add a small bonus.
        base = (max_severity / PatternSeverity.CRITICAL.value) * 0.96
        bonus = min(0.10, 0.04 * (len(hits) - 1))
        return min(1.0, base + bonus)

    def _combine(self, pattern_score: float, ml_score: float) -> float:
        if not self._ml_pipeline:
            return pattern_score
        # Defense in depth — take the *max* if either signal is highly
        # confident, otherwise blend.
        if pattern_score >= 0.85 or ml_score >= 0.95:
            return max(pattern_score, ml_score)
        weighted = (
            self.config.pattern_weight * pattern_score
            + self.config.ml_weight * ml_score
        )
        # Normalize in case weights don't sum to 1.0
        denom = self.config.pattern_weight + self.config.ml_weight
        return min(1.0, weighted / denom) if denom > 0 else max(pattern_score, ml_score)

    def _confidence(self, hits: list[AttackPattern], ml_score: float) -> float:
        # Confidence is high when *both* signals agree, or when a single
        # signal is extremely strong.
        if not hits and self._ml_pipeline is None:
            return 0.95  # confidently safe (no signal at all)
        agree = bool(hits) and ml_score >= 0.5
        if agree:
            return 0.95
        if hits:
            top = max(h.severity.value for h in hits) / PatternSeverity.CRITICAL.value
            return 0.6 + 0.3 * top
        if self._ml_pipeline is not None:
            return 0.5 + 0.4 * ml_score
        return 0.7

    @staticmethod
    def _explain(hits: list[AttackPattern], ml_score: float, final: float) -> str:
        if not hits and ml_score < 0.1:
            return "No injection signals detected."
        parts: list[str] = []
        if hits:
            names = ", ".join(f"{h.name}({h.severity.name})" for h in hits)
            parts.append(f"pattern hits: {names}")
        if ml_score > 0:
            parts.append(f"ml_score={ml_score:.2f}")
        parts.append(f"final={final:.2f}")
        return "; ".join(parts)

    def _try_load_ml(self) -> Any | None:  # pragma: no cover — needs ML extras
        try:
            from transformers import pipeline  # type: ignore[import-not-found]

            return pipeline(
                "text-classification",
                model=self.config.model_path,
                device=self.config.device if self.config.device != "auto" else None,
            )
        except Exception:
            return None

    def _ml_score(self, text: str) -> float:  # pragma: no cover — needs ML extras
        if self._ml_pipeline is None:
            return 0.0
        try:
            result = self._ml_pipeline(text)
            entry = result[0] if isinstance(result, list) else result
            label = str(entry.get("label", "")).lower()
            score = float(entry.get("score", 0.0))
            if any(tag in label for tag in ("inject", "unsafe", "malicious", "label_1", "positive")):
                return score
            return 1.0 - score if "safe" in label or "label_0" in label else 0.0
        except Exception:
            return 0.0
