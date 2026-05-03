"""OpenAI SDK integration.

Wraps an ``AsyncOpenAI`` client so user/system messages flow through Bulwark
before reaching the model and tool-call results are audited.
"""

from __future__ import annotations

import logging
from typing import Any

from bulwark.api import BulwarkConfig
from bulwark.core.detector import InjectionDetector
from bulwark.core.sanitizer import InputSanitizer
from bulwark.exceptions import InjectionDetectedError

logger = logging.getLogger(__name__)


class _ChatCompletionsProxy:
    def __init__(self, client: Any, sanitizer: InputSanitizer, detector: InjectionDetector,
                 config: BulwarkConfig) -> None:
        self._client = client
        self._sanitizer = sanitizer
        self._detector = detector
        self._config = config

    async def create(self, **kwargs: Any) -> Any:
        messages = kwargs.get("messages") or []
        scanned: list[dict[str, Any]] = []
        for msg in messages:
            content = msg.get("content")
            if isinstance(content, str):
                cleaned, detection = await self._scan(content)
                if detection.is_injection and self._config.alert_mode == "interrupt":
                    raise InjectionDetectedError(
                        f"Injection detected in {msg.get('role','?')} message: "
                        f"{detection.explanation}",
                        score=detection.score,
                        patterns=detection.patterns,
                    )
                scanned.append({**msg, "content": cleaned})
            else:
                scanned.append(msg)
        kwargs["messages"] = scanned
        return await self._client.chat.completions.create(**kwargs)

    async def _scan(self, content: str) -> tuple[str, Any]:
        cleaned = await self._sanitizer.sanitize(content)
        detection = await self._detector.detect(cleaned.filtered_text)
        return cleaned.filtered_text, detection


class _ChatProxy:
    def __init__(self, completions_proxy: _ChatCompletionsProxy) -> None:
        self.completions = completions_proxy


class BulwarkOpenAI:
    """Drop-in wrapper around an ``AsyncOpenAI`` client."""

    def __init__(self, client: Any, config: BulwarkConfig | None = None) -> None:
        self._client = client
        self.config = config or BulwarkConfig()
        self._sanitizer = InputSanitizer(self.config.sanitizer_config)
        self._detector = InjectionDetector(self.config.build_detector_config())
        self.chat = _ChatProxy(
            _ChatCompletionsProxy(client, self._sanitizer, self._detector, self.config)
        )

    def __getattr__(self, item: str) -> Any:
        return getattr(self._client, item)
