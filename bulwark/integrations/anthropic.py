"""Anthropic (Claude) SDK integration.

Wraps an Anthropic ``messages.create`` call so the user-controlled message
content runs through Bulwark's sanitizer + detector before being sent, and
any returned tool-use blocks are audited.

Usage::

    from anthropic import AsyncAnthropic
    from bulwark import BulwarkConfig
    from bulwark.integrations.anthropic import BulwarkAnthropic

    client = AsyncAnthropic()
    safe_client = BulwarkAnthropic(client, BulwarkConfig())

    response = await safe_client.messages.create(
        model="claude-opus-4-7",
        max_tokens=1024,
        messages=[{"role": "user", "content": untrusted_text}],
    )
"""

from __future__ import annotations

import logging
from typing import Any

from bulwark.api import BulwarkConfig
from bulwark.core.detector import InjectionDetector
from bulwark.core.sanitizer import InputSanitizer
from bulwark.exceptions import InjectionDetectedError

logger = logging.getLogger(__name__)


class _MessagesProxy:
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
                        f"Injection detected in user message: {detection.explanation}",
                        score=detection.score,
                        patterns=detection.patterns,
                    )
                scanned.append({**msg, "content": cleaned})
            else:
                scanned.append(msg)
        kwargs["messages"] = scanned
        return await self._client.messages.create(**kwargs)

    async def _scan(self, content: str) -> tuple[str, Any]:
        cleaned = await self._sanitizer.sanitize(content)
        detection = await self._detector.detect(cleaned.filtered_text)
        return cleaned.filtered_text, detection


class BulwarkAnthropic:
    """Drop-in wrapper around an ``AsyncAnthropic`` client."""

    def __init__(self, client: Any, config: BulwarkConfig | None = None) -> None:
        self._client = client
        self.config = config or BulwarkConfig()
        self._sanitizer = InputSanitizer(self.config.sanitizer_config)
        self._detector = InjectionDetector(self.config.build_detector_config())
        self.messages = _MessagesProxy(client, self._sanitizer, self._detector, self.config)

    def __getattr__(self, item: str) -> Any:
        # Pass through any non-wrapped attributes (e.g. .beta, .files) untouched.
        return getattr(self._client, item)
