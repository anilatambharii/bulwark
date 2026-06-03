"""Catalog of known prompt-injection attack signatures.

Each :class:`AttackPattern` packages a regular expression with a severity
weight and a human-readable description so detection results can explain
*why* something tripped the filter, not just that it did.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum
from typing import Final, Pattern


class PatternSeverity(IntEnum):
    """How damaging a pattern's payload tends to be when it succeeds.

    Severity weights are used by :class:`bulwark.core.detector.InjectionDetector`
    to combine multiple matches into a single risk score.
    """

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass(frozen=True)
class AttackPattern:
    """A single known-bad signature."""

    name: str
    description: str
    regex: Pattern[str]
    severity: PatternSeverity

    def matches(self, text: str) -> bool:
        return self.regex.search(text) is not None


def _compile(expr: str) -> Pattern[str]:
    return re.compile(expr, flags=re.IGNORECASE | re.MULTILINE | re.DOTALL)


# Ordered roughly from most to least specific. Order matters only for
# readability — the detector evaluates the full set on every call.
ATTACK_PATTERNS: Final[tuple[AttackPattern, ...]] = (
    AttackPattern(
        name="role_marker_override",
        description="Attempt to inject a fake system / assistant / user role marker.",
        regex=_compile(
            r"(?:^|\n|\s)(?:###\s*)?(?:system|assistant|user|developer)\s*[:>\]]"
        ),
        severity=PatternSeverity.HIGH,
    ),
    AttackPattern(
        name="ignore_previous_instructions",
        description="Classic 'ignore previous instructions' jailbreak phrasing.",
        regex=_compile(
            r"\b(?:ignore|disregard|forget|override)\b[^.\n]{0,40}"
            r"\b(?:previous|prior|above|earlier|all)\b[^.\n]{0,30}"
            r"\b(?:instructions?|prompts?|rules?|directives?|constraints?)\b"
        ),
        severity=PatternSeverity.CRITICAL,
    ),
    AttackPattern(
        name="new_instruction_directive",
        description="Phrasing that tries to install a fresh directive mid-context.",
        regex=_compile(
            r"\b(?:new|updated|revised)\s+(?:instructions?|directives?|rules?|task)\b"
        ),
        severity=PatternSeverity.MEDIUM,
    ),
    AttackPattern(
        name="hidden_html_zero_size",
        description="HTML/CSS attempting to hide payload via zero size, opacity, or clipping.",
        regex=_compile(
            r"(?:font-size\s*:\s*0|opacity\s*:\s*0|"
            r"visibility\s*:\s*hidden|display\s*:\s*none|"
            r"clip\s*:\s*rect\s*\(\s*0[, ]+0[, ]+0[, ]+0\s*\))"
        ),
        severity=PatternSeverity.HIGH,
    ),
    AttackPattern(
        name="hidden_html_offscreen",
        description="HTML/CSS using absolute positioning to push content offscreen.",
        regex=_compile(r"position\s*:\s*absolute[^;]*?(?:left|top)\s*:\s*-\s*\d{2,}"),
        severity=PatternSeverity.HIGH,
    ),
    AttackPattern(
        name="zero_width_unicode",
        description="Zero-width / BOM characters used to smuggle hidden text.",
        regex=re.compile(r"[​-‍﻿⁠]"),
        severity=PatternSeverity.HIGH,
    ),
    AttackPattern(
        name="bidi_override",
        description="Right-to-left / bidi override characters (Trojan Source style).",
        regex=re.compile(r"[\u202A-\u202E\u2066-\u2069]"),
        severity=PatternSeverity.CRITICAL,
    ),
    AttackPattern(
        name="tag_injection",
        description="Fake XML-style instruction tags such as <system> or <admin>.",
        regex=_compile(
            r"<\s*/?\s*(?:system|admin|root|sudo|developer|instructions?)\s*/?\s*>"
        ),
        severity=PatternSeverity.HIGH,
    ),
    AttackPattern(
        name="base64_payload",
        description="Suspiciously long base64 blob — possible encoded payload.",
        regex=re.compile(r"(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{120,}={0,2})(?:$|[^A-Za-z0-9+/])"),
        severity=PatternSeverity.MEDIUM,
    ),
    AttackPattern(
        name="data_url_payload",
        description="data: URLs that may smuggle executable HTML or scripts.",
        regex=_compile(r"data:\s*(?:text/html|application/javascript|image/svg\+xml)"),
        severity=PatternSeverity.HIGH,
    ),
    AttackPattern(
        name="javascript_url",
        description="javascript: URLs.",
        regex=_compile(r"javascript\s*:"),
        severity=PatternSeverity.HIGH,
    ),
    AttackPattern(
        name="exfiltration_url",
        description="Suspicious instruction to render an image to an external URL (data exfiltration).",
        regex=_compile(
            r"!\[[^\]]*\]\(\s*https?://[^\s)]+\?[^)]*(?:\$\{|\{\{|<%)"
        ),
        severity=PatternSeverity.CRITICAL,
    ),
    AttackPattern(
        name="tool_invocation_smuggle",
        description="Embedded JSON tool-call envelope inside untrusted text.",
        regex=_compile(
            r"\"(?:tool|function|name)\"\s*:\s*\"[^\"]+\"\s*,\s*\"(?:arguments|parameters|input)\"\s*:"
        ),
        severity=PatternSeverity.HIGH,
    ),
    AttackPattern(
        name="developer_mode_jailbreak",
        description="DAN / 'developer mode' jailbreak phrasing.",
        regex=_compile(
            r"\b(?:DAN|do\s*anything\s*now|developer\s*mode|jailbreak\s*mode|"
            r"unfiltered\s*mode|god\s*mode)\b"
        ),
        severity=PatternSeverity.HIGH,
    ),
    AttackPattern(
        name="credential_phishing",
        description="Requests for credentials, API keys, or secrets in user-controlled text.",
        regex=_compile(
            r"\b(?:reveal|share|send|email)\b[^.\n]{0,40}"
            r"\b(?:api[_\s-]?key|password|secret|token|credential)s?\b"
        ),
        severity=PatternSeverity.CRITICAL,
    ),
    AttackPattern(
        name="prompt_leak_directive",
        description="Attempts to extract the model's system prompt or hidden instructions.",
        regex=_compile(
            r"\b(?:repeat|output|print|show|display|tell\s+me|share)\b[^.\n]{0,50}"
            r"\b(?:system\s+prompt|hidden\s+instructions?|initial\s+prompt|"
            r"your\s+instructions?|your\s+rules?|your\s+context)\b"
        ),
        severity=PatternSeverity.HIGH,
    ),
    AttackPattern(
        name="virtualization_jailbreak",
        description="Roleplay / persona framing to bypass policy (DAN-style).",
        regex=_compile(
            r"\b(?:pretend|imagine|roleplay|act\s+as|you\s+are\s+now|"
            r"simulate|behave\s+as|you\s+have\s+no\s+restrictions?|"
            r"without\s+(?:any\s+)?restrictions?|uncensored\s+mode)\b"
        ),
        severity=PatternSeverity.HIGH,
    ),
    AttackPattern(
        name="memory_poisoning",
        description="Instructions to persist hostile context across future sessions.",
        regex=_compile(
            r"\b(?:remember|store|save|memorize|record)\b[^.\n]{0,40}"
            r"\b(?:(?:all\s+)?future\s+(?:sessions?|conversations?|chats?)|"
            r"permanently|always\s+from\s+now)\b"
        ),
        severity=PatternSeverity.HIGH,
    ),
    AttackPattern(
        name="special_token_injection",
        description="LLM special / control tokens embedded in user-controlled text.",
        regex=_compile(
            r"(?:<\|(?:endoftext|im_start|im_end|system|pad|eos|bos|"
            r"end_header_id|start_header_id)\|>|"
            r"\[INST\]|\[/INST\]|\[SYS\]|\[/SYS\]|<s>|</s>)"
        ),
        severity=PatternSeverity.CRITICAL,
    ),
    AttackPattern(
        name="indirect_tool_invocation",
        description="Embedded directive attempting to invoke a specific tool or function by name.",
        regex=_compile(
            r"\b(?:call|invoke|execute|run|trigger|use)\b[^.\n]{0,30}"
            r"\b(?:the\s+)?(?:tool|function|plugin|action|skill)\b[^.\n]{0,20}"
            r"\b(?:with|using|and\s+pass)\b"
        ),
        severity=PatternSeverity.HIGH,
    ),
    AttackPattern(
        name="markdown_exfil_link",
        description="Markdown image/link with external URL and templated query params — classic data exfiltration via renderer.",
        regex=_compile(
            r"!?\[[^\]]{0,80}\]\(\s*https?://[^\s)]{10,}\?[^)]*"
            r"(?:\{\{|\$\{|<%|%7B%7B|<\?)"
        ),
        severity=PatternSeverity.CRITICAL,
    ),
    AttackPattern(
        name="context_window_overflow",
        description="Extremely large repetitive padding block used to push instructions out of attention window.",
        regex=re.compile(r"(.)\1{2000,}", re.DOTALL),
        severity=PatternSeverity.MEDIUM,
    ),
)


def patterns_by_name() -> dict[str, AttackPattern]:
    """Return the pattern catalog keyed by name (useful for tests / overrides)."""

    return {p.name: p for p in ATTACK_PATTERNS}
