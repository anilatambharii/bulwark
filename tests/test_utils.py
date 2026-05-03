"""Tests for :mod:`bulwark.utils.patterns` and :mod:`bulwark.utils.crypto`."""

from __future__ import annotations

import pytest

from bulwark.utils.crypto import AuditCipher, generate_audit_key
from bulwark.utils.patterns import ATTACK_PATTERNS, PatternSeverity, patterns_by_name


class TestPatternCatalog:
    def test_catalog_non_empty(self) -> None:
        assert len(ATTACK_PATTERNS) >= 10

    def test_all_patterns_have_required_fields(self) -> None:
        for p in ATTACK_PATTERNS:
            assert p.name
            assert p.description
            assert isinstance(p.severity, PatternSeverity)
            # Every regex should compile and be queryable
            assert hasattr(p.regex, "search")

    def test_unique_names(self) -> None:
        names = [p.name for p in ATTACK_PATTERNS]
        assert len(names) == len(set(names))

    def test_patterns_by_name_lookup(self) -> None:
        m = patterns_by_name()
        assert "ignore_previous_instructions" in m
        assert m["ignore_previous_instructions"].severity == PatternSeverity.CRITICAL

    def test_severity_ordering(self) -> None:
        assert PatternSeverity.LOW < PatternSeverity.MEDIUM
        assert PatternSeverity.MEDIUM < PatternSeverity.HIGH
        assert PatternSeverity.HIGH < PatternSeverity.CRITICAL


class TestCryptoBytes:
    def test_encrypts_and_decrypts_bytes(self) -> None:
        cipher = AuditCipher(generate_audit_key())
        token = cipher.encrypt(b"binary \x00\x01\x02 payload")
        assert cipher.decrypt(token) == b"binary \x00\x01\x02 payload"

    def test_decrypt_text_helper(self) -> None:
        cipher = AuditCipher(generate_audit_key())
        token = cipher.encrypt("hello")
        assert cipher.decrypt_text(token) == "hello"

    def test_str_token_input_accepted(self) -> None:
        cipher = AuditCipher(generate_audit_key())
        token = cipher.encrypt("hello").decode("ascii")
        assert cipher.decrypt(token) == b"hello"
