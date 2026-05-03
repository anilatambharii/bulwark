"""Tests for :mod:`bulwark.core.audit`."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from bulwark.core.audit import (
    AuditConfig,
    AuditEntry,
    AuditTrail,
    FileAuditStorage,
    InMemoryAuditStorage,
)
from bulwark.exceptions import AuditError, ConfigurationError
from bulwark.utils.crypto import AuditCipher, generate_audit_key


class TestBasicLogging:
    async def test_log_and_retrieve(self, audit_trail: AuditTrail) -> None:
        entry = AuditEntry(
            tool_called="read_database",
            input_data={"sql": "SELECT 1"},
            output_data={"rows": 1},
            risk_score=0.1,
            decision="approved",
        )
        audit_id = await audit_trail.log(entry)
        retrieved = await audit_trail.get(audit_id)
        assert retrieved is not None
        assert retrieved.tool_called == "read_database"
        assert retrieved.decision == "approved"

    async def test_missing_id_returns_none(self, audit_trail: AuditTrail) -> None:
        result = await audit_trail.get("nonexistent")
        assert result is None

    async def test_timestamps_are_utc(self, audit_trail: AuditTrail) -> None:
        local_time = datetime.now()  # naive
        entry = AuditEntry(tool_called="x", timestamp=local_time)
        await audit_trail.log(entry)
        fetched = await audit_trail.get(entry.audit_id)
        assert fetched is not None
        assert fetched.timestamp.tzinfo is not None


class TestEncryption:
    async def test_encrypted_logs_are_unreadable_without_key(
        self, encrypted_audit: AuditTrail
    ) -> None:
        assert encrypted_audit.encrypted is True
        entry = AuditEntry(tool_called="payment", input_data={"amount": 99})
        await encrypted_audit.log(entry)
        # Inspect raw storage — should be ciphertext, not JSON
        raw = await encrypted_audit._storage.read(entry.audit_id)
        assert raw is not None
        assert b"payment" not in raw  # ciphertext

    async def test_encrypted_round_trip(self, encrypted_audit: AuditTrail) -> None:
        entry = AuditEntry(tool_called="x", input_data={"k": "v"})
        await encrypted_audit.log(entry)
        retrieved = await encrypted_audit.get(entry.audit_id)
        assert retrieved is not None
        assert retrieved.input_data == {"k": "v"}

    async def test_tampered_ciphertext_raises(self) -> None:
        cipher = AuditCipher(generate_audit_key())
        token = cipher.encrypt(b"hello")
        tampered = token[:-1] + (b"!" if token[-1:] != b"!" else b"@")
        with pytest.raises(AuditError):
            cipher.decrypt(tampered)

    async def test_key_rotation_decrypts_old_records(self) -> None:
        old_key = generate_audit_key()
        new_key = generate_audit_key()
        # Encrypt with old key
        old_cipher = AuditCipher(old_key)
        token = old_cipher.encrypt(b"old data")
        # Rotate: new key first, old key kept for backward decrypt
        rotated = AuditCipher([new_key, old_key])
        assert rotated.decrypt(token) == b"old data"

    def test_invalid_key_raises_config_error(self) -> None:
        with pytest.raises(ConfigurationError):
            AuditCipher("not a real fernet key")

    def test_empty_key_list_raises(self) -> None:
        with pytest.raises(ConfigurationError):
            AuditCipher([])


class TestRedaction:
    async def test_password_field_redacted(self) -> None:
        trail = AuditTrail(
            AuditConfig(redact_fields=["password", "ssn"]),
            storage=InMemoryAuditStorage(),
        )
        entry = AuditEntry(
            tool_called="login",
            input_data={"username": "alice", "password": "hunter2", "ssn": "123-45-6789"},
        )
        await trail.log(entry)
        fetched = await trail.get(entry.audit_id)
        assert fetched is not None
        assert fetched.input_data["password"] == "[REDACTED]"
        assert fetched.input_data["ssn"] == "[REDACTED]"
        assert fetched.input_data["username"] == "alice"

    async def test_redaction_case_insensitive(self) -> None:
        trail = AuditTrail(
            AuditConfig(redact_fields=["password"]),
            storage=InMemoryAuditStorage(),
        )
        entry = AuditEntry(tool_called="x", input_data={"PASSWORD": "x"})
        await trail.log(entry)
        fetched = await trail.get(entry.audit_id)
        assert fetched is not None
        assert fetched.input_data["PASSWORD"] == "[REDACTED]"


class TestQuery:
    async def _seed(self, trail: AuditTrail) -> list[AuditEntry]:
        now = datetime.now(timezone.utc)
        entries = [
            AuditEntry(
                tool_called="read_database",
                agent_id="agent-A",
                user_id="alice",
                decision="approved",
                risk_score=0.1,
                timestamp=now - timedelta(minutes=5),
                compliance_tags=["HIPAA"],
            ),
            AuditEntry(
                tool_called="send_email",
                agent_id="agent-B",
                user_id="bob",
                decision="blocked",
                risk_score=0.95,
                timestamp=now - timedelta(minutes=2),
                compliance_tags=["SOC2"],
            ),
            AuditEntry(
                tool_called="process_payment",
                agent_id="agent-A",
                user_id="alice",
                decision="approved",
                risk_score=0.3,
                timestamp=now,
                compliance_tags=["HIPAA", "PCI_DSS"],
            ),
        ]
        for e in entries:
            await trail.log(e)
        return entries

    async def test_query_by_agent(self, audit_trail: AuditTrail) -> None:
        await self._seed(audit_trail)
        results = await audit_trail.query(agent_id="agent-A")
        assert len(results) == 2
        assert all(r.agent_id == "agent-A" for r in results)

    async def test_query_by_decision(self, audit_trail: AuditTrail) -> None:
        await self._seed(audit_trail)
        blocked = await audit_trail.query(decision="blocked")
        assert len(blocked) == 1
        assert blocked[0].decision == "blocked"

    async def test_query_by_min_risk(self, audit_trail: AuditTrail) -> None:
        await self._seed(audit_trail)
        high = await audit_trail.query(min_risk=0.9)
        assert len(high) == 1
        assert high[0].risk_score >= 0.9

    async def test_query_by_compliance_tag(self, audit_trail: AuditTrail) -> None:
        await self._seed(audit_trail)
        hipaa = await audit_trail.query(compliance_tag="HIPAA")
        assert len(hipaa) == 2

    async def test_query_time_range(self, audit_trail: AuditTrail) -> None:
        await self._seed(audit_trail)
        now = datetime.now(timezone.utc)
        recent = await audit_trail.query(start_time=now - timedelta(minutes=3))
        assert len(recent) == 2

    async def test_query_results_sorted(self, audit_trail: AuditTrail) -> None:
        await self._seed(audit_trail)
        results = await audit_trail.query()
        assert results == sorted(results, key=lambda e: e.timestamp)

    async def test_query_limit(self, audit_trail: AuditTrail) -> None:
        await self._seed(audit_trail)
        results = await audit_trail.query(limit=1)
        assert len(results) == 1


class TestRetentionPurge:
    async def test_purge_removes_old_entries(self) -> None:
        trail = AuditTrail(AuditConfig(retention_days=1), storage=InMemoryAuditStorage())
        old = AuditEntry(
            tool_called="x",
            timestamp=datetime.now(timezone.utc) - timedelta(days=30),
        )
        new = AuditEntry(
            tool_called="x",
            timestamp=datetime.now(timezone.utc),
        )
        await trail.log(old)
        await trail.log(new)
        purged = await trail.purge_expired()
        assert purged == 1
        assert await trail.get(old.audit_id) is None
        assert await trail.get(new.audit_id) is not None


class TestFileStorage:
    async def test_round_trip_on_disk(self, tmp_path) -> None:
        storage = FileAuditStorage(tmp_path)
        trail = AuditTrail(AuditConfig(), storage=storage)
        entry = AuditEntry(tool_called="x", input_data={"k": "v"})
        await trail.log(entry)

        # Re-open with a fresh AuditTrail
        trail2 = AuditTrail(AuditConfig(), storage=FileAuditStorage(tmp_path))
        retrieved = await trail2.get(entry.audit_id)
        assert retrieved is not None
        assert retrieved.input_data == {"k": "v"}

    async def test_path_traversal_neutralized(self, tmp_path) -> None:
        storage = FileAuditStorage(tmp_path)
        # Inject a malicious id; FileAuditStorage must collapse traversal
        malicious_id = "../../etc/passwd"
        await storage.append(malicious_id, b"data")
        # Stored under a sanitized name *inside* base_path
        files = list(tmp_path.glob("*.bin"))
        assert len(files) == 1
        assert "passwd" in files[0].stem
        assert ".." not in files[0].stem


class TestFieldTruncation:
    async def test_huge_field_truncated(self, audit_trail: AuditTrail) -> None:
        big_blob = "x" * (32 * 1024)
        entry = AuditEntry(tool_called="x", input_data={"blob": big_blob})
        await audit_trail.log(entry)
        retrieved = await audit_trail.get(entry.audit_id)
        assert retrieved is not None
        assert "[truncated]" in str(retrieved.input_data["blob"])
