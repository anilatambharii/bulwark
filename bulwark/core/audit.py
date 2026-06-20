"""Layer 4 — Compliance audit trail.

Every guarded tool invocation produces an :class:`AuditEntry` describing who
did what, on whose behalf, with what risk score, and how the request was
resolved. Entries are JSON-serializable, optionally encrypted at rest, and
queryable for forensic reconstruction.

Storage backends are pluggable via :class:`AuditStorage`. The default
in-memory backend is fine for tests and short-lived agents; production
deployments should plug in :class:`FileAuditStorage` or implement an
S3/Postgres backend conforming to the same protocol.

Compliance regimes (HIPAA, NERC CIP, SOC 2) require:
  * authenticated encryption at rest — ``Fernet`` (AES-128-CBC + HMAC-SHA256)
  * tamper detection — Fernet token MAC (HMAC-SHA256)
  * 7-year retention default for HIPAA — configurable per profile
  * queryable forensic reconstruction — :meth:`AuditTrail.query`
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Protocol, runtime_checkable

from pydantic import BaseModel, Field, field_validator

from bulwark.exceptions import AuditError
from bulwark.utils.crypto import AuditCipher

_MAX_FIELD_BYTES = 16 * 1024  # 16 KiB per field — keep entries small

AuditDecision = str  # 'approved' | 'blocked' | 'escalated' | 'denied'


class AuditEntry(BaseModel):
    """A single record in the audit trail."""

    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent_id: str = "default"
    user_id: str = "default"
    tool_called: str
    input_data: dict[str, Any] = Field(default_factory=dict)
    output_data: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = Field(ge=0.0, le=1.0, default=0.0)
    decision: AuditDecision = "approved"
    source_data: list[str] = Field(default_factory=list)
    reasoning_chain: str | None = None
    compliance_tags: list[str] = Field(default_factory=list)
    layer: str | None = None
    duration_ms: float = 0.0

    @field_validator("timestamp")
    @classmethod
    def _ensure_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_validator("input_data", "output_data")
    @classmethod
    def _truncate(cls, v: dict[str, Any]) -> dict[str, Any]:
        # Truncate any one field that ballooned past _MAX_FIELD_BYTES so the
        # audit log doesn't gobble disk because someone passed a 50 MiB blob.
        out: dict[str, Any] = {}
        for k, val in v.items():
            try:
                serialized = json.dumps(val, default=str)
            except (TypeError, ValueError):
                serialized = str(val)
            if len(serialized.encode("utf-8")) > _MAX_FIELD_BYTES:
                out[k] = serialized[: _MAX_FIELD_BYTES] + "...[truncated]"
            else:
                out[k] = val
        return out

    def to_json(self) -> str:
        return self.model_dump_json()


class AuditConfig(BaseModel):
    """Configuration for the audit trail."""

    encryption_key: str | None = None
    encryption_keys: list[str] | None = Field(
        default=None,
        description="If provided, supports key rotation. First key encrypts; all decrypt.",
    )
    retention_days: int = Field(default=2555, ge=1)
    compliance_mode: list[str] = Field(default_factory=lambda: ["HIPAA", "SOC2"])
    storage_path: str | None = None
    redact_fields: list[str] = Field(
        default_factory=lambda: ["password", "ssn", "api_key", "token", "secret"]
    )

    @field_validator("compliance_mode")
    @classmethod
    def _normalize_compliance(cls, v: list[str]) -> list[str]:
        return [s.upper().replace("-", "_") for s in v]


@runtime_checkable
class AuditStorage(Protocol):
    """Storage backend protocol — implement these three methods to plug in your own."""

    async def append(self, audit_id: str, payload: bytes) -> None: ...

    async def read(self, audit_id: str) -> bytes | None: ...

    async def scan(self) -> AsyncIterator[tuple[str, bytes]]: ...


class InMemoryAuditStorage:
    """In-memory audit storage — used by default and for tests."""

    def __init__(self) -> None:
        self._records: dict[str, bytes] = {}
        self._lock = asyncio.Lock()

    async def append(self, audit_id: str, payload: bytes) -> None:
        async with self._lock:
            self._records[audit_id] = payload

    async def read(self, audit_id: str) -> bytes | None:
        return self._records.get(audit_id)

    async def scan(self) -> AsyncIterator[tuple[str, bytes]]:
        async with self._lock:
            items = list(self._records.items())
        for audit_id, payload in items:
            yield audit_id, payload


class FileAuditStorage:
    """File-backed append-only audit storage.

    Writes one file per entry under ``base_path/<audit_id>.bin`` so corrupt
    or tampered entries cannot poison sibling records. Use with an immutable
    object store (S3 with object-lock, GCS retention) for true WORM.
    """

    def __init__(self, base_path: str | Path) -> None:
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()

    def _path_for(self, audit_id: str) -> Path:
        # Reject path traversal — audit_id should be a UUID but defense in depth.
        safe = audit_id.replace("/", "_").replace("\\", "_").replace("..", "_")
        return self.base_path / f"{safe}.bin"

    async def append(self, audit_id: str, payload: bytes) -> None:
        path = self._path_for(audit_id)
        async with self._lock:
            await asyncio.to_thread(path.write_bytes, payload)

    async def read(self, audit_id: str) -> bytes | None:
        path = self._path_for(audit_id)
        if not path.exists():
            return None
        return await asyncio.to_thread(path.read_bytes)

    async def scan(self) -> AsyncIterator[tuple[str, bytes]]:
        paths = sorted(self.base_path.glob("*.bin"))
        for path in paths:
            data = await asyncio.to_thread(path.read_bytes)
            yield path.stem, data


class AuditTrail:
    """Encrypted, queryable audit log.

    Initialize with an :class:`AuditConfig`. By default, entries are kept in
    process memory; pass ``storage_path`` to spill to disk via
    :class:`FileAuditStorage`, or pass an explicit ``storage`` instance.
    """

    def __init__(
        self,
        config: AuditConfig | None = None,
        *,
        storage: AuditStorage | None = None,
    ) -> None:
        self.config = config or AuditConfig()
        self._cipher: AuditCipher | None = None
        if self.config.encryption_keys:
            self._cipher = AuditCipher(self.config.encryption_keys)
        elif self.config.encryption_key:
            self._cipher = AuditCipher(self.config.encryption_key)

        if storage is not None:
            self._storage: AuditStorage = storage
        elif self.config.storage_path:
            self._storage = FileAuditStorage(self.config.storage_path)
        else:
            self._storage = InMemoryAuditStorage()

    # ------------------------------------------------------------------ public

    @property
    def encrypted(self) -> bool:
        return self._cipher is not None

    async def log(self, entry: AuditEntry) -> str:
        """Persist ``entry`` and return its audit_id."""

        try:
            redacted = self._redact(entry)
            payload = redacted.to_json().encode("utf-8")
            if self._cipher is not None:
                payload = self._cipher.encrypt(payload)
            await self._storage.append(entry.audit_id, payload)
        except AuditError:
            raise
        except Exception as exc:  # pragma: no cover — last-ditch failure path
            raise AuditError(f"Failed to write audit entry: {exc}") from exc
        return entry.audit_id

    async def get(self, audit_id: str) -> AuditEntry | None:
        """Fetch a single entry by id."""

        raw = await self._storage.read(audit_id)
        if raw is None:
            return None
        return self._decode(raw)

    async def query(
        self,
        *,
        agent_id: str | None = None,
        user_id: str | None = None,
        tool_called: str | None = None,
        decision: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        min_risk: float | None = None,
        compliance_tag: str | None = None,
        limit: int | None = None,
    ) -> list[AuditEntry]:
        """Forensic query — returns matching entries sorted by timestamp."""

        results: list[AuditEntry] = []
        async for _, raw in self._storage.scan():
            try:
                entry = self._decode(raw)
            except AuditError:
                continue  # skip tampered records but don't fail the query
            if not self._matches(
                entry,
                agent_id=agent_id,
                user_id=user_id,
                tool_called=tool_called,
                decision=decision,
                start_time=start_time,
                end_time=end_time,
                min_risk=min_risk,
                compliance_tag=compliance_tag,
            ):
                continue
            results.append(entry)
            if limit and len(results) >= limit * 4:
                # collect a few extra so the final sort is stable, then trim
                break

        results.sort(key=lambda e: e.timestamp)
        if limit is not None:
            results = results[:limit]
        return results

    async def purge_expired(self, *, now: datetime | None = None) -> int:
        """Remove records older than ``retention_days``. Returns count purged.

        The default :class:`InMemoryAuditStorage` and :class:`FileAuditStorage`
        both support deletion through this method; custom backends without a
        deletion API will see this raise :class:`AuditError`.
        """

        cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=self.config.retention_days)
        purged = 0
        async for audit_id, raw in self._storage.scan():
            try:
                entry = self._decode(raw)
            except AuditError:
                continue
            if entry.timestamp < cutoff:
                await self._delete(audit_id)
                purged += 1
        return purged

    # ----------------------------------------------------------------- private

    async def _delete(self, audit_id: str) -> None:
        if isinstance(self._storage, InMemoryAuditStorage):
            self._storage._records.pop(audit_id, None)  # noqa: SLF001
            return
        if isinstance(self._storage, FileAuditStorage):
            path = self._storage._path_for(audit_id)  # noqa: SLF001
            if path.exists():
                await asyncio.to_thread(path.unlink)
            return
        raise AuditError("Configured storage backend does not support deletion.")

    def _redact(self, entry: AuditEntry) -> AuditEntry:
        if not self.config.redact_fields:
            return entry
        redact_set = {f.lower() for f in self.config.redact_fields}

        def _sanitize(d: dict[str, Any]) -> dict[str, Any]:
            return {
                k: ("[REDACTED]" if k.lower() in redact_set else v)
                for k, v in d.items()
            }

        return entry.model_copy(
            update={
                "input_data": _sanitize(entry.input_data),
                "output_data": _sanitize(entry.output_data),
            }
        )

    def _decode(self, raw: bytes) -> AuditEntry:
        try:
            if self._cipher is not None:
                raw = self._cipher.decrypt(raw)
            data = json.loads(raw.decode("utf-8"))
            return AuditEntry.model_validate(data)
        except AuditError:
            raise
        except Exception as exc:
            raise AuditError(f"Failed to decode audit entry: {exc}") from exc

    @staticmethod
    def _matches(
        entry: AuditEntry,
        *,
        agent_id: str | None,
        user_id: str | None,
        tool_called: str | None,
        decision: str | None,
        start_time: datetime | None,
        end_time: datetime | None,
        min_risk: float | None,
        compliance_tag: str | None,
    ) -> bool:
        if agent_id and entry.agent_id != agent_id:
            return False
        if user_id and entry.user_id != user_id:
            return False
        if tool_called and entry.tool_called != tool_called:
            return False
        if decision and entry.decision != decision:
            return False
        if start_time and entry.timestamp < start_time:
            return False
        if end_time and entry.timestamp > end_time:
            return False
        if min_risk is not None and entry.risk_score < min_risk:
            return False
        if compliance_tag:
            tag = compliance_tag.upper().replace("-", "_")
            if tag not in {t.upper().replace("-", "_") for t in entry.compliance_tags}:
                return False
        return True


def build_compliance_tags(modes: Iterable[str]) -> list[str]:
    """Normalize compliance mode names into uppercase audit tags."""

    return [m.upper().replace("-", "_") for m in modes]
