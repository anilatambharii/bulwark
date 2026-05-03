"""Cryptographic helpers for the audit trail.

The audit trail uses Fernet (AES-128-CBC + HMAC-SHA256, authenticated, with
key rotation support) wrapped in an :class:`AuditCipher` so the rest of the
framework never touches keys directly. ``cryptography``'s Fernet is FIPS-aware
and battle-tested; the wrapping is for ergonomics, not novelty.
"""

from __future__ import annotations

from typing import Sequence

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from bulwark.exceptions import AuditError, ConfigurationError


def generate_audit_key() -> str:
    """Generate a fresh URL-safe base64 Fernet key.

    Returns:
        A 44-character ASCII string suitable for passing to
        :class:`bulwark.core.audit.AuditConfig.encryption_key`.
    """

    return Fernet.generate_key().decode("ascii")


class AuditCipher:
    """Symmetric authenticated encryption with optional key rotation.

    Pass a single key to encrypt + decrypt with that key. Pass a list of keys
    (newest first) to support seamless key rotation: encryption uses the first
    key, but decryption is attempted against each in turn.
    """

    def __init__(self, keys: str | Sequence[str]) -> None:
        if isinstance(keys, str):
            key_list: list[str] = [keys]
        else:
            key_list = list(keys)
        if not key_list:
            raise ConfigurationError("AuditCipher requires at least one key.")

        try:
            fernets = [Fernet(k.encode("ascii") if isinstance(k, str) else k) for k in key_list]
        except (ValueError, TypeError) as exc:
            raise ConfigurationError(f"Invalid Fernet key: {exc}") from exc

        self._primary = fernets[0]
        self._fernet = MultiFernet(fernets) if len(fernets) > 1 else fernets[0]

    def encrypt(self, plaintext: str | bytes) -> bytes:
        """Encrypt UTF-8 text or raw bytes; returns a Fernet token."""

        data = plaintext.encode("utf-8") if isinstance(plaintext, str) else plaintext
        return self._fernet.encrypt(data)

    def decrypt(self, token: bytes | str) -> bytes:
        """Decrypt a Fernet token. Raises :class:`AuditError` on tamper."""

        raw = token.encode("ascii") if isinstance(token, str) else token
        try:
            return self._fernet.decrypt(raw)
        except InvalidToken as exc:
            raise AuditError("Audit token failed authentication — possible tampering.") from exc

    def decrypt_text(self, token: bytes | str) -> str:
        return self.decrypt(token).decode("utf-8")
