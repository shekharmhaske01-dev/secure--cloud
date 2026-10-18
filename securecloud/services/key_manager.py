"""Key management: envelope encryption for per-file data-encryption keys.

Design
------
* Every file gets its own random 256-bit data-encryption key (DEK).
* Blocks are encrypted with the DEK (AES-256-GCM).
* The DEK is *wrapped* with a key-encryption key (KEK) using AES-256-GCM and
  only the wrapped ciphertext is stored in the metadata database.
* The KEK lives exclusively in ``SECURECLOUD_KEY_ENCRYPTION_KEY`` (environment
  variable / secret manager) - never in the database, never in object storage,
  never in source code.

This module never generates or substitutes a key implicitly: a missing or
invalid KEK raises, so existing wrapped records are never silently orphaned.
"""
from __future__ import annotations

import base64
import binascii
import os
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from securecloud.services import ConfigurationError, CryptoError

KEK_ENV_VAR = "SECURECLOUD_KEY_ENCRYPTION_KEY"
KEY_BYTES = 32  # AES-256
NONCE_BYTES = 12
WRAP_FORMAT_VERSION = 1
# AAD binds the wrapped record to its purpose and format version.
WRAP_AAD = b"SecureCloud/DEK-wrap/v1"


@dataclass(frozen=True)
class WrappedKeyMaterial:
    """Result of wrapping a DEK with the KEK."""

    wrapped_key: bytes
    nonce: bytes
    format_version: int
    kek_fingerprint: str
    key_size_bits: int = KEY_BYTES * 8

    @property
    def nonce_hex(self) -> str:
        return self.nonce.hex()

    def as_dict(self) -> dict:
        return {
            "wrapped_key": self.wrapped_key,
            "wrap_nonce": self.nonce,
            "wrap_format_version": self.format_version,
            "kek_fingerprint": self.kek_fingerprint,
            "key_size_bits": self.key_size_bits,
            "algorithm": "AES-256-GCM",
        }


@dataclass(frozen=True)
class KeyStatus:
    """Non-secret description of the configured KEK, safe to display."""

    configured: bool
    valid: bool
    fingerprint: str | None
    key_size_bits: int | None
    message: str

    def as_dict(self) -> dict:
        return {
            "configured": self.configured,
            "valid": self.valid,
            "fingerprint": self.fingerprint,
            "key_size_bits": self.key_size_bits,
            "message": self.message,
        }


def generate_kek() -> bytes:
    """Generate a new 256-bit KEK from the OS CSPRNG."""
    return os.urandom(KEY_BYTES)


def generate_kek_b64() -> str:
    return base64.b64encode(generate_kek()).decode("ascii")


def generate_secret_key(nbytes: int = 48) -> str:
    """Generate a Flask ``SECRET_KEY``."""
    return secrets.token_urlsafe(nbytes)


def fingerprint_key(key: bytes) -> str:
    """Return a non-reversible SHA-256 fingerprint of the key material."""
    import hashlib

    return hashlib.sha256(b"SecureCloud/KEK-fingerprint/v1" + key).hexdigest()


def decode_kek(value: str | None) -> bytes:
    """Decode and validate a base64-encoded KEK.

    Accepts standard or URL-safe base64 with optional padding.  Raises
    :class:`ConfigurationError` with an actionable message when invalid.
    """
    if value is None or str(value).strip() == "":
        raise ConfigurationError(
            f"{KEK_ENV_VAR} is not set. SecureCloud refuses to start without a "
            "key-encryption key, because existing wrapped keys could not be unwrapped. "
            "Generate one with: python scripts/generate_encryption_key.py",
            detail=f"{KEK_ENV_VAR} missing",
        )
    raw = str(value).strip().strip('"').strip("'")
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        try:
            padded = raw + "=" * (-len(raw) % 4)
            decoded = base64.urlsafe_b64decode(padded)
        except (binascii.Error, ValueError) as exc:
            raise ConfigurationError(
                f"{KEK_ENV_VAR} is not valid base64. Expected {KEY_BYTES} random "
                "bytes encoded as base64 (44 characters, e.g. produced by "
                "scripts/generate_encryption_key.py).",
                detail=f"base64 decode failed: {exc}",
            ) from exc
    if len(decoded) != KEY_BYTES:
        raise ConfigurationError(
            f"{KEK_ENV_VAR} must decode to exactly {KEY_BYTES} bytes "
            f"(AES-256); got {len(decoded)} bytes.",
            detail=f"decoded length {len(decoded)}",
        )
    return decoded


def validate_kek(value: str | None) -> KeyStatus:
    """Validate a KEK value without raising; used by the configuration checker."""
    if value is None or str(value).strip() == "":
        return KeyStatus(False, False, None, None, f"{KEK_ENV_VAR} is not set.")
    try:
        key = decode_kek(value)
    except ConfigurationError as exc:
        return KeyStatus(True, False, None, None, exc.public_message)
    return KeyStatus(
        True,
        True,
        fingerprint_key(key),
        len(key) * 8,
        f"Valid AES-{len(key) * 8} key-encryption key loaded.",
    )


class KeyManager:
    """Wraps and unwraps per-file data-encryption keys."""

    def __init__(self, kek_b64: str | None, *, allow_missing: bool = False,
                 wrap_format_version: int = WRAP_FORMAT_VERSION):
        self.wrap_format_version = wrap_format_version
        self._kek: bytes | None = None
        self._fingerprint: str | None = None
        self.key_size_bits: int | None = None

        if kek_b64 is None or str(kek_b64).strip() == "":
            if not allow_missing:
                # Never auto-generate: existing wrapped records would become
                # permanently unreadable.
                decode_kek(kek_b64)  # raises ConfigurationError with guidance
            self.message = (
                f"{KEK_ENV_VAR} is not configured. Encryption, upload and download "
                "operations are disabled until a valid key is set."
            )
            return

        key = decode_kek(kek_b64)  # raises on invalid encoding/length
        self._kek = key
        self._fingerprint = fingerprint_key(key)
        self.key_size_bits = len(key) * 8
        self.message = f"Valid AES-{self.key_size_bits} key-encryption key loaded."

    # --- state ------------------------------------------------------------
    @property
    def configured(self) -> bool:
        return self._kek is not None

    @property
    def fingerprint(self) -> str | None:
        return self._fingerprint

    @property
    def fingerprint_short(self) -> str:
        return (self._fingerprint or "")[:12] or "-"

    def status(self) -> KeyStatus:
        return KeyStatus(
            configured=self.configured,
            valid=self.configured,
            fingerprint=self._fingerprint,
            key_size_bits=self.key_size_bits,
            message=self.message,
        )

    def require_key(self) -> bytes:
        if self._kek is None:
            raise ConfigurationError(self.message, detail="KEK not configured")
        return self._kek

    # --- data keys --------------------------------------------------------
    @staticmethod
    def generate_data_key() -> bytes:
        """Generate a fresh 256-bit data-encryption key."""
        return os.urandom(KEY_BYTES)

    def wrap_dek(self, dek: bytes) -> WrappedKeyMaterial:
        """Encrypt a DEK with the KEK (AES-256-GCM, fresh nonce each call)."""
        kek = self.require_key()
        if len(dek) != KEY_BYTES:
            raise CryptoError("Invalid data-encryption key length.", detail=f"len={len(dek)}")
        nonce = os.urandom(NONCE_BYTES)
        wrapped = AESGCM(kek).encrypt(nonce, dek, WRAP_AAD + bytes([self.wrap_format_version]))
        return WrappedKeyMaterial(
            wrapped_key=wrapped,
            nonce=nonce,
            format_version=self.wrap_format_version,
            kek_fingerprint=self._fingerprint or "",
            key_size_bits=KEY_BYTES * 8,
        )

    def unwrap_dek(self, wrapped_key: bytes, nonce: bytes, format_version: int = WRAP_FORMAT_VERSION) -> bytes:
        """Decrypt (unwrap) a stored DEK. Fails safely on any tampering."""
        kek = self.require_key()
        if format_version != self.wrap_format_version:
            raise CryptoError(
                "Unsupported key-wrapping format version.",
                detail=f"record version {format_version} != supported {self.wrap_format_version}",
            )
        try:
            dek = AESGCM(kek).decrypt(nonce, wrapped_key, WRAP_AAD + bytes([format_version]))
        except InvalidTag as exc:
            raise CryptoError(
                "The stored file key could not be authenticated. The key-encryption key "
                "does not match this record, or the record has been modified.",
                detail="InvalidTag while unwrapping DEK",
            ) from exc
        if len(dek) != KEY_BYTES:
            raise CryptoError("Unwrapped key has an unexpected length.", detail=f"len={len(dek)}")
        return dek


def load_key_manager(config) -> KeyManager:
    """Build a KeyManager from an application config mapping."""
    raw = config.get("SECURECLOUD_KEY_ENCRYPTION_KEY") or config.get(KEK_ENV_VAR)
    allow_missing = bool(config.get("ALLOW_START_WITHOUT_KEY", False)) or not bool(
        config.get("REQUIRE_KEY_AT_STARTUP", True)
    )
    return KeyManager(raw, allow_missing=allow_missing)


def get_key_manager() -> KeyManager:
    """Return the KeyManager bound to the current application."""
    from flask import current_app

    manager = current_app.extensions.get("securecloud_key_manager")
    if manager is None:  # pragma: no cover - factory always registers it
        raise ConfigurationError("Key manager is not initialised.", detail="missing extension")
    return manager
