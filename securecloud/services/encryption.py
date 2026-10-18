"""AES-256-GCM encryption for file blocks.

Encrypted block format v1 (one block == one cloud object)
---------------------------------------------------------
An encrypted object is the raw AEAD ciphertext produced by
``cryptography.hazmat.primitives.ciphers.aead.AESGCM``:

    ciphertext || tag     (the library appends the 16-byte GCM tag)

Nothing else is embedded in the object, so the bytes are exactly the output of
the AEAD primitive.  Everything needed to decrypt the block is stored as
metadata in the SQLite database:

    format_version : 1
    nonce          : 12 random bytes, unique per (key, block)
    file_id        : internal UUID of the file (``StoredFile.public_id``)
    block_index    : 0-based position of the block
    plaintext_size : length of the original block, in bytes
    encrypted_size : length of the stored object (plaintext + 16-byte tag)

Additional authenticated data (AAD) is not stored; it is reconstructed on
both sides as::

    AAD = b"SecureCloud/block/v1/" + file_id_utf8 + b"/" + ascii(block_index)

Binding file id, block index and format version into the AEAD makes it
impossible to move a block to another file, to reorder blocks inside a file,
or to replay a block written with a different format version - any such
attempt makes tag verification fail, and no plaintext is ever released.

Sizes: ``encrypted_size == plaintext_size + 16`` (GCM tag).  The nonce is
never reused with a key because each block draws a fresh random nonce and a
fresh DEK is used for every file.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from securecloud.services import CryptoError, FileIntegrityError

BLOCK_FORMAT_VERSION = 1
SUPPORTED_BLOCK_FORMATS = (1,)
NONCE_BYTES = 12
GCM_TAG_BYTES = 16
KEY_BYTES = 32
AAD_PREFIX = b"SecureCloud/block/v"


def build_block_aad(file_uid: str, block_index: int, format_version: int = BLOCK_FORMAT_VERSION) -> bytes:
    """Reconstruct the authenticated additional data for a block."""
    if not file_uid:
        raise CryptoError("A file identifier is required to encrypt a block.")
    if block_index < 0:
        raise CryptoError("Block index must not be negative.")
    return f"{AAD_PREFIX.decode()}{format_version}/{file_uid}/{block_index}".encode("utf-8")


@dataclass(frozen=True)
class EncryptedBlock:
    """In-memory representation of an encrypted block (not persisted)."""

    block_index: int
    nonce: bytes
    ciphertext: bytes
    plaintext_size: int
    format_version: int = BLOCK_FORMAT_VERSION

    @property
    def encrypted_size(self) -> int:
        return len(self.ciphertext)

    @property
    def nonce_hex(self) -> str:
        return self.nonce.hex()


def new_nonce() -> bytes:
    """Return a fresh 96-bit nonce from the OS CSPRNG."""
    return os.urandom(NONCE_BYTES)


def validate_data_key(dek: bytes) -> bytes:
    if not isinstance(dek, (bytes, bytearray, memoryview)):
        raise CryptoError("Data-encryption key must be bytes.")
    key = bytes(dek)
    if len(key) != KEY_BYTES:
        raise CryptoError("Data-encryption key must be 256 bits.", detail=f"len={len(key)}")
    return key


def encrypt_block(dek: bytes, plaintext: bytes, file_uid: str, block_index: int,
                  format_version: int = BLOCK_FORMAT_VERSION) -> tuple[bytes, bytes]:
    """Encrypt one block. Returns ``(nonce, ciphertext_with_tag)``."""
    key = validate_data_key(dek)
    if format_version not in SUPPORTED_BLOCK_FORMATS:
        raise CryptoError("Unsupported encrypted-block format version.", detail=str(format_version))
    nonce = new_nonce()
    aad = build_block_aad(file_uid, block_index, format_version)
    try:
        ciphertext = AESGCM(key).encrypt(nonce, bytes(plaintext), aad)
    except Exception as exc:  # pragma: no cover - library level failure
        raise CryptoError("Block encryption failed.", detail=str(exc)) from exc
    return nonce, ciphertext


def decrypt_block(dek: bytes, nonce: bytes, ciphertext: bytes, file_uid: str, block_index: int,
                  format_version: int = BLOCK_FORMAT_VERSION) -> bytes:
    """Authenticate and decrypt one block.

    Raises :class:`FileIntegrityError` when the authentication tag does not
    verify (tampered ciphertext, wrong key, wrong position/identifier, or a
    different format version).  Plaintext is never returned in that case.
    """
    key = validate_data_key(dek)
    if format_version not in SUPPORTED_BLOCK_FORMATS:
        raise CryptoError("Unsupported encrypted-block format version.", detail=str(format_version))
    if not nonce or len(nonce) != NONCE_BYTES:
        raise FileIntegrityError(
            "Encrypted block metadata is invalid (nonce length).",
            detail=f"nonce len={len(nonce) if nonce else 0}",
        )
    if len(ciphertext) < GCM_TAG_BYTES:
        raise FileIntegrityError(
            "Encrypted block is truncated and cannot be authenticated.",
            detail=f"ciphertext len={len(ciphertext)}",
        )
    aad = build_block_aad(file_uid, block_index, format_version)
    try:
        return AESGCM(key).decrypt(nonce, bytes(ciphertext), aad)
    except InvalidTag as exc:
        raise FileIntegrityError(
            "Block authentication failed: the stored data is corrupted or has been "
            "modified, or it does not belong to this file.",
            detail=f"InvalidTag file={file_uid[:8]} index={block_index}",
        ) from exc


def encrypt_block_record(dek: bytes, plaintext: bytes, file_uid: str, block_index: int) -> EncryptedBlock:
    nonce, ciphertext = encrypt_block(dek, plaintext, file_uid, block_index)
    return EncryptedBlock(
        block_index=block_index,
        nonce=nonce,
        ciphertext=ciphertext,
        plaintext_size=len(plaintext),
    )


def ciphertext_size(plaintext_size: int) -> int:
    """Expected stored size for a given plaintext block size."""
    return plaintext_size + GCM_TAG_BYTES


def describe_format() -> dict:
    """Machine-readable summary of the on-the-wire format (used by /settings)."""
    return {
        "format_version": BLOCK_FORMAT_VERSION,
        "algorithm": "AES-256-GCM",
        "key_size_bits": KEY_BYTES * 8,
        "nonce_bytes": NONCE_BYTES,
        "tag_bytes": GCM_TAG_BYTES,
        "aad_template": "SecureCloud/block/v{version}/{file_id}/{block_index}",
        "ciphertext_overhead_bytes": GCM_TAG_BYTES,
        "object_layout": "raw AEAD output: ciphertext || tag (metadata stored in SQLite)",
    }
