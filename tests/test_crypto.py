"""AES-256-GCM block encryption tests."""
from __future__ import annotations

import os

import pytest

from securecloud.services import CryptoError, FileIntegrityError
from securecloud.services.encryption import (
    BLOCK_FORMAT_VERSION,
    GCM_TAG_BYTES,
    NONCE_BYTES,
    build_block_aad,
    ciphertext_size,
    decrypt_block,
    encrypt_block,
    new_nonce,
)


def test_block_format_constants():
    assert BLOCK_FORMAT_VERSION == 1
    assert NONCE_BYTES == 12
    assert GCM_TAG_BYTES == 16
    assert ciphertext_size(0) == 16
    assert ciphertext_size(1024) == 1040


def test_nonces_are_unique():
    nonces = {new_nonce().hex() for _ in range(2000)}
    assert len(nonces) == 2000, "a nonce was reused, which is forbidden for GCM"


def test_aad_binds_version_file_and_index():
    aad = build_block_aad("abc123", 7)
    assert aad == b"SecureCloud/block/v1/abc123/7"
    # Different file, index or version must produce different AAD.
    assert build_block_aad("abc123", 8) != aad
    assert build_block_aad("abc124", 7) != aad
    assert build_block_aad("abc123", 7, 2) != aad


@pytest.mark.parametrize("size", [0, 1, 15, 16, 4095, 4096, 4097, 8192, 10000])
def test_round_trip_exact_bytes(size):
    key = os.urandom(32)
    plaintext = os.urandom(size)
    nonce, ciphertext = encrypt_block(key, plaintext, "file-uid", 3)
    assert len(nonce) == NONCE_BYTES
    assert len(ciphertext) == size + GCM_TAG_BYTES
    assert ciphertext != plaintext or size == 0
    assert decrypt_block(key, nonce, ciphertext, "file-uid", 3) == plaintext


def test_ciphertext_does_not_contain_plaintext():
    key = os.urandom(32)
    plaintext = b"SUPER-SECRET-MARKER-" * 20
    _nonce, ciphertext = encrypt_block(key, plaintext, "uid", 0)
    assert b"SUPER-SECRET-MARKER" not in ciphertext


def test_fresh_nonce_per_encryption_of_same_block():
    key = os.urandom(32)
    plaintext = b"identical content" * 40
    nonce_a, cipher_a = encrypt_block(key, plaintext, "uid", 0)
    nonce_b, cipher_b = encrypt_block(key, plaintext, "uid", 0)
    assert nonce_a != nonce_b, "nonce must never repeat for the same key"
    assert cipher_a != cipher_b, "identical plaintext must not produce identical ciphertext"
    assert decrypt_block(key, nonce_a, cipher_a, "uid", 0) == plaintext
    assert decrypt_block(key, nonce_b, cipher_b, "uid", 0) == plaintext


def test_tampered_ciphertext_is_rejected():
    key = os.urandom(32)
    plaintext = os.urandom(2048)
    nonce, ciphertext = encrypt_block(key, plaintext, "uid", 1)
    tampered = bytearray(ciphertext)
    tampered[100] ^= 0x01
    with pytest.raises(FileIntegrityError):
        decrypt_block(key, nonce, bytes(tampered), "uid", 1)


def test_truncated_ciphertext_is_rejected():
    key = os.urandom(32)
    nonce, ciphertext = encrypt_block(key, os.urandom(512), "uid", 0)
    with pytest.raises(FileIntegrityError):
        decrypt_block(key, nonce, ciphertext[:-4], "uid", 0)
    with pytest.raises(FileIntegrityError):
        decrypt_block(key, nonce, b"short", "uid", 0)


def test_wrong_key_is_rejected():
    nonce, ciphertext = encrypt_block(os.urandom(32), b"data" * 100, "uid", 0)
    with pytest.raises(FileIntegrityError):
        decrypt_block(os.urandom(32), nonce, ciphertext, "uid", 0)


def test_wrong_position_or_file_is_rejected():
    key = os.urandom(32)
    nonce, ciphertext = encrypt_block(key, b"block-payload" * 50, "file-a", 2)
    # Same key, wrong block index (a reordering / replay attempt).
    with pytest.raises(FileIntegrityError):
        decrypt_block(key, nonce, ciphertext, "file-a", 3)
    # Same key, wrong file (moving a block between files).
    with pytest.raises(FileIntegrityError):
        decrypt_block(key, nonce, ciphertext, "file-b", 2)
    # Wrong (all-zero) nonce: authentication must still fail.
    bad_nonce = b"\x00" * NONCE_BYTES
    with pytest.raises(FileIntegrityError):
        decrypt_block(key, bad_nonce, ciphertext, "file-a", 2)


def test_invalid_key_length_rejected():
    with pytest.raises(CryptoError):
        encrypt_block(os.urandom(16), b"data", "uid", 0)


def test_invalid_nonce_length_rejected():
    key = os.urandom(32)
    _nonce, ciphertext = encrypt_block(key, b"data", "uid", 0)
    with pytest.raises(FileIntegrityError):
        decrypt_block(key, b"short-nonce", ciphertext, "uid", 0)


def test_unsupported_format_version_rejected():
    key = os.urandom(32)
    with pytest.raises(CryptoError):
        encrypt_block(key, b"data", "uid", 0, format_version=99)
    nonce, ciphertext = encrypt_block(key, b"data", "uid", 0)
    with pytest.raises(CryptoError):
        decrypt_block(key, nonce, ciphertext, "uid", 0, format_version=42)


def test_aad_requires_file_identifier():
    with pytest.raises(CryptoError):
        build_block_aad("", 0)


def test_encrypted_blocks_are_independent_per_index():
    """Each block of a file must authenticate with its own index."""
    key = os.urandom(32)
    blocks = {}
    for index in range(5):
        nonce, ciphertext = encrypt_block(key, f"block-{index}".encode() * 10, "uid", index)
        blocks[index] = (nonce, ciphertext)
    for index, (nonce, ciphertext) in blocks.items():
        assert decrypt_block(key, nonce, ciphertext, "uid", index) == f"block-{index}".encode() * 10
        for other in blocks:
            if other == index:
                continue
            with pytest.raises(FileIntegrityError):
                decrypt_block(key, nonce, ciphertext, "uid", other)
