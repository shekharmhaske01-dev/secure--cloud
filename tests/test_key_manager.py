"""Envelope key-management tests (KEK validation and DEK wrapping)."""
from __future__ import annotations

import base64
import os

import pytest

from securecloud.services import ConfigurationError, CryptoError
from securecloud.services.key_manager import (
    KEK_ENV_VAR,
    KEY_BYTES,
    KeyManager,
    decode_kek,
    fingerprint_key,
    generate_kek_b64,
    generate_secret_key,
    validate_kek,
)

KEK_A = base64.b64encode(bytes(range(32))).decode()
KEK_B = base64.b64encode(bytes(range(1, 33))).decode()


def test_generated_key_is_32_random_bytes():
    value = generate_kek_b64()
    decoded = decode_kek(value)
    assert len(decoded) == KEY_BYTES
    assert decoded != decode_kek(generate_kek_b64()), "two generated keys must differ"
    status = validate_kek(value)
    assert status.valid and status.configured
    assert status.key_size_bits == 256
    assert status.fingerprint == fingerprint_key(decoded)


def test_generate_secret_key_is_long_and_unique():
    a, b = generate_secret_key(), generate_secret_key()
    assert len(a) >= 32 and a != b


@pytest.mark.parametrize("bad", [None, "", "   ", "not-base64!!", "short", base64.b64encode(b"1234").decode()])
def test_invalid_keys_are_rejected(bad):
    with pytest.raises(ConfigurationError):
        decode_kek(bad)
    status = validate_kek(bad)
    assert status.valid is False


def test_validation_accepts_url_safe_and_unpadded_base64():
    raw = os.urandom(32)
    url_safe = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    assert decode_kek(url_safe) == raw or len(decode_kek(url_safe)) == 32


def test_manager_refuses_to_start_without_key():
    """The application must never silently invent a key-encryption key."""
    with pytest.raises(ConfigurationError):
        KeyManager(None)
    with pytest.raises(ConfigurationError):
        KeyManager("")


def test_manager_can_run_in_configuration_only_mode():
    manager = KeyManager(None, allow_missing=True)
    assert manager.configured is False
    assert manager.status().valid is False
    with pytest.raises(ConfigurationError):
        manager.wrap_dek(os.urandom(32))


def test_wrap_and_unwrap_round_trip():
    manager = KeyManager(KEK_A)
    dek = manager.generate_data_key()
    assert len(dek) == KEY_BYTES
    wrapped = manager.wrap_dek(dek)
    assert wrapped.wrapped_key != dek, "the stored record must not contain the raw key"
    assert dek not in wrapped.wrapped_key
    assert len(wrapped.nonce) == 12
    assert manager.unwrap_dek(wrapped.wrapped_key, wrapped.nonce, wrapped.format_version) == dek


def test_each_wrap_uses_a_fresh_nonce():
    manager = KeyManager(KEK_A)
    dek = manager.generate_data_key()
    nonces = {manager.wrap_dek(dek).nonce for _ in range(200)}
    assert len(nonces) == 200
    ciphers = {manager.wrap_dek(dek).wrapped_key for _ in range(50)}
    assert len(ciphers) == 50


def test_unwrap_with_wrong_kek_fails_safely():
    dek = os.urandom(32)
    wrapped = KeyManager(KEK_A).wrap_dek(dek)
    with pytest.raises(CryptoError):
        KeyManager(KEK_B).unwrap_dek(wrapped.wrapped_key, wrapped.nonce, wrapped.format_version)


def test_tampered_wrapped_key_fails_safely():
    manager = KeyManager(KEK_A)
    dek = manager.generate_data_key()
    wrapped = manager.wrap_dek(dek)
    tampered = bytearray(wrapped.wrapped_key)
    tampered[0] ^= 0xFF
    with pytest.raises(CryptoError):
        manager.unwrap_dek(bytes(tampered), wrapped.nonce, wrapped.format_version)


def test_wrong_wrap_format_version_rejected():
    manager = KeyManager(KEK_A)
    wrapped = manager.wrap_dek(os.urandom(32))
    with pytest.raises(CryptoError):
        manager.unwrap_dek(wrapped.wrapped_key, wrapped.nonce, 99)


def test_two_managers_with_same_kek_interoperate():
    """A restarted instance must unwrap records written by an earlier one."""
    dek = os.urandom(32)
    wrapped = KeyManager(KEK_A).wrap_dek(dek)
    assert KeyManager(KEK_A).unwrap_dek(wrapped.wrapped_key, wrapped.nonce, wrapped.format_version) == dek
    assert KeyManager(KEK_A).fingerprint == KeyManager(KEK_A).fingerprint


def test_fingerprint_is_stable_and_key_specific():
    assert fingerprint_key(bytes(range(32))) == fingerprint_key(bytes(range(32)))
    assert fingerprint_key(bytes(range(32))) != fingerprint_key(bytes(range(1, 33)))
    assert len(fingerprint_key(bytes(range(32)))) == 64


def test_dek_length_is_enforced():
    manager = KeyManager(KEK_A)
    with pytest.raises(CryptoError):
        manager.wrap_dek(os.urandom(16))


def test_status_message_names_the_environment_variable():
    status = validate_kek(None)
    assert KEK_ENV_VAR in status.message
