"""Integrity-manifest tests (block counts, ordering, sizes, object presence)."""
from __future__ import annotations

import os

import pytest

from securecloud.extensions import db as _db
from securecloud.models import EncryptedBlock, StoredFile
from securecloud.services import integrity
from securecloud.services.storage_service import get_storage_service

from tests.conftest import register, upload_bytes

BLOCK = 4096


def _store(client, size, name="manifest.bin"):
    payload = os.urandom(size)
    response = upload_bytes(client, payload, name)
    assert response.status_code == 201
    return payload, response.get_json()["file"]


def test_manifest_is_valid_for_a_complete_file(app, client):
    register(client)
    _payload, info = _store(client, BLOCK * 2 + 17)
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        report = integrity.verify_manifest(file, get_storage_service())
        assert report.ok is True
        assert report.block_count_expected == 3
        assert report.block_count_found == 3
        assert report.total_size_expected == report.total_size_found
        assert report.order_ok and report.encrypted_size_ok and report.objects_present
        names = {check["name"] for check in report.checks}
        assert {"block_count", "block_order", "plaintext_sizes", "aead_overhead",
                "reconstructed_length", "wrapped_key", "objects_present"} <= names


def test_manifest_reports_missing_block_rows(app, client):
    register(client)
    _payload, info = _store(client, BLOCK * 2 + 30)
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        victim = sorted(file.blocks, key=lambda b: b.block_index)[1]
        _db.session.delete(victim)
        _db.session.commit()
        _db.session.refresh(file)
        report = integrity.verify_manifest(file, get_storage_service())
        assert report.ok is False
        assert report.block_count_found == 2
        assert any("blocks" in problem.lower() for problem in report.problems)


def test_manifest_detects_unexpected_block_size(app, client):
    register(client)
    _payload, info = _store(client, BLOCK * 2 + 50)
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        block = sorted(file.blocks, key=lambda b: b.block_index)[0]
        block.plaintext_size = 12345
        _db.session.commit()
        report = integrity.verify_manifest(file, get_storage_service())
        assert report.ok is False
        assert report.encrypted_size_ok is False


def test_manifest_detects_wrong_aead_overhead(app, client):
    register(client)
    _payload, info = _store(client, BLOCK + 5)
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        sorted(file.blocks, key=lambda b: b.block_index)[0].encrypted_size += 5
        _db.session.commit()
        report = integrity.verify_manifest(file, get_storage_service())
        assert report.ok is False
        assert any("aead" in check["name"] for check in report.checks if not check["ok"])


def test_manifest_detects_missing_object(app, client):
    register(client)
    _payload, info = _store(client, BLOCK + 5)
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        victim = sorted(file.blocks, key=lambda b: b.block_index)[0]
        app.extensions["securecloud_storage"].delete_object(victim.object_key)
        report = integrity.verify_manifest(file, get_storage_service())
        assert report.ok is False
        assert victim.object_key in report.missing_objects


def test_manifest_detects_object_size_mismatch(app, client):
    register(client)
    _payload, info = _store(client, BLOCK + 5)
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        victim = sorted(file.blocks, key=lambda b: b.block_index)[1]
        app.extensions["securecloud_storage"].upload_object(victim.object_key, b"tiny")
        report = integrity.verify_manifest(file, get_storage_service())
        assert report.ok is False


def test_deep_manifest_authenticates_blocks(app, client):
    register(client)
    _payload, info = _store(client, BLOCK * 2 + 3)
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        report = integrity.verify_manifest(file, get_storage_service(), deep=True)
        assert report.ok is True
        assert report.authenticated is True


def test_deep_manifest_fails_on_tampered_object(app, client):
    register(client)
    _payload, info = _store(client, BLOCK * 2 + 3)
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        victim = sorted(file.blocks, key=lambda b: b.block_index)[1]
        data = bytearray(app.extensions["securecloud_storage"].download_object(victim.object_key))
        data[1] ^= 0x0F
        app.extensions["securecloud_storage"].upload_object(victim.object_key, bytes(data))
        report = integrity.verify_manifest(file, get_storage_service(), deep=True)
        assert report.ok is False
        assert report.authenticated is False
        assert any(check["name"] == "authentication" and not check["ok"] for check in report.checks)


def test_manifest_detects_missing_wrapped_key(app, client):
    register(client)
    _payload, info = _store(client, 5000)
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        _db.session.delete(file.wrapped_key)
        _db.session.commit()
        _db.session.refresh(file)
        report = integrity.verify_manifest(file, get_storage_service())
        assert report.ok is False
        assert any(check["name"] == "wrapped_key" and not check["ok"] for check in report.checks)


def test_deep_manifest_fails_with_wrong_kek(app, client):
    """A record wrapped with a different KEK must fail loudly, not decrypt garbage."""
    import base64

    from securecloud.services.key_manager import KeyManager

    register(client)
    _payload, info = _store(client, BLOCK + 9)
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        wrong = KeyManager(base64.b64encode(bytes(range(1, 33))).decode())
        report = integrity.verify_manifest(file, get_storage_service(), deep=True, key_manager=wrong)
        assert report.ok is False
        assert report.authenticated is False
        assert any(check["name"] == "key_unwrap" and not check["ok"] for check in report.checks)


def test_report_serialises_to_json(app, client):
    register(client)
    _payload, info = _store(client, 3000)
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        data = integrity.verify_manifest(file, get_storage_service()).as_dict()
        for key in ("ok", "block_count_expected", "block_count_found", "checks", "problems"):
            assert key in data
        assert isinstance(data["checks"], list)
        # No secret material is exposed in the report.
        assert "wrapped" not in str(data).lower() or "wrapped_key" in str(data).lower()
        assert file.public_id not in str(data.get("problems"))


def test_reconstruction_helper_confirms_recorded_digest(app, client):
    from securecloud.services.key_manager import get_key_manager

    register(client)
    _payload, info = _store(client, BLOCK * 2 + 77)
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        result = integrity.verify_reconstruction(blocks=list(file.blocks), file=file,
                                                key_manager=get_key_manager())
        assert result["matches_recorded"] is True
        assert result["sha256"] == file.plaintext_sha256


def test_expected_plaintext_size_helper():
    assert integrity.expected_plaintext_size(0, BLOCK, BLOCK + 10, 2) == BLOCK
    assert integrity.expected_plaintext_size(1, BLOCK, BLOCK + 10, 2) == 10
    assert integrity.expected_plaintext_size(0, BLOCK, 0, 0) == 0
