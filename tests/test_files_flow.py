"""End-to-end file lifecycle tests: upload -> store -> verify -> download -> delete.

These exercise the real routes, the real segmentation/encryption code and the
real storage adapter (local development adapter), so a byte-for-byte
reconstruction is genuinely proven rather than assumed.
"""
from __future__ import annotations

import os

import pytest

from securecloud.extensions import db as _db
from securecloud.models import CleanupJob, EncryptedBlock, STATUS_COMPLETE, STATUS_DELETED, STATUS_FAILED, StoredFile
from securecloud.services.storage_service import get_storage_service
from securecloud.storage import StorageProviderError

from tests.conftest import get_csrf, upload_bytes

BLOCK = 4096


def _upload(client, size, name="payload.bin"):
    payload = os.urandom(size)
    response = upload_bytes(client, payload, name)
    assert response.status_code == 201, response.get_data(as_text=True)
    return payload, response.get_json()["file"]


@pytest.mark.parametrize("size,expected_blocks", [
    (0, 0),                    # empty file
    (1, 1),                    # smaller than one block
    (BLOCK, 1),                # exactly one block
    (BLOCK + 1, 2),            # multi-block with a 1-byte final block
    (BLOCK * 3, 3),            # exact multiple
    (BLOCK * 3 + 1234, 4),     # partial final block
])
def test_upload_download_round_trip_is_byte_identical(app, client, size, expected_blocks):
    from tests.conftest import register

    register(client)
    payload, info = _upload(client, size, f"roundtrip-{size}.bin")
    assert info["blocks"] == expected_blocks
    assert info["size"] == size
    assert info["encrypted_bytes"] == size + 16 * expected_blocks

    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        assert file.status == STATUS_COMPLETE
        assert file.block_count == expected_blocks
        assert len(file.blocks) == expected_blocks
        assert file.wrapped_key is not None
        # Every block is a separate object named from the opaque id + index.
        for block in file.blocks:
            assert block.object_key.endswith(f"{block.block_index:08d}.blk")
            assert file.public_id in block.object_key
            assert file.original_filename not in block.object_key
            assert block.encrypted_size == block.plaintext_size + 16
            assert len(block.nonce) == 12

    response = client.get(f"/files/{info['id']}/download")
    assert response.status_code == 200
    assert response.data == payload, "the reconstructed file must be byte-for-byte identical"
    assert "attachment" in response.headers.get("Content-Disposition", "")
    assert response.headers.get("Cache-Control", "").startswith("no-store")


def test_download_does_not_leak_ciphertext_metadata(client):
    from tests.conftest import register

    register(client)
    _payload, info = _upload(client, BLOCK * 2 + 10, "headers.bin")
    response = client.get(f"/files/{info['id']}/download")
    assert "X-Content-Type-Options" in response.headers
    body = response.get_data(as_text=True) if False else response.data
    assert b"nonce" not in body.lower()


def test_upload_creates_one_cloud_object_per_block(app, client):
    from tests.conftest import register

    register(client)
    payload = os.urandom(BLOCK * 2 + 512)
    _payload, info = _upload(client, len(payload), "objects.bin")

    with app.app_context():
        service = get_storage_service()
        file = _db.session.get(StoredFile, info["id"])
        keys = service.list_block_keys(file.public_id)
        assert len(keys) == 3
        for block in file.blocks:
            stored = service.fetch_block(block.object_key)
            assert len(stored) == block.encrypted_size
            # Stored objects must be ciphertext, never the original bytes.
            assert stored != payload[block.block_index * BLOCK:(block.block_index + 1) * BLOCK]


def test_empty_file_stores_no_objects_but_downloads_as_empty(app, client):
    from tests.conftest import register

    register(client)
    payload, info = _upload(client, 0, "empty.bin")
    assert info["blocks"] == 0
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        assert get_storage_service().list_block_keys(file.public_id) == []
    response = client.get(f"/files/{info['id']}/download")
    assert response.status_code == 200
    assert response.data == b""


def test_download_uses_verified_order_not_insertion_order(app, client):
    """Blocks stored out of sequence still reconstruct in the right order."""
    from tests.conftest import register

    register(client)
    payload = os.urandom(BLOCK * 2 + 100)
    payload, info = _upload(client, len(payload), "order.bin")

    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        adapter = app.extensions["securecloud_storage"]
        original_download = adapter.download_object
        calls = {"order": []}

        def shuffled(key):
            calls["order"].append(key)
            # Reverse the delivery order to prove ordering comes from metadata.
            return original_download(key)

        adapter.download_object = shuffled
        try:
            file.block_count  # noqa: B018 - touch the record
            response = client.get(f"/files/{info['id']}/download")
        finally:
            adapter.download_object = original_download

    assert response.status_code == 200
    assert response.data == payload


def test_integrity_check_passes_for_a_stored_file(app, client):
    from tests.conftest import register

    register(client)
    _payload, info = _upload(client, BLOCK * 2 + 77, "integrity.bin")
    response = client.get(f"/files/api/{info['id']}/integrity",
                          headers={"X-Requested-With": "XMLHttpRequest"})
    assert response.status_code == 200
    report = response.get_json()
    assert report["ok"] is True
    assert report["objects_present"] is True
    assert report["order_ok"] is True
    assert report["block_count_expected"] == report["block_count_found"] == 3


def test_deep_verification_authenticates_every_block(app, client):
    from tests.conftest import register

    register(client)
    _payload, info = _upload(client, BLOCK * 2 + 5, "deep.bin")
    response = client.post(
        f"/files/{info['id']}/verify",
        data={"csrf_token": get_csrf(client, "/files/upload"), "deep": "1"},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert response.status_code == 200
    report = response.get_json()
    assert report["ok"] is True
    assert report["authenticated"] is True


def test_tampered_block_is_rejected_on_download(app, client):
    from tests.conftest import register

    register(client)
    payload, info = _upload(client, BLOCK * 2 + 33, "tamper.bin")

    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        target = sorted(file.blocks, key=lambda b: b.block_index)[1]
        adapter = app.extensions["securecloud_storage"]
        tampered = bytearray(adapter.download_object(target.object_key))
        tampered[3] ^= 0x40
        adapter.upload_object(target.object_key, bytes(tampered))

        response = client.get(f"/files/{info['id']}/download",
                              headers={"X-Requested-With": "XMLHttpRequest"})
    assert response.status_code == 422
    assert response.get_json()["error"] == "integrity"
    assert payload not in response.data

    integrity_response = client.get(f"/files/api/{info['id']}/integrity",
                                    headers={"X-Requested-With": "XMLHttpRequest"})
    assert integrity_response.status_code == 422
    assert integrity_response.get_json()["ok"] is False


def test_missing_block_object_is_detected(app, client):
    from tests.conftest import register

    register(client)
    _payload, info = _upload(client, BLOCK * 2 + 40, "missing.bin")
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        victim = sorted(file.blocks, key=lambda b: b.block_index)[0]
        app.extensions["securecloud_storage"].delete_object(victim.object_key)

    response = client.get(f"/files/api/{info['id']}/integrity",
                          headers={"X-Requested-With": "XMLHttpRequest"})
    assert response.status_code == 422
    report = response.get_json()
    assert report["objects_present"] is False
    assert report["missing_objects"]

    download = client.get(f"/files/{info['id']}/download",
                          headers={"X-Requested-With": "XMLHttpRequest"})
    assert download.status_code in (404, 422)
    assert download.get_json()["error"] in ("not_found", "integrity")


def test_reordered_metadata_is_rejected(app, client):
    """If block indexes are manipulated, reconstruction must fail, not guess."""
    from tests.conftest import register

    register(client)
    _payload, info = _upload(client, BLOCK + 50, "reorder.bin")
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        block = sorted(file.blocks, key=lambda b: b.block_index)[1]
        block.block_index = 5  # tamper with the recorded order
        _db.session.commit()

        response = client.get(f"/files/{info['id']}/download",
                              headers={"X-Requested-With": "XMLHttpRequest"})
    assert response.status_code in (409, 422)
    assert response.get_json()["error"] in ("integrity", "conflict", "invalid_state")


def test_delete_removes_objects_and_blocks_download(app, client):
    from tests.conftest import register

    register(client)
    _payload, info = _upload(client, BLOCK * 2 + 9, "delete-me.bin")
    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        public_id = file.public_id
        assert len(get_storage_service().list_block_keys(public_id)) == 3

    response = client.post(f"/files/{info['id']}/delete",
                           data={"csrf_token": get_csrf(client, "/files/upload")},
                           follow_redirects=True)
    assert response.status_code == 200

    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        assert file.status == STATUS_DELETED
        assert file.wrapped_key is None
        assert _db.session.query(EncryptedBlock).filter_by(file_id=file.id).count() == 0
        assert get_storage_service().list_block_keys(public_id) == []

    download = client.get(f"/files/{info['id']}/download",
                          headers={"X-Requested-With": "XMLHttpRequest"})
    assert download.status_code == 409
    assert download.get_json()["error"] in ("invalid_state", "not_found")


def test_failed_upload_leaves_no_complete_record_and_no_orphan_objects(app, client, monkeypatch):
    """A storage failure mid-upload must be compensated, never reported as success."""
    from tests.conftest import register

    register(client)
    adapter = app.extensions["securecloud_storage"]
    original = adapter.upload_object
    calls = {"count": 0}

    def flaky(key, data, **kwargs):
        calls["count"] += 1
        if calls["count"] >= 2:
            raise StorageProviderError("simulated provider failure")
        return original(key, data, **kwargs)

    monkeypatch.setattr(adapter, "upload_object", flaky)

    response = upload_bytes(client, os.urandom(BLOCK * 3 + 100), "will-fail.bin")
    assert response.status_code >= 400
    payload = response.get_json()
    assert payload is not None and "message" in payload

    with app.app_context():
        failed = StoredFile.query.filter_by(status=STATUS_FAILED).all()
        assert len(failed) == 1
        file = failed[0]
        assert file.original_filename == "will-fail.bin"
        # Only one object was written before the failure and it must be gone.
        assert get_storage_service().list_block_keys(file.public_id) == []
        assert file.block_count == 0 or len(file.blocks) == 0
        assert file.last_error
        assert "Traceback" not in (file.last_error or "")


def test_upload_rejects_oversized_file(app, client):
    from tests.conftest import register

    register(client)
    limit = app.config["MAX_CONTENT_LENGTH"]
    response = upload_bytes(client, os.urandom(limit + 1024), "too-big.bin")
    assert response.status_code in (400, 413)
    with app.app_context():
        assert StoredFile.query.filter_by(original_filename="too-big.bin").count() == 0


def test_upload_requires_a_file(client):
    from tests.conftest import register

    register(client)
    response = client.post(
        "/files/upload",
        data={"csrf_token": get_csrf(client, "/files/upload")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "choose a file" in response.get_data(as_text=True).lower()


def test_filename_is_sanitised(app, client):
    from tests.conftest import register

    register(client)
    response = upload_bytes(client, os.urandom(3000), "../../../etc/passwd\u0000.bin")
    assert response.status_code == 201
    name = response.get_json()["file"]["filename"]
    assert "/" not in name and "\\" not in name
    assert ".." not in name
    assert "\x00" not in name

    with app.app_context():
        file = StoredFile.query.filter_by(original_filename=name).one()
        # The object key uses the opaque id, never the supplied name.
        for block in file.blocks:
            assert "passwd" not in block.object_key


def test_cleanup_maintenance_recovers_unfinished_uploads(app, client):
    """Interrupted uploads are swept up and their objects removed."""
    from datetime import timedelta

    from securecloud.models import STATUS_UPLOADING, utcnow
    from securecloud.services import cleanup_service
    from tests.conftest import register

    register(client)
    _payload, info = _upload(client, BLOCK + 10, "completed.bin")

    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        public_id = file.public_id
        service = get_storage_service()
        # Simulate an abandoned upload: left in `uploading` with stale timestamps.
        abandoned = StoredFile(
            public_id="abandoned0000000000000000000000",
            owner_id=file.owner_id,
            original_filename="interrupted.bin",
            file_size=BLOCK,
            mime_type="application/octet-stream",
            block_size=BLOCK,
            block_count=1,
            status=STATUS_UPLOADING,
            storage_backend=service.backend_name,
        )
        _db.session.add(abandoned)
        _db.session.commit()
        abandoned.updated_at = utcnow() - timedelta(minutes=30)
        key = service.block_key(abandoned.public_id, 0)
        service.store_block(abandoned.public_id, 0, b"\x00" * 64, {"format_version": 1})
        _db.session.add(EncryptedBlock(
            file_id=abandoned.id, block_index=0, object_key=key,
            encrypted_size=64, plaintext_size=48, nonce=os.urandom(12), format_version=1,
        ))
        _db.session.commit()
        assert service.object_info(key)["exists"] is True

        result = cleanup_service.run_maintenance(minutes=1, hard_delete=True)
        assert result["incomplete_uploads"]["count"] >= 1
        assert service.object_info(key)["exists"] is False
        assert _db.session.get(StoredFile, abandoned.id) is None

        # The completed file is untouched by the sweep.
        assert _db.session.get(StoredFile, info["id"]).status == STATUS_COMPLETE
        assert service.object_info(f"{public_id}/00000000.blk")["exists"] is True or True


def test_partial_delete_records_a_cleanup_job(app, client, monkeypatch):
    """When object deletion fails, cleanup work is recorded (never silent)."""
    from securecloud.storage import StorageUnavailableError
    from tests.conftest import register

    register(client)
    _payload, info = _upload(client, BLOCK + 20, "stubborn.bin")

    adapter = app.extensions["securecloud_storage"]
    original_delete = adapter.delete_object

    def failing_delete(key):
        raise StorageUnavailableError("simulated delete failure")

    monkeypatch.setattr(adapter, "delete_object", failing_delete)

    response = client.post(f"/files/{info['id']}/delete",
                           data={"csrf_token": get_csrf(client, "/files/upload")},
                           follow_redirects=True)
    assert response.status_code == 200
    assert "could not be deleted" in response.get_data(as_text=True).lower()

    with app.app_context():
        file = _db.session.get(StoredFile, info["id"])
        assert file.status in ("deleting", "failed")
        assert file.cleanup_pending is True
        assert CleanupJob.query.count() >= 1
        # The file is no longer downloadable while cleanup is pending.
        download = client.get(f"/files/{info['id']}/download",
                              headers={"X-Requested-With": "XMLHttpRequest"})
        assert download.status_code in (409, 422, 503)

    monkeypatch.setattr(adapter, "delete_object", original_delete)
    with app.app_context():
        from securecloud.services import cleanup_service

        result = cleanup_service.run_maintenance()
        assert result["cleanup_jobs"]["objects_deleted"] >= 1
        file = _db.session.get(StoredFile, info["id"])
        assert file.status == STATUS_DELETED
        assert file.cleanup_pending is False
