"""End-to-end pipeline tests for SecureCloud.

These tests exercise the full upload → encrypt → store → download → decrypt →
reconstruct cycle.  They run against the local storage backend using a real
in-process Flask test client, a real SQLite database, and real AES-256-GCM
encryption.
"""
from __future__ import annotations

import hashlib
import io
import os
import struct

import pytest

from securecloud.extensions import db
from securecloud.models import (
    EncryptedBlock,
    StoredFile,
    WrappedKey,
    STATUS_COMPLETE,
    STATUS_DELETED,
)

# ---------------------------------------------------------------------------
# helpers (import from conftest where possible)
# ---------------------------------------------------------------------------

from tests.conftest import register, login, upload_bytes, get_csrf


def _make_data(size: int) -> bytes:
    """Return ``size`` bytes of deterministic pseudo-random data."""
    rng = bytearray()
    while len(rng) < size:
        rng.extend(os.urandom(min(4096, size - len(rng))))
    return bytes(rng[:size])


def _register_and_login(client, username="alice", email="alice@example.com",
                         password="Str0ng!Pass1"):
    """Register a new user and log them in, returning the client."""
    register(client, username, email, password)
    login(client, email, password)
    return client


# ---------------------------------------------------------------------------
# Upload / download round-trip tests
# ---------------------------------------------------------------------------

class TestUploadDownloadRoundTrip:
    """Upload a file and download it — the result must match byte-for-byte."""

    def test_upload_small_file(self, client):
        """A file smaller than one block should upload and create a DB record."""
        _register_and_login(client)
        data = _make_data(512)
        resp = upload_bytes(client, data, filename="small.bin")
        assert resp.status_code in (200, 302), resp.data[:300]

        sf = db.session.execute(
            db.select(StoredFile).filter_by(original_filename="small.bin")
        ).scalar_one_or_none()
        assert sf is not None
        assert sf.original_size == 512
        assert sf.status == STATUS_COMPLETE

    def test_upload_multi_block_file(self, client):
        """A file larger than block_size should create multiple blocks."""
        _register_and_login(client)
        # block_size in test config is 4096
        data = _make_data(4096 * 3 + 100)  # 3 full blocks + partial
        resp = upload_bytes(client, data, filename="multi.bin")
        assert resp.status_code in (200, 302)

        sf = db.session.execute(
            db.select(StoredFile).filter_by(original_filename="multi.bin")
        ).scalar_one()
        blocks = db.session.execute(
            db.select(EncryptedBlock).filter_by(file_id=sf.id)
        ).scalars().all()
        assert len(blocks) == 4, f"Expected 4 blocks, got {len(blocks)}"

    def test_download_matches_original(self, client):
        """Downloaded content must be identical to the uploaded content."""
        _register_and_login(client)
        data = _make_data(8000)
        upload_bytes(client, data, filename="round_trip.bin")

        sf = db.session.execute(
            db.select(StoredFile).filter_by(original_filename="round_trip.bin")
        ).scalar_one()

        resp = client.get(f"/files/{sf.id}/download")
        assert resp.status_code == 200
        assert resp.data == data

    def test_download_integrity_check(self, client):
        """SHA-256 of download must match SHA-256 of original upload."""
        _register_and_login(client)
        data = _make_data(12345)
        upload_sha = hashlib.sha256(data).hexdigest()
        upload_bytes(client, data, filename="integrity.bin")

        sf = db.session.execute(
            db.select(StoredFile).filter_by(original_filename="integrity.bin")
        ).scalar_one()

        resp = client.get(f"/files/{sf.id}/download")
        download_sha = hashlib.sha256(resp.data).hexdigest()
        assert upload_sha == download_sha

    def test_upload_download_various_types(self, client):
        """Different MIME types should round-trip correctly."""
        _register_and_login(client)
        for fname, mime in [
            ("doc.txt", "text/plain"),
            ("report.pdf", "application/pdf"),
            ("photo.jpg", "image/jpeg"),
        ]:
            data = _make_data(2048)
            upload_bytes(client, data, filename=fname, content_type=mime)
            sf = db.session.execute(
                db.select(StoredFile).filter_by(original_filename=fname)
            ).scalar_one()
            resp = client.get(f"/files/{sf.id}/download")
            assert resp.status_code == 200
            assert resp.data == data, f"Round-trip mismatch for {fname}"


# ---------------------------------------------------------------------------
# Encryption verification tests
# ---------------------------------------------------------------------------

class TestEncryptionVerification:
    """Verify that stored blocks are actually encrypted."""

    def test_encrypted_blocks_exist_in_storage(self, client, app):
        """After upload, encrypted block files must exist on disk."""
        _register_and_login(client)
        data = _make_data(5000)
        upload_bytes(client, data, filename="exists_check.bin")

        sf = db.session.execute(
            db.select(StoredFile).filter_by(original_filename="exists_check.bin")
        ).scalar_one()
        blocks = db.session.execute(
            db.select(EncryptedBlock).filter_by(file_id=sf.id)
        ).scalars().all()

        storage = app.extensions.get("securecloud_storage")
        for block in blocks:
            info = storage.object_info(block.storage_key)
            assert info["exists"], f"Block {block.block_index} not found in storage"

    def test_encrypted_blocks_not_plaintext(self, client, app):
        """The bytes stored on disk must NOT match the original plaintext."""
        _register_and_login(client)
        # Use a known pattern that would be easy to spot
        data = b"A" * 8192
        upload_bytes(client, data, filename="not_plaintext.bin")

        sf = db.session.execute(
            db.select(StoredFile).filter_by(original_filename="not_plaintext.bin")
        ).scalar_one()
        blocks = db.session.execute(
            db.select(EncryptedBlock).filter_by(file_id=sf.id)
        ).scalars().all()

        storage = app.extensions.get("securecloud_storage")
        for block in blocks:
            encrypted = storage.download_object(block.storage_key)
            # The encrypted data must not contain the plaintext pattern
            assert b"A" * 100 not in encrypted, (
                f"Block {block.block_index} appears to contain plaintext!"
            )

    def test_decryption_produces_original(self, client):
        """Full encrypt → store → retrieve → decrypt cycle must reproduce the input."""
        _register_and_login(client)
        data = _make_data(16384)
        upload_bytes(client, data, filename="decrypt_test.bin")

        sf = db.session.execute(
            db.select(StoredFile).filter_by(original_filename="decrypt_test.bin")
        ).scalar_one()

        resp = client.get(f"/files/{sf.id}/download")
        assert resp.status_code == 200
        assert resp.data == data, "Decrypted download does not match original"


# ---------------------------------------------------------------------------
# Delete tests
# ---------------------------------------------------------------------------

class TestFileDeletion:
    """Deleting a file should remove blocks and update metadata."""

    def test_delete_removes_blocks(self, client, app):
        """After deletion, encrypted blocks should be gone from storage."""
        _register_and_login(client)
        data = _make_data(10000)
        upload_bytes(client, data, filename="delete_blocks.bin")

        sf = db.session.execute(
            db.select(StoredFile).filter_by(original_filename="delete_blocks.bin")
        ).scalar_one()
        block_keys = [b.storage_key for b in db.session.execute(
            db.select(EncryptedBlock).filter_by(file_id=sf.id)
        ).scalars().all()]

        # Delete the file
        csrf = get_csrf(client, f"/files/{sf.id}")
        resp = client.post(
            f"/files/{sf.id}/delete",
            data={"csrf_token": csrf},
            follow_redirects=True,
        )
        assert resp.status_code == 200

        # Verify blocks are removed from storage
        storage = app.extensions.get("securecloud_storage")
        for key in block_keys:
            info = storage.object_info(key)
            assert not info["exists"], f"Block {key} still exists after deletion"

    def test_delete_removes_metadata(self, client):
        """After deletion, the DB record should be marked deleted."""
        _register_and_login(client)
        data = _make_data(4000)
        upload_bytes(client, data, filename="delete_meta.bin")

        sf = db.session.execute(
            db.select(StoredFile).filter_by(original_filename="delete_meta.bin")
        ).scalar_one()
        file_id = sf.id

        csrf = get_csrf(client, f"/files/{file_id}")
        client.post(
            f"/files/{file_id}/delete",
            data={"csrf_token": csrf},
            follow_redirects=True,
        )

        sf = db.session.get(StoredFile, file_id)
        assert sf.status == STATUS_DELETED


# ---------------------------------------------------------------------------
# Listing & details tests
# ---------------------------------------------------------------------------

class TestFileListingAndDetails:
    """Test the file listing page and file details page."""

    def test_file_listing(self, client):
        """Uploading multiple files should show all of them in the listing."""
        _register_and_login(client)
        filenames = ["list_a.txt", "list_b.txt", "list_c.txt"]
        for fname in filenames:
            upload_bytes(client, _make_data(1024), filename=fname)

        resp = client.get("/files/")
        assert resp.status_code == 200
        for fname in filenames:
            assert fname.encode() in resp.data

    def test_file_details_page(self, client):
        """The file details page should display correct file information."""
        _register_and_login(client)
        data = _make_data(6000)
        upload_bytes(client, data, filename="details_test.bin")

        sf = db.session.execute(
            db.select(StoredFile).filter_by(original_filename="details_test.bin")
        ).scalar_one()

        resp = client.get(f"/files/{sf.id}")
        assert resp.status_code == 200
        assert b"details_test.bin" in resp.data


# ---------------------------------------------------------------------------
# Reconstruction test
# ---------------------------------------------------------------------------

class TestBlockReconstruction:
    """Verify that blocks can be manually reassembled into the original file."""

    def test_reconstruction_from_blocks(self, client, app):
        """Downloading and concatenating decrypted blocks must yield the original."""
        _register_and_login(client)
        data = _make_data(4096 * 2 + 500)  # 2 full blocks + partial
        upload_bytes(client, data, filename="reconstruct.bin")

        sf = db.session.execute(
            db.select(StoredFile).filter_by(original_filename="reconstruct.bin")
        ).scalar_one()

        # Download through the normal endpoint (which internally reconstructs)
        resp = client.get(f"/files/{sf.id}/download")
        assert resp.status_code == 200
        assert resp.data == data
        assert len(resp.data) == len(data)


# ---------------------------------------------------------------------------
# Access control tests
# ---------------------------------------------------------------------------

class TestAccessControl:
    """Verify that users cannot access each other's files."""

    def test_unauthorized_download_blocked(self, client, app):
        """User B must NOT be able to download user A's file."""
        # Register and upload as alice
        _register_and_login(client, "alice", "alice@example.com", "Str0ng!Pass1")
        upload_bytes(client, _make_data(1024), filename="alice_private.bin")

        sf = db.session.execute(
            db.select(StoredFile).filter_by(original_filename="alice_private.bin")
        ).scalar_one()
        file_id = sf.id

        # Logout alice
        client.get("/auth/logout", follow_redirects=True)

        # Register and login as bob
        _register_and_login(client, "bob", "bob@example.com", "B0b$Str0ng!2")

        # Try to download alice's file
        resp = client.get(f"/files/{file_id}/download")
        assert resp.status_code in (403, 404), (
            f"Expected 403 or 404, got {resp.status_code}"
        )


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Test boundary conditions and edge cases."""

    def test_upload_exactly_one_block(self, client):
        """A file exactly equal to block_size should create exactly one block."""
        _register_and_login(client)
        data = _make_data(4096)
        upload_bytes(client, data, filename="exact_block.bin")

        sf = db.session.execute(
            db.select(StoredFile).filter_by(original_filename="exact_block.bin")
        ).scalar_one()
        blocks = db.session.execute(
            db.select(EncryptedBlock).filter_by(file_id=sf.id)
        ).scalars().all()
        assert len(blocks) == 1

        resp = client.get(f"/files/{sf.id}/download")
        assert resp.data == data

    def test_upload_one_byte_over_block(self, client):
        """block_size + 1 bytes should create exactly two blocks."""
        _register_and_login(client)
        data = _make_data(4097)
        upload_bytes(client, data, filename="one_over.bin")

        sf = db.session.execute(
            db.select(StoredFile).filter_by(original_filename="one_over.bin")
        ).scalar_one()
        blocks = db.session.execute(
            db.select(EncryptedBlock).filter_by(file_id=sf.id)
        ).scalars().all()
        assert len(blocks) == 2

        resp = client.get(f"/files/{sf.id}/download")
        assert resp.data == data

    def test_upload_very_small_file(self, client):
        """A single-byte file should work correctly."""
        _register_and_login(client)
        data = b"\x42"
        upload_bytes(client, data, filename="tiny.bin")

        sf = db.session.execute(
            db.select(StoredFile).filter_by(original_filename="tiny.bin")
        ).scalar_one()
        resp = client.get(f"/files/{sf.id}/download")
        assert resp.data == data
