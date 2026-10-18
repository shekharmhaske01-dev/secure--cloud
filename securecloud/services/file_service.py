"""Upload, download and delete orchestration.

Upload lifecycle
----------------
``pending`` -> ``uploading`` -> ``complete``  (metadata committed only after
every encrypted block has been stored and verified)

Failure paths move the record to ``failed`` and schedule compensating cleanup,
because SQLite and object storage do not share a transaction.  A row is never
reported as ``complete`` while blocks are missing.
"""
from __future__ import annotations

import logging
import os
import tempfile
from dataclasses import dataclass
from typing import BinaryIO

from flask import current_app

from securecloud.extensions import db
from securecloud.models import (
    STATUS_COMPLETE,
    STATUS_DELETED,
    STATUS_DELETING,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_UPLOADING,
    CleanupJob,
    EncryptedBlock,
    StoredFile,
    WrappedKey,
    utcnow,
)
from securecloud.services import (
    CleanupError,
    FileIntegrityError,
    FileNotFoundForUser,
    FileOperationError,
    FileTooLargeError,
    FileValidationError,
    InvalidFileStateError,
)
from securecloud.services import chunking, encryption
from securecloud.services.key_manager import get_key_manager
from securecloud.services.storage_service import get_storage_service
from securecloud.storage import StorageObjectNotFoundError
from securecloud.utils import redact, sanitize_filename

logger = logging.getLogger("securecloud.files")

MAX_ERROR_LENGTH = 480


@dataclass
class UploadResult:
    file: StoredFile
    block_count: int
    total_size: int
    encrypted_bytes: int
    sha256: str
    storage_backend: str


@dataclass
class DownloadResult:
    file: StoredFile
    temp_path: str
    filename: str
    size: int
    block_count: int

    def cleanup(self) -> None:
        """Remove the temporary plaintext file (safe to call repeatedly)."""
        if self.temp_path:
            chunking.remove_quietly(self.temp_path)
            self.temp_path = ""


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def owned_file_or_404(file_id: int, user) -> StoredFile:
    """Fetch a file, enforcing ownership.

    The same "not found" error is raised whether the file does not exist or
    belongs to somebody else, so IDs cannot be enumerated.
    """
    if user is None:
        raise FileNotFoundForUser("no authenticated user")
    file = db.session.get(StoredFile, file_id)
    if file is None or file.owner_id != user.id:
        raise FileNotFoundForUser(f"file id={file_id} user={getattr(user, 'id', None)}")
    return file


def _resolve_block_size() -> int:
    configured = current_app.config.get("BLOCK_SIZE") or chunking.DEFAULT_BLOCK_SIZE
    return chunking.validate_block_size(configured)


def _max_upload_bytes() -> int:
    return int(current_app.config.get("MAX_CONTENT_LENGTH") or 0) or 0


def _staging_path(public_id: str) -> str:
    staging_dir = current_app.config["STAGING_DIR"]
    os.makedirs(staging_dir, exist_ok=True)
    return os.path.join(staging_dir, f"upload-{public_id}.tmp")


def _schedule_cleanup(file: StoredFile | None, object_keys: list[str], reason: str,
                      error: str = "") -> CleanupJob | None:
    """Record recoverable cleanup work for objects that could not be removed."""
    keys = [k for k in object_keys if k]
    if not keys:
        return None
    job = CleanupJob(
        file_id=file.id if file else None,
        public_id=file.public_id if file else None,
        reason=reason,
        status="pending",
        object_keys=keys,
        last_error=redact(error, MAX_ERROR_LENGTH) if error else None,
    )
    db.session.add(job)
    if file is not None:
        file.cleanup_pending = True
    db.session.commit()
    logger.warning("Scheduled cleanup of %d object(s) (%s).", len(keys), reason)
    return job


def _mark_failed(file: StoredFile, error: Exception) -> None:
    file.status = STATUS_FAILED
    file.last_error = redact(getattr(error, "public_message", "") or str(error), MAX_ERROR_LENGTH)
    file.updated_at = utcnow()
    db.session.commit()


# --------------------------------------------------------------------------
# Upload
# --------------------------------------------------------------------------
def create_pending_file(user, filename: str, size: int, mime_type: str, *,
                        block_size: int | None = None, storage_backend: str | None = None,
                        public_id: str | None = None) -> StoredFile:
    """Create the metadata record in ``pending`` state before any bytes move."""
    safe_name = sanitize_filename(filename, max_length=current_app.config.get("MAX_FILENAME_LENGTH", 255))
    service = get_storage_service()
    file = StoredFile(
        public_id=public_id or service.new_file_identifier(),
        owner_id=user.id,
        original_filename=safe_name,
        file_size=int(size or 0),
        mime_type=(mime_type or "application/octet-stream")[:255],
        block_size=block_size or _resolve_block_size(),
        block_count=0,
        status=STATUS_PENDING,
        storage_backend=storage_backend or service.backend_name,
    )
    db.session.add(file)
    db.session.commit()
    return file


def stage_upload(stream: BinaryIO, file: StoredFile) -> dict:
    """Copy an incoming stream into staging, enforcing the size limit."""
    limit = _max_upload_bytes()
    path = _staging_path(file.public_id)
    try:
        staged = chunking.stage_stream_to_file(stream, path, max_bytes=limit or None)
    except FileValidationError as exc:
        if "exceeds" in exc.public_message:
            raise FileTooLargeError(
                "The uploaded file exceeds the maximum allowed size.",
                detail=f"limit={limit}",
            ) from exc
        raise
    return {"path": path, **staged}


def upload_file(user, staged_path: str, filename: str, mime_type: str, *,
                declared_size: int | None = None) -> UploadResult:
    """Encrypt and store a staged file, then commit the metadata.

    Every failure path either removes the objects it created or records a
    cleanup job, and leaves the metadata row in ``failed`` state (never
    ``complete``).
    """
    service = get_storage_service()
    key_manager = get_key_manager()
    if not key_manager.configured:
        raise FileOperationError(key_manager.message)
    if not os.path.isfile(staged_path):
        raise FileValidationError("The staged upload could not be found. Please upload again.")

    actual_size = os.path.getsize(staged_path)
    limit = _max_upload_bytes()
    if limit and actual_size > limit:
        chunking.remove_quietly(staged_path)
        raise FileTooLargeError(
            "The uploaded file exceeds the maximum allowed size.",
            detail=f"size={actual_size} limit={limit}",
        )
    if declared_size is not None and declared_size != actual_size:
        # Trust the bytes on disk, but keep the discrepancy visible in the log.
        logger.info("Declared size %s differs from staged size %s.", declared_size, actual_size)

    block_size = _resolve_block_size()
    plan = chunking.plan_for_size(actual_size, block_size)
    # The opaque identifier is generated first: it is used both in the cloud
    # object names and as the AES-GCM AAD binding for every block.
    public_id = service.new_file_identifier()
    file = create_pending_file(
        user, filename, actual_size, mime_type,
        block_size=block_size, storage_backend=service.backend_name, public_id=public_id,
    )
    file.status = STATUS_UPLOADING
    db.session.commit()

    staged_blocks: list[EncryptedBlock] = []
    written_keys: list[str] = []
    operation = service.start_operation("upload", file_id=file.id, objects_total=plan.block_count)
    encrypted_bytes = 0

    try:
        dek = key_manager.generate_data_key()
        wrapped = key_manager.wrap_dek(dek)
        file.wrapped_key = WrappedKey(
            wrapped_dek=wrapped.wrapped_key,
            wrap_nonce=wrapped.nonce,
            wrap_format_version=wrapped.format_version,
            kek_fingerprint=wrapped.kek_fingerprint,
            key_size_bits=wrapped.key_size_bits,
        )
        db.session.commit()

        for index, block in chunking.iter_file_blocks(staged_path, block_size):
            nonce, ciphertext = encryption.encrypt_block(dek, block, public_id, index)
            key = service.block_key(public_id, index)
            service.store_block(public_id, index, ciphertext, {"format_version": encryption.BLOCK_FORMAT_VERSION})
            written_keys.append(key)
            encrypted_bytes += len(ciphertext)
            staged_blocks.append(EncryptedBlock(
                file_id=file.id,
                block_index=index,
                object_key=key,
                encrypted_size=len(ciphertext),
                plaintext_size=len(block),
                nonce=nonce,
                format_version=encryption.BLOCK_FORMAT_VERSION,
            ))
            if len(staged_blocks) % max(int(current_app.config.get("BLOCK_COMMIT_INTERVAL", 16)), 1) == 0:
                db.session.add_all(staged_blocks)
                staged_blocks.clear()
                db.session.commit()
        dek = None  # noqa: F841  drop the plaintext key as soon as possible

        if staged_blocks:
            db.session.add_all(staged_blocks)
            staged_blocks.clear()
            db.session.commit()

        # Verify every object exists before declaring success.
        for block in sorted(file.blocks, key=lambda b: b.block_index):
            info = service.object_info(block.object_key)
            if not info.get("exists"):
                raise FileIntegrityError(
                    "An uploaded block could not be verified in object storage.",
                    detail=f"key={block.object_key}",
                )
            if info.get("size") is not None and info["size"] != block.encrypted_size:
                raise FileIntegrityError(
                    "An uploaded block has an unexpected stored size.",
                    detail=f"key={block.object_key}",
                )

        file.block_count = plan.block_count
        file.file_size = actual_size
        file.plaintext_sha256 = chunking.sha256_file(staged_path)
        file.status = STATUS_COMPLETE
        file.completed_at = utcnow()
        file.last_error = None
        file.cleanup_pending = False
        db.session.commit()

        service.finish_operation(
            operation, status="success", objects_done=plan.block_count,
            bytes_processed=encrypted_bytes,
        )
        logger.info(
            "Stored file id=%s blocks=%s size=%s backend=%s",
            file.id, plan.block_count, actual_size, service.backend_name,
        )
        return UploadResult(
            file=file,
            block_count=plan.block_count,
            total_size=actual_size,
            encrypted_bytes=encrypted_bytes,
            sha256=file.plaintext_sha256,
            storage_backend=service.backend_name,
        )

    except Exception as exc:
        db.session.rollback()
        # Re-load the row: the rollback discarded any uncommitted state.
        file = db.session.get(StoredFile, file.id)
        if file is not None:
            _mark_failed(file, exc)
            service.finish_operation(
                operation, status="failed", error=exc,
                objects_done=len(written_keys), bytes_processed=encrypted_bytes,
            )
        else:  # pragma: no cover - only if the row itself failed to persist
            service.record_failure("upload", None, exc, objects_total=plan.block_count)
        # Compensating cleanup: never leave orphan objects behind silently.
        try:
            _delete_objects_or_schedule(file, written_keys, reason="failed_upload",
                                       error=getattr(exc, "detail", "") or str(exc))
        except Exception as cleanup_exc:  # pragma: no cover - cleanup must not mask the cause
            logger.exception("Cleanup after failed upload also failed: %s", cleanup_exc)
            if file is not None:
                _schedule_cleanup(file, written_keys, "failed_upload", str(cleanup_exc))
        logger.warning("Upload failed for file id=%s: %s", getattr(file, "id", None), redact(str(exc)))
        raise
    finally:
        chunking.remove_quietly(staged_path)


def _delete_objects_or_schedule(file: StoredFile | None, keys: list[str], reason: str,
                                error: str = "") -> dict:
    """Best-effort object deletion; schedule a cleanup job for anything left."""
    if not keys:
        return {"deleted": [], "missing": [], "failed": []}
    service = get_storage_service()
    result = service.delete_blocks(keys)
    if result["failed"]:
        remaining = [key for key, _msg in result["failed"]]
        _schedule_cleanup(file, remaining, reason, error or result["failed"][0][1])
    elif file is not None and file.cleanup_pending:
        file.cleanup_pending = False
        db.session.commit()
    return result


# --------------------------------------------------------------------------
# Download
# --------------------------------------------------------------------------
def download_file(file: StoredFile, user) -> DownloadResult:
    """Decrypt and reconstruct a stored file into a temporary file.

    Ordering always comes from the verified ``block_index`` metadata, never
    from the order objects are returned in.  Any authentication failure aborts
    the download and the temporary file is removed.
    """
    if user is None or file.owner_id != user.id:
        raise FileNotFoundForUser("ownership check failed")
    if file.status != STATUS_COMPLETE:
        raise InvalidFileStateError(
            "This file is not available for download because its upload did not complete.",
            detail=f"status={file.status}",
        )
    key_manager = get_key_manager()
    service = get_storage_service()
    operation = service.start_operation("download", file_id=file.id, objects_total=file.block_count)

    blocks = sorted(file.blocks, key=lambda b: b.block_index)
    if len(blocks) != (file.block_count or 0):
        service.finish_operation(operation, status="failed",
                                error=FileIntegrityError("Block count mismatch."))
        raise FileIntegrityError(
            "The stored metadata is inconsistent: the number of blocks does not match.",
            detail=f"metadata={file.block_count} found={len(blocks)}",
        )
    if indexes_missing(blocks, file.block_count):
        service.finish_operation(operation, status="failed",
                                error=FileIntegrityError("Missing block indexes."))
        raise FileIntegrityError(
            "The stored metadata is inconsistent: block sequence numbers are incomplete.",
            detail="contiguity check failed",
        )
    if file.wrapped_key is None:
        service.finish_operation(operation, status="failed",
                                error=FileIntegrityError("Wrapped key missing."))
        raise FileIntegrityError(
            "The stored key record for this file is missing, so it cannot be decrypted.",
            detail="wrapped_key missing",
        )

    temp_dir = current_app.config["DOWNLOAD_TEMP_DIR"]
    os.makedirs(temp_dir, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(dir=temp_dir, prefix="sc-download-", suffix=".part")
    decoded_bytes = 0
    try:
        dek = key_manager.unwrap_dek(
            file.wrapped_key.wrapped_dek,
            file.wrapped_key.wrap_nonce,
            file.wrapped_key.wrap_format_version,
        )
        with os.fdopen(fd, "w+b") as out:
            reconstructor = chunking.Reconstructor(out, file.block_size, file.block_count, file.file_size)
            for block in blocks:
                try:
                    ciphertext = service.fetch_block(block.object_key)
                except StorageObjectNotFoundError as exc:
                    # The object is simply absent: report it as an incomplete
                    # stored file rather than as a provider outage.
                    raise FileIntegrityError(
                        "One or more encrypted blocks are missing from object storage, "
                        "so this file cannot be reconstructed.",
                        detail=f"missing object for block {block.block_index}",
                    ) from exc
                plaintext = encryption.decrypt_block(
                    dek, block.nonce, ciphertext, file.public_id,
                    block.block_index, block.format_version,
                )
                if len(plaintext) != block.plaintext_size:
                    raise FileIntegrityError(
                        "A decrypted block has an unexpected length.",
                        detail=f"index={block.block_index}",
                    )
                reconstructor.add(block.block_index, plaintext)
                decoded_bytes += len(plaintext)
            stats = reconstructor.finish()
        dek = None  # noqa: F841  drop the plaintext key reference

        final_size = os.path.getsize(temp_path)
        if final_size != file.file_size:
            raise FileIntegrityError(
                "The reconstructed file size does not match the original.",
                detail=f"reconstructed={final_size} expected={file.file_size}",
            )
        if file.plaintext_sha256:
            actual = chunking.sha256_file(temp_path)
            if actual != file.plaintext_sha256:
                raise FileIntegrityError(
                    "The reconstructed file failed its integrity check.",
                    detail="plaintext digest mismatch",
                )

        service.finish_operation(operation, status="success", objects_done=stats["block_count"],
                                bytes_processed=decoded_bytes)
        return DownloadResult(
            file=file,
            temp_path=temp_path,
            filename=sanitize_filename(file.original_filename),
            size=final_size,
            block_count=stats["block_count"],
        )
    except Exception as exc:
        chunking.remove_quietly(temp_path)
        service.finish_operation(operation, status="failed", error=exc, objects_done=0)
        logger.warning("Download failed for file id=%s: %s", file.id, redact(str(exc)))
        raise


def indexes_missing(blocks: list, block_count: int) -> bool:
    indexes = [b.block_index for b in blocks]
    return indexes != list(range(block_count))


# --------------------------------------------------------------------------
# Delete
# --------------------------------------------------------------------------
def delete_file(file: StoredFile, user) -> dict:
    """Delete a file's objects and metadata with recoverable compensation.

    The record is marked ``deleting`` first; it only becomes ``deleted`` (and
    the wrapped key is dropped) once every object is confirmed gone.  Leftover
    objects are recorded as a cleanup job, and the file cannot be downloaded
    while the deletion is in progress.
    """
    if user is None or file.owner_id != user.id:
        raise FileNotFoundForUser("ownership check failed")
    if file.status == STATUS_DELETED:
        return {"deleted": True, "objects_deleted": 0, "cleanup_pending": False, "already_deleted": True}

    service = get_storage_service()
    keys = [b.object_key for b in sorted(file.blocks, key=lambda b: b.block_index)]
    operation = service.start_operation("delete", file_id=file.id, objects_total=len(keys))

    file.status = STATUS_DELETING
    file.updated_at = utcnow()
    db.session.commit()

    result = service.delete_blocks(keys)
    failed_keys = [key for key, _msg in result["failed"]]

    if failed_keys:
        _schedule_cleanup(file, failed_keys, "delete_incomplete", result["failed"][0][1])
        service.finish_operation(
            operation, status="partial",
            error=CleanupError(
                "Some stored blocks could not be deleted and will be retried.",
                detail=f"{len(failed_keys)} object(s) pending cleanup",
            ),
            objects_done=len(result["deleted"]) + len(result["missing"]),
        )
        raise CleanupError(
            "Some encrypted blocks could not be deleted. SecureCloud has recorded the "
            "remaining objects and will retry the cleanup; the file is no longer "
            "available for download.",
            detail=f"pending={len(failed_keys)}",
        )

    # Remove per-block records and the wrapped key, then finalise the metadata.
    for block in list(file.blocks):
        db.session.delete(block)
    if file.wrapped_key is not None:
        db.session.delete(file.wrapped_key)
    file.status = STATUS_DELETED
    file.block_count = 0
    file.deleted_at = utcnow()
    file.updated_at = utcnow()
    file.cleanup_pending = False
    file.last_error = None
    db.session.commit()

    service.finish_operation(
        operation, status="success",
        objects_done=len(result["deleted"]) + len(result["missing"]),
    )
    logger.info("Deleted file id=%s (%s objects).", file.id, len(keys))
    return {
        "deleted": True,
        "objects_deleted": len(result["deleted"]),
        "objects_missing": len(result["missing"]),
        "cleanup_pending": False,
        "already_deleted": False,
    }


def purge_file_records(file: StoredFile) -> None:
    """Hard-delete a metadata row (used by the cleanup sweeps)."""
    db.session.delete(file)
    db.session.commit()


__all__ = [
    "DownloadResult",
    "UploadResult",
    "create_pending_file",
    "delete_file",
    "download_file",
    "indexes_missing",
    "owned_file_or_404",
    "purge_file_records",
    "stage_upload",
    "upload_file",
]
