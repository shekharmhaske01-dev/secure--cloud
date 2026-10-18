"""Block-level object-storage service.

Wraps the configured storage adapter with the operations the application needs
for encrypted blocks, translating provider failures into the application's
error taxonomy and recording storage operations for recovery.
"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime

from flask import current_app

from securecloud.extensions import db
from securecloud.models import StorageOperation, utcnow
from securecloud.storage import ObjectStorage, StorageError, StorageObjectNotFoundError, get_storage
from securecloud.utils import redact

logger = logging.getLogger("securecloud.storage_service")

BLOCK_CONTENT_TYPE = "application/octet-stream"


class StorageService:
    """Application-facing wrapper around an :class:`ObjectStorage` adapter."""

    def __init__(self, adapter: ObjectStorage, prefix: str = ""):
        self.adapter = adapter
        self.prefix = (prefix or "").strip("/")

    # --- identity ---------------------------------------------------------
    @property
    def description(self):
        return self.adapter.describe()

    @property
    def backend_name(self) -> str:
        return self.adapter.backend_name

    @property
    def is_local(self) -> bool:
        return self.adapter.is_local

    def health_check(self) -> dict:
        try:
            return self.adapter.health_check()
        except Exception as exc:  # pragma: no cover - adapter already guards
            return {"ok": False, "message": redact(str(exc)), "details": {}}

    # --- object keys ------------------------------------------------------
    @staticmethod
    def new_file_identifier() -> str:
        """Random, opaque file identifier used in object keys and AAD."""
        return secrets.token_hex(16)

    def block_prefix(self, file_uid: str) -> str:
        """Shard by the first two characters to keep listings small."""
        return f"{file_uid[:2]}/{file_uid}"

    def block_key(self, file_uid: str, block_index: int) -> str:
        """Return the object key for a block.

        The key contains only the opaque file identifier and the block index -
        never the original filename or any user information.
        """
        return f"{self.block_prefix(file_uid)}/{block_index:08d}.blk"

    # --- block operations -------------------------------------------------
    def store_block(self, file_uid: str, block_index: int, ciphertext: bytes,
                    metadata: dict | None = None) -> dict:
        key = self.block_key(file_uid, block_index)
        meta = {
            "securecloud-format-version": str((metadata or {}).get("format_version", 1)),
            "securecloud-block-index": str(block_index),
        }
        result = self.adapter.upload_object(key, ciphertext, content_type=BLOCK_CONTENT_TYPE, metadata=meta)
        if result.get("size") != len(ciphertext):
            from securecloud.storage import StorageIntegrityError

            raise StorageIntegrityError(
                "The stored object size does not match the encrypted block that was sent.",
                detail=f"key={key}",
            )
        return result

    def fetch_block(self, object_key: str) -> bytes:
        return self.adapter.download_object(object_key)

    def delete_block(self, object_key: str) -> bool:
        return self.adapter.delete_object(object_key)

    def object_info(self, object_key: str) -> dict:
        return self.adapter.object_info(object_key)

    def delete_blocks(self, object_keys: list[str]) -> dict:
        """Delete several objects, reporting individual failures.

        Returns ``{deleted: [...], missing: [...], failed: [(key, message)]}`` so
        the caller can schedule recoverable cleanup for whatever remains.
        """
        deleted: list[str] = []
        missing: list[str] = []
        failed: list[tuple[str, str]] = []
        for key in object_keys:
            try:
                if self.adapter.delete_object(key):
                    deleted.append(key)
                else:
                    missing.append(key)
            except StorageObjectNotFoundError:
                missing.append(key)
            except StorageError as exc:
                failed.append((key, exc.public_message))
            except Exception as exc:  # pragma: no cover - defensive
                failed.append((key, redact(str(exc), 120)))
        return {"deleted": deleted, "missing": missing, "failed": failed}

    def list_block_keys(self, file_uid: str) -> list[str]:
        return self.adapter.list_objects(prefix=self.block_prefix(file_uid))

    # --- operation records -----------------------------------------------
    def start_operation(self, operation_type: str, file_id: int | None = None,
                        objects_total: int = 0) -> StorageOperation:
        operation = StorageOperation(
            id=secrets.token_hex(16),
            file_id=file_id,
            operation_type=operation_type,
            status="running",
            storage_backend=self.backend_name,
            objects_total=objects_total,
        )
        db.session.add(operation)
        db.session.commit()
        return operation

    def finish_operation(self, operation: StorageOperation, *, status: str = "success",
                         error: Exception | None = None, objects_done: int | None = None,
                         bytes_processed: int | None = None) -> StorageOperation:
        operation.status = status
        if objects_done is not None:
            operation.objects_done = objects_done
        if bytes_processed is not None:
            operation.bytes_processed = bytes_processed
        if error is not None:
            category = getattr(error, "category", None) or "unknown"
            detail = getattr(error, "detail", "") or str(error)
            operation.error_category = category
            operation.error_detail = redact(detail, 480)
        operation.finished_at = utcnow()
        operation.updated_at = utcnow()
        db.session.commit()
        return operation

    def record_failure(self, operation_type: str, file_id: int | None, error: Exception,
                       objects_total: int = 0, objects_done: int = 0) -> StorageOperation:
        operation = StorageOperation(
            id=secrets.token_hex(16),
            file_id=file_id,
            operation_type=operation_type,
            status="failed",
            storage_backend=self.backend_name,
            objects_total=objects_total,
            objects_done=objects_done,
            error_category=getattr(error, "category", None) or "unknown",
            error_detail=redact(getattr(error, "detail", "") or str(error), 480),
            finished_at=utcnow(),
        )
        db.session.add(operation)
        db.session.commit()
        return operation


_service: StorageService | None = None
_service_backend: str | None = None


def get_storage_service() -> StorageService:
    """Return a StorageService for the current application."""
    global _service, _service_backend
    adapter = get_storage()
    if _service is None or _service.adapter is not adapter:
        _service = StorageService(adapter, prefix=str(current_app.config.get("STORAGE_PREFIX") or ""))
        _service_backend = adapter.backend_name
    return _service


def storage_status() -> dict:
    """Compact status block used by the dashboard and settings pages."""
    service = get_storage_service()
    return {
        "backend": service.backend_name,
        "is_local": service.is_local,
        "description": service.description.as_dict(),
    }


__all__ = [
    "BLOCK_CONTENT_TYPE",
    "StorageService",
    "get_storage",
    "get_storage_service",
    "storage_status",
    "datetime",
]
