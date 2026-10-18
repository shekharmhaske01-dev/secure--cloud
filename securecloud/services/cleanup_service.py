"""Cleanup and recovery for incomplete uploads and pending deletions.

Cloud object storage and SQLite do not share a transaction, so every operation
that touches both is designed with compensating work:

* a failed upload records a :class:`CleanupJob` for the objects it created;
* a partially failed delete records the objects that remain;
* ``run_maintenance()`` retries those jobs and sweeps away abandoned staging
  files and unfinished upload records.
"""
from __future__ import annotations

import logging
import os
from datetime import timedelta

from flask import current_app

from securecloud.extensions import db
from securecloud.models import (
    STATUS_DELETED,
    STATUS_DELETING,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_UPLOADING,
    CleanupJob,
    EncryptedBlock,
    StoredFile,
    utcnow,
)
from securecloud.services.storage_service import get_storage_service
from securecloud.utils import redact

logger = logging.getLogger("securecloud.cleanup")

STAGING_PREFIX = "upload-"


def find_stale_unfinished_files(minutes: int | None = None) -> list[StoredFile]:
    """Upload records that never completed and are older than the threshold."""
    threshold_minutes = minutes or int(current_app.config.get("STALE_UPLOAD_MINUTES", 60))
    cutoff = utcnow() - timedelta(minutes=threshold_minutes)
    return (
        StoredFile.query.filter(
            StoredFile.status.in_((STATUS_PENDING, STATUS_UPLOADING, STATUS_FAILED)),
            StoredFile.updated_at < cutoff,
        )
        .order_by(StoredFile.id.asc())
        .all()
    )


def find_pending_cleanup_jobs(limit: int = 100) -> list[CleanupJob]:
    return (
        CleanupJob.query.filter(CleanupJob.status.in_(("pending", "failed")))
        .order_by(CleanupJob.created_at.asc())
        .limit(limit)
        .all()
    )


def sweep_staging_directory() -> dict:
    """Remove abandoned staging files (interrupted or oversized uploads)."""
    staging_dir = current_app.config["STAGING_DIR"]
    removed: list[str] = []
    errors: list[str] = []
    if not os.path.isdir(staging_dir):
        return {"removed": removed, "errors": errors}
    for name in os.listdir(staging_dir):
        if not name.startswith(STAGING_PREFIX):
            continue
        path = os.path.join(staging_dir, name)
        try:
            if os.path.isfile(path):
                os.remove(path)
                removed.append(name)
        except OSError as exc:
            errors.append(redact(str(exc), 160))
    return {"removed": removed, "errors": errors}


def sweep_download_temp() -> dict:
    """Remove any leftover plaintext download files."""
    temp_dir = current_app.config["DOWNLOAD_TEMP_DIR"]
    removed: list[str] = []
    errors: list[str] = []
    if not os.path.isdir(temp_dir):
        return {"removed": removed, "errors": errors}
    for name in os.listdir(temp_dir):
        path = os.path.join(temp_dir, name)
        try:
            if os.path.isfile(path):
                os.remove(path)
                removed.append(name)
        except OSError as exc:
            errors.append(redact(str(exc), 160))
    return {"removed": removed, "errors": errors}


def cleanup_file_objects(file: StoredFile, *, record_job: bool = True) -> dict:
    """Delete every object belonging to *file* and its per-block metadata."""
    service = get_storage_service()
    keys = [b.object_key for b in file.blocks]
    if not keys:
        return {"deleted": [], "missing": [], "failed": [], "keys": 0}

    result = service.delete_blocks(keys)
    failed_keys = [key for key, _msg in result["failed"]]

    if failed_keys and record_job:
        job = CleanupJob(
            file_id=file.id,
            public_id=file.public_id,
            reason="retry_delete",
            status="pending",
            object_keys=failed_keys,
            last_error=redact(result["failed"][0][1], 300),
        )
        db.session.add(job)
        file.cleanup_pending = True
        db.session.commit()
    elif not failed_keys:
        for block in list(file.blocks):
            db.session.delete(block)
        if file.wrapped_key is not None:
            db.session.delete(file.wrapped_key)
        file.block_count = 0
        file.cleanup_pending = False
        db.session.commit()

    return {
        "deleted": len(result["deleted"]),
        "missing": len(result["missing"]),
        "failed": len(failed_keys),
        "keys": len(keys),
    }


def recover_incomplete_upload(file: StoredFile) -> dict:
    """Clean up an upload that never completed and finalise its metadata."""
    keys = [b.object_key for b in file.blocks]
    if not keys:
        keys = get_storage_service().list_block_keys(file.public_id)

    result = cleanup_file_objects(file, record_job=True)
    file.status = STATUS_FAILED if file.status != STATUS_DELETED else file.status
    file.last_error = file.last_error or "Unfinished upload cleaned up during recovery."
    file.updated_at = utcnow()
    db.session.commit()
    logger.info("Recovered unfinished upload id=%s (%s objects).", file.id, len(keys))
    return {"file_id": file.id, "objects": len(keys), **result}


def run_cleanup_jobs(limit: int = 100) -> dict:
    """Retry recorded cleanup work."""
    service = get_storage_service()
    jobs = find_pending_cleanup_jobs(limit=limit)
    summary = {"jobs": 0, "objects_deleted": 0, "objects_missing": 0, "still_failed": 0, "completed": []}
    for job in jobs:
        job.status = "running"
        job.attempts = (job.attempts or 0) + 1
        db.session.commit()
        keys = list(job.object_keys or [])
        result = service.delete_blocks(keys)
        summary["jobs"] += 1
        summary["objects_deleted"] += len(result["deleted"])
        summary["objects_missing"] += len(result["missing"])
        if result["failed"]:
            job.status = "failed"
            job.last_error = redact(result["failed"][0][1], 300)
            job.object_keys = [key for key, _msg in result["failed"]]
            summary["still_failed"] += len(job.object_keys)
            db.session.commit()
            continue
        job.status = "done"
        job.object_keys = []
        job.last_error = None
        file = db.session.get(StoredFile, job.file_id) if job.file_id else None
        if file is not None:
            # The objects this job owned are confirmed gone, so their manifest
            # rows can go too; rows for a newer upload are left untouched.
            job_keys = set(keys)
            for block in list(file.blocks):
                if not job_keys or block.object_key in job_keys:
                    db.session.delete(block)
            db.session.flush()
            if EncryptedBlock.query.filter_by(file_id=file.id).count() == 0:
                if file.wrapped_key is not None:
                    db.session.delete(file.wrapped_key)
                file.cleanup_pending = False
                if file.status in (STATUS_DELETING, STATUS_FAILED):
                    file.status = STATUS_DELETED
                    file.deleted_at = utcnow()
            db.session.commit()
        summary["completed"].append(job.id)
        db.session.commit()
    return summary


def abandon_stale_uploading_files(minutes: int | None = None, hard_delete: bool = False) -> dict:
    """Recover uploads that were interrupted (e.g. the process was killed)."""
    stale = find_stale_unfinished_files(minutes)
    recovered = []
    for file in stale:
        try:
            recover_incomplete_upload(file)
            recovered.append({"file_id": file.id, "filename": file.original_filename, "status": file.status})
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Recovery failed for file id=%s: %s", file.id, redact(str(exc)))
    if hard_delete:
        for file in stale:
            if file.status in (STATUS_FAILED, STATUS_DELETED) and not file.cleanup_pending:
                db.session.delete(file)
        db.session.commit()
    return {"recovered": recovered, "count": len(recovered), "hard_deleted": hard_delete}


def run_maintenance(minutes: int | None = None, hard_delete: bool = False) -> dict:
    """Full maintenance pass used by the CLI and the maintenance endpoint."""
    with_ctx = current_app._get_current_object()
    logger.info("Maintenance run started (app=%s).", with_ctx.config.get("APP_NAME"))
    result = {
        "started_at": utcnow().isoformat(),
        "cleanup_jobs": run_cleanup_jobs(),
        "incomplete_uploads": abandon_stale_uploading_files(minutes, hard_delete=hard_delete),
        "staging": sweep_staging_directory(),
        "download_temp": sweep_download_temp(),
    }
    result["finished_at"] = utcnow().isoformat()
    logger.info("Maintenance run finished: %s", {k: v for k, v in result.items() if k.endswith("_jobs")})
    return result


def recovery_summary() -> dict:
    """Numbers shown on the Settings page."""
    return {
        "failed_files": StoredFile.query.filter_by(status=STATUS_FAILED).count(),
        "deleting_files": StoredFile.query.filter_by(status=STATUS_DELETING).count(),
        "unfinished_files": StoredFile.query.filter(
            StoredFile.status.in_((STATUS_PENDING, STATUS_UPLOADING))
        ).count(),
        "pending_cleanup_jobs": CleanupJob.query.filter(CleanupJob.status.in_(("pending", "failed"))).count(),
        "deleted_files": StoredFile.query.filter_by(status=STATUS_DELETED).count(),
    }


__all__ = [
    "abandon_stale_uploading_files",
    "cleanup_file_objects",
    "find_pending_cleanup_jobs",
    "find_stale_unfinished_files",
    "recover_incomplete_upload",
    "recovery_summary",
    "run_cleanup_jobs",
    "run_maintenance",
    "sweep_download_temp",
    "sweep_staging_directory",
]
