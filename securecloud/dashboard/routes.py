"""Landing page, dashboard and settings routes."""
from __future__ import annotations

import logging

from flask import Blueprint, current_app, jsonify, redirect, render_template, url_for
from sqlalchemy import func

from securecloud.extensions import db, limiter
from securecloud.models import (
    STATUS_COMPLETE,
    STATUS_DELETED,
    STATUS_FAILED,
    EncryptedBlock,
    StoredFile,
    User,
    utcnow,
)
from securecloud.security import current_user, login_required
from securecloud.services import chunking, encryption
from securecloud.services import cleanup_service
from securecloud.services.key_manager import get_key_manager
from securecloud.services.storage_service import get_storage_service

logger = logging.getLogger("securecloud.dashboard")

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():  # noqa: ANN202
    """Landing page (public)."""
    return render_template(
        "index.html",
        features=[
            {
                "icon": "blocks",
                "title": "File segmentation",
                "text": "Every upload is split into configurable blocks (1 MiB by default) "
                        "and each block is handled independently.",
            },
            {
                "icon": "shield",
                "title": "AES-256-GCM encryption",
                "text": "Each block is sealed with authenticated encryption using a fresh "
                        "nonce and additional authenticated data.",
            },
            {
                "icon": "key",
                "title": "Envelope key management",
                "text": "A unique file key encrypts the blocks; it is itself wrapped by a "
                        "key-encryption key that never touches the database.",
            },
            {
                "icon": "cloud",
                "title": "Cloud object storage",
                "text": "Encrypted blocks are stored as separate objects in S3-compatible "
                        "object storage (Neon Object Storage).",
            },
            {
                "icon": "check",
                "title": "Integrity verification",
                "text": "Block counts, ordering, sizes and GCM authentication tags are "
                        "verified before any download is released.",
            },
            {
                "icon": "user",
                "title": "Accounts and authorization",
                "text": "Argon2 password hashing, server-side sessions, CSRF protection and "
                        "per-file ownership checks on every operation.",
            },
        ],
        storage=get_storage_service().description,
        key_status=get_key_manager().status(),
    )


@dashboard_bp.route("/dashboard")
@login_required
def dashboard():  # noqa: ANN202
    """Authenticated overview of the current user's storage."""
    user = current_user()
    total_files = StoredFile.query.filter_by(owner_id=user.id).filter(
        StoredFile.status != STATUS_DELETED
    ).count()
    completed = StoredFile.query.filter_by(owner_id=user.id, status=STATUS_COMPLETE).count()
    failed = StoredFile.query.filter_by(owner_id=user.id, status=STATUS_FAILED).count()

    logical_size = (
        db.session.query(func.coalesce(func.sum(StoredFile.file_size), 0))
        .filter(StoredFile.owner_id == user.id, StoredFile.status == STATUS_COMPLETE)
        .scalar()
        or 0
    )
    block_count = (
        db.session.query(func.count(EncryptedBlock.id))
        .join(StoredFile, EncryptedBlock.file_id == StoredFile.id)
        .filter(StoredFile.owner_id == user.id, StoredFile.status == STATUS_COMPLETE)
        .scalar()
        or 0
    )
    encrypted_size = (
        db.session.query(func.coalesce(func.sum(EncryptedBlock.encrypted_size), 0))
        .join(StoredFile, EncryptedBlock.file_id == StoredFile.id)
        .filter(StoredFile.owner_id == user.id, StoredFile.status == STATUS_COMPLETE)
        .scalar()
        or 0
    )

    recent = (
        StoredFile.query.filter_by(owner_id=user.id)
        .filter(StoredFile.status != STATUS_DELETED)
        .order_by(StoredFile.created_at.desc())
        .limit(6)
        .all()
    )
    storage_service = get_storage_service()
    health = storage_service.health_check()

    return render_template(
        "dashboard.html",
        stats={
            "total_files": total_files,
            "completed": completed,
            "failed": failed,
            "logical_size": int(logical_size),
            "encrypted_size": int(encrypted_size),
            "block_count": int(block_count),
            "overhead": int(encrypted_size) - int(logical_size),
        },
        recent_files=recent,
        storage=storage_service.description,
        storage_health=health,
        key_status=get_key_manager().status(),
        block_size=current_app.config.get("BLOCK_SIZE"),
    )


@dashboard_bp.route("/settings")
@login_required
def settings():  # noqa: ANN202
    """Configuration and storage status (never exposes secrets)."""
    storage_service = get_storage_service()
    health = storage_service.health_check()
    key_manager = get_key_manager()
    recovery = cleanup_service.recovery_summary()
    return render_template(
        "settings.html",
        storage=storage_service.description,
        storage_health=health,
        key_status=key_manager.status(),
        block_format=encryption.describe_format(),
        recovery=recovery,
        config_summary={
            "environment": current_app.config.get("ENVIRONMENT"),
            "block_size": current_app.config.get("BLOCK_SIZE"),
            "max_upload_bytes": current_app.config.get("MAX_CONTENT_LENGTH"),
            "session_hours": int(current_app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() // 3600),
            "stale_upload_minutes": current_app.config.get("STALE_UPLOAD_MINUTES"),
            "rate_limits": {
                "login": current_app.config.get("RATELIMIT_LOGIN"),
                "register": current_app.config.get("RATELIMIT_REGISTER"),
                "upload": current_app.config.get("RATELIMIT_UPLOAD"),
                "download": current_app.config.get("RATELIMIT_DOWNLOAD"),
            },
        },
        block_size_bounds={"min": chunking.MIN_BLOCK_SIZE, "max": chunking.MAX_BLOCK_SIZE},
    )


@dashboard_bp.route("/settings/storage-check")
@login_required
@limiter.limit("30 per hour")
def storage_check():  # noqa: ANN202
    """Re-run the storage connectivity test (JSON, used by the Settings page)."""
    service = get_storage_service()
    health = service.health_check()
    return jsonify({
        "ok": bool(health.get("ok")),
        "message": health.get("message", ""),
        "backend": service.backend_name,
        "is_local": service.is_local,
        "details": health.get("details", {}),
    })


@dashboard_bp.route("/settings/maintenance", methods=["POST"])
@login_required
@limiter.limit("10 per hour")
def run_maintenance():  # noqa: ANN202
    """Recover unfinished uploads and retry pending object cleanup."""
    result = cleanup_service.run_maintenance()
    from flask import flash

    recovered = result["incomplete_uploads"]["count"]
    retried = result["cleanup_jobs"]["jobs"]
    flash(
        f"Maintenance completed: {recovered} unfinished upload(s) recovered and "
        f"{retried} cleanup job(s) processed.",
        "success",
    )
    logger.info("Manual maintenance run by user id=%s", getattr(current_user(), "id", None))
    return redirect(url_for("dashboard.settings"))


@dashboard_bp.route("/about")
def about():  # noqa: ANN202
    user_count = User.query.count()
    file_count = StoredFile.query.filter_by(status=STATUS_COMPLETE).count()
    return render_template(
        "about.html",
        block_format=encryption.describe_format(),
        user_count=user_count,
        file_count=file_count,
        storage=get_storage_service().description,
        now=utcnow(),
    )
