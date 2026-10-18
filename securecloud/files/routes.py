"""Upload, listing, details, download and delete routes for stored files."""
from __future__ import annotations

import logging
import os
import tempfile

from flask import (
    Blueprint,
    after_this_request,
    abort,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from sqlalchemy import func

from securecloud.auth.forms import DeleteFileForm, UploadForm
from securecloud.extensions import db, limiter
from securecloud.models import (
    STATUS_COMPLETE,
    STATUS_DELETED,
    STATUS_FAILED,
    EncryptedBlock,
    StoredFile,
    utcnow,
)
from securecloud.security import current_user, json_error, login_required, wants_json
from securecloud.services import (
    CleanupError,
    FileIntegrityError,
    FileNotFoundForUser,
    FileOperationError,
    FileTooLargeError,
    FileValidationError,
    InvalidFileStateError,
    SecureCloudError,
    chunking,
)
from securecloud.services import cleanup_service, file_service, integrity
from securecloud.services.key_manager import get_key_manager
from securecloud.services.storage_service import get_storage_service
from securecloud.utils import human_size, redact, sanitize_filename

logger = logging.getLogger("securecloud.files")

files_bp = Blueprint("files", __name__, url_prefix="/files")


def _handle(exc: SecureCloudError) -> tuple:
    """Convert a domain error into a safe user-facing response."""
    if wants_json():
        return jsonify({"error": exc.category, "message": exc.public_message}), getattr(exc, "http_status", 500)
    flash(exc.public_message, "danger")
    return redirect(url_for("files.index"))


# --------------------------------------------------------------------------
# Upload
# --------------------------------------------------------------------------
@files_bp.route("/upload", methods=["GET", "POST"])
@login_required
@limiter.limit("60 per hour", methods=["POST"])
def upload():  # noqa: ANN202
    user = current_user()
    key_manager = get_key_manager()
    storage_service = get_storage_service()
    form = UploadForm()

    if request.method == "POST" and not key_manager.configured:
        message = ("Encryption is unavailable because the key-encryption key is not "
                   "configured. Ask the administrator to set SECURECLOUD_KEY_ENCRYPTION_KEY.")
        if wants_json():
            return json_error(message, 503, "configuration_error")
        flash(message, "danger")
        return render_template("upload.html", form=form, key_status=key_manager.status(),
                               storage=storage_service.description,
                               block_size=current_app.config.get("BLOCK_SIZE")), 503

    if form.validate_on_submit():
        upload_stream = form.file.data
        filename = sanitize_filename(
            getattr(upload_stream, "filename", "") or "upload.bin",
            max_length=current_app.config.get("MAX_FILENAME_LENGTH", 255),
        )
        if not filename:
            filename = "upload.bin"
        mime_type = (getattr(upload_stream, "mimetype", "") or "application/octet-stream")[:255]

        staged_path = None
        try:
            # 1) Stage the incoming stream to disk (bounded memory, size enforced).
            staging_dir = current_app.config["STAGING_DIR"]
            os.makedirs(staging_dir, exist_ok=True)
            fd, staged_path = tempfile.mkstemp(dir=staging_dir, prefix="upload-incoming-")
            with os.fdopen(fd, "wb") as handle:
                chunking.stage_stream_to_file(
                    upload_stream.stream, staged_path,
                    max_bytes=current_app.config.get("MAX_CONTENT_LENGTH"),
                )

            # 2) Encrypt every block, store it, then commit metadata.
            result = file_service.upload_file(user, staged_path, filename, mime_type)

            if wants_json():
                return jsonify({
                    "ok": True,
                    "file": {
                        "id": result.file.id,
                        "filename": result.file.original_filename,
                        "size": result.total_size,
                        "blocks": result.block_count,
                        "encrypted_bytes": result.encrypted_bytes,
                        "storage_backend": result.storage_backend,
                    },
                    "message": "Upload complete: the file was encrypted and stored.",
                }), 201

            flash(
                f"'{result.file.original_filename}' was encrypted into {result.block_count} "
                f"block(s) and stored successfully.",
                "success",
            )
            return redirect(url_for("files.details", file_id=result.file.id))

        except FileTooLargeError as exc:
            return _handle(exc)
        except FileValidationError as exc:
            return _handle(exc)
        except SecureCloudError as exc:
            logger.warning("Upload failed: %s", exc.detail or exc.public_message)
            return _handle(exc)
        except Exception as exc:  # pragma: no cover - unexpected
            logger.exception("Unexpected upload failure")
            message = ("The upload could not be completed because of an unexpected error. "
                       "No partial file was recorded as stored.")
            if wants_json():
                return json_error(message, 500, "upload_failed")
            flash(message, "danger")
            return redirect(url_for("files.upload"))
        finally:
            chunking.remove_quietly(staged_path)

    if request.method == "POST":
        flash("Please choose a file to upload.", "danger")

    return render_template(
        "upload.html",
        form=form,
        key_status=key_manager.status(),
        storage=storage_service.description,
        block_size=current_app.config.get("BLOCK_SIZE"),
        max_upload_bytes=current_app.config.get("MAX_CONTENT_LENGTH"),
        errors=form.errors,
    )


# --------------------------------------------------------------------------
# Listing and details
# --------------------------------------------------------------------------
@files_bp.route("/")
@login_required
def index():  # noqa: ANN202
    user = current_user()
    page = max(request.args.get("page", 1, type=int) or 1, 1)
    per_page = int(current_app.config.get("FILES_PER_PAGE", 20))
    status_filter = (request.args.get("status") or "").strip().lower()

    query = StoredFile.query.filter_by(owner_id=user.id)
    if status_filter in ("complete", "failed", "pending", "uploading", "deleted"):
        query = query.filter(StoredFile.status == status_filter)
    else:
        status_filter = ""

    pagination = query.order_by(StoredFile.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    delete_form = DeleteFileForm()
    return render_template(
        "files.html",
        pagination=pagination,
        files=pagination.items,
        delete_form=delete_form,
        status_filter=status_filter,
        total=query.count(),
    )


@files_bp.route("/<int:file_id>")
@login_required
def details(file_id: int):  # noqa: ANN202
    user = current_user()
    try:
        file = file_service.owned_file_or_404(file_id, user)
    except FileNotFoundForUser as exc:
        logger.info("Blocked access to file id=%s by user id=%s", file_id, user.id)
        return _handle(exc)

    blocks = sorted(file.blocks, key=lambda b: b.block_index)
    manifest_ok = None
    if file.status == STATUS_COMPLETE and blocks:
        manifest_ok = integrity.verify_manifest(file, get_storage_service())
    return render_template(
        "file_details.html",
        file=file,
        blocks=blocks,
        manifest=manifest_ok,
        delete_form=DeleteFileForm(),
        plaintext_overhead=sum(b.overhead_bytes for b in blocks),
    )


@files_bp.route("/<int:file_id>/verify", methods=["POST"])
@login_required
@limiter.limit("60 per hour")
def verify(file_id: int):  # noqa: ANN202
    user = current_user()
    try:
        file = file_service.owned_file_or_404(file_id, user)
    except FileNotFoundForUser as exc:
        return _handle(exc)

    deep = request.form.get("deep") == "1"
    report = integrity.verify_manifest(file, get_storage_service(), deep=deep)
    if deep and report.ok:
        # Confirm the full plaintext round-trip digest as well.
        try:
            digest_report = integrity.verify_reconstruction(
                blocks=list(file.blocks), file=file, key_manager=get_key_manager()
            )
            report.add_check("plaintext_digest", bool(digest_report.get("matches_recorded")),
                             "whole-file SHA-256 compared with the upload record")
        except Exception as exc:
            report.add_check("plaintext_digest", False, type(exc).__name__)

    if wants_json():
        return jsonify(report.as_dict()), (200 if report.ok else 422)
    if report.ok:
        flash("Integrity check passed: every block is present and authenticates correctly.", "success")
    else:
        flash("Integrity check failed: " + " ".join(report.problems[:3]), "danger")
    return redirect(url_for("files.details", file_id=file.id))


# --------------------------------------------------------------------------
# Download
# --------------------------------------------------------------------------
@files_bp.route("/<int:file_id>/download")
@login_required
@limiter.limit("240 per hour")
def download(file_id: int):  # noqa: ANN202
    user = current_user()
    try:
        file = file_service.owned_file_or_404(file_id, user)
    except FileNotFoundForUser as exc:
        logger.info("Blocked download of file id=%s by user id=%s", file_id, user.id)
        return _handle(exc)

    try:
        result = file_service.download_file(file, user)
    except InvalidFileStateError as exc:
        return _handle(exc)
    except FileIntegrityError as exc:
        logger.warning("Integrity failure on download of file id=%s: %s", file_id, exc.detail)
        return _handle(exc)
    except SecureCloudError as exc:
        return _handle(exc)

    response = send_file(
        result.temp_path,
        as_attachment=True,
        download_name=result.filename,
        mimetype="application/octet-stream",
        conditional=False,
        max_age=0,
    )
    response.headers["Content-Length"] = str(result.size)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"

    @after_this_request
    def _cleanup_temp_file(response):  # noqa: ANN001, ANN202
        """Remove the plaintext temporary file after the response is sent."""
        chunking.remove_quietly(result.temp_path)
        return response

    return response


# --------------------------------------------------------------------------
# Delete
# --------------------------------------------------------------------------
@files_bp.route("/<int:file_id>/delete", methods=["POST"])
@login_required
@limiter.limit("120 per hour")
def delete(file_id: int):  # noqa: ANN202
    user = current_user()
    try:
        file = file_service.owned_file_or_404(file_id, user)
    except FileNotFoundForUser as exc:
        return _handle(exc)

    try:
        outcome = file_service.delete_file(file, user)
    except CleanupError as exc:
        logger.warning("Partial delete for file id=%s: %s", file_id, exc.detail)
        return _handle(exc)
    except SecureCloudError as exc:
        return _handle(exc)

    if wants_json():
        return jsonify({"ok": True, "message": "File deleted.", **outcome})
    flash("The file and all of its encrypted blocks were deleted.", "success")
    return redirect(url_for("files.index"))


# --------------------------------------------------------------------------
# JSON API helpers (same authorization rules as the HTML routes)
# --------------------------------------------------------------------------
@files_bp.route("/api/list")
@login_required
def api_list():  # noqa: ANN202
    user = current_user()
    files = (
        StoredFile.query.filter_by(owner_id=user.id)
        .filter(StoredFile.status != STATUS_DELETED)
        .order_by(StoredFile.created_at.desc())
        .limit(200)
        .all()
    )
    return jsonify({
        "count": len(files),
        "files": [
            {
                "id": f.id,
                "filename": f.original_filename,
                "size": f.file_size,
                "size_human": human_size(f.file_size),
                "blocks": f.block_count,
                "status": f.status,
                "storage_backend": f.storage_backend,
                "created_at": f.created_at.isoformat() if f.created_at else None,
                "download_url": url_for("files.download", file_id=f.id),
                "details_url": url_for("files.details", file_id=f.id),
            }
            for f in files
        ],
    })


@files_bp.route("/api/<int:file_id>/integrity")
@login_required
def api_integrity(file_id: int):  # noqa: ANN202
    user = current_user()
    try:
        file = file_service.owned_file_or_404(file_id, user)
    except FileNotFoundForUser as exc:
        return _handle(exc)
    # Shallow metadata checks cannot see a flipped bit inside an object, so the
    # default is the full AEAD verification; pass ?deep=0 for the cheap check.
    deep = request.args.get("deep", "1") != "0"
    report = integrity.verify_manifest(
        file, get_storage_service(), deep=deep, key_manager=get_key_manager()
    )
    return jsonify(report.as_dict()), (200 if report.ok else 422)


@files_bp.errorhandler(413)
def handle_too_large(error):  # noqa: ANN001, ANN202
    limit = current_app.config.get("MAX_CONTENT_LENGTH") or 0
    message = f"The uploaded file exceeds the limit of {human_size(limit)}."
    if wants_json():
        return json_error(message, 413, "file_too_large")
    flash(message, "danger")
    return redirect(url_for("files.upload")), 413
