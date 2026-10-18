"""Database models for SecureCloud.

The metadata database (SQLite) stores *only* metadata:
users, file descriptions, encrypted-block records, wrapped data-encryption
keys and storage operation records.  Plaintext file content and unwrapped
file keys are never written here.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timezone

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import CheckConstraint, ForeignKey, Index, UniqueConstraint
from sqlalchemy.orm import relationship

from securecloud.extensions import db

# --------------------------------------------------------------------------
# Upload lifecycle / operation states
# --------------------------------------------------------------------------
STATUS_PENDING = "pending"
STATUS_UPLOADING = "uploading"
STATUS_COMPLETE = "complete"
STATUS_FAILED = "failed"
STATUS_DELETING = "deleting"
STATUS_DELETED = "deleted"

UPLOAD_STATUSES = (
    STATUS_PENDING,
    STATUS_UPLOADING,
    STATUS_COMPLETE,
    STATUS_FAILED,
    STATUS_DELETING,
    STATUS_DELETED,
)

OPERATION_TYPES = ("upload", "download", "delete", "cleanup", "verify")
OPERATION_STATUSES = ("pending", "running", "success", "failed", "partial")

CLEANUP_PENDING = "pending"
CLEANUP_RUNNING = "running"
CLEANUP_DONE = "done"
CLEANUP_FAILED = "failed"
CLEANUP_STATUSES = (CLEANUP_PENDING, CLEANUP_RUNNING, CLEANUP_DONE, CLEANUP_FAILED)

# Statuses whose bytes are complete and safe to download.
DOWNLOADABLE_STATUSES = (STATUS_COMPLETE,)

# Statuses that indicate an unfinished upload (candidates for recovery sweeps).
UNFINISHED_STATUSES = (STATUS_PENDING, STATUS_UPLOADING)


def utcnow() -> datetime:
    """Timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------
# Password hashing (Argon2id)
# --------------------------------------------------------------------------
DEFAULT_ARGON2_PARAMS = {
    "time_cost": 2,
    "memory_cost": 19456,  # 19 MiB (OWASP minimum recommendation)
    "parallelism": 1,
    "hash_len": 32,
    "salt_len": 16,
}
_hasher: PasswordHasher | None = None
_hasher_params: dict | None = None


def get_password_hasher() -> PasswordHasher:
    """Return a cached Argon2 PasswordHasher, honouring optional app config."""
    global _hasher, _hasher_params
    params = dict(DEFAULT_ARGON2_PARAMS)
    try:
        from flask import current_app

        cfg = current_app.config
        params["time_cost"] = int(cfg.get("ARGON2_TIME_COST", params["time_cost"]))
        params["memory_cost"] = int(cfg.get("ARGON2_MEMORY_COST", params["memory_cost"]))
        params["parallelism"] = int(cfg.get("ARGON2_PARALLELISM", params["parallelism"]))
    except Exception:  # outside an application context (scripts, tests)
        pass
    if _hasher is None or _hasher_params != params:
        _hasher = PasswordHasher(**params)
        _hasher_params = params
    return _hasher


def hash_password(password: str) -> str:
    return get_password_hasher().hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return get_password_hasher().verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError, TypeError):
        return False


def password_needs_rehash(password_hash: str) -> bool:
    try:
        return get_password_hasher().check_needs_rehash(password_hash)
    except (InvalidHashError, TypeError):
        return True


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), nullable=False, unique=True, index=True)
    email = db.Column(db.String(255), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    # Server-side session identifier: rotating it invalidates every existing
    # session for this account (used on login and password change).
    session_token = db.Column(db.String(64), nullable=False, default=lambda: secrets.token_urlsafe(32))
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)

    files = relationship(
        "StoredFile",
        back_populates="owner",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint("length(username) >= 3", name="ck_users_username_len"),
    )

    # --- password helpers -------------------------------------------------
    def set_password(self, password: str) -> None:
        self.password_hash = hash_password(password)
        self.updated_at = utcnow()

    def check_password(self, password: str) -> bool:
        if not self.password_hash:
            return False
        ok = verify_password(self.password_hash, password)
        if ok and password_needs_rehash(self.password_hash):
            self.set_password(password)
        return ok

    def rotate_session_token(self) -> str:
        self.session_token = secrets.token_urlsafe(32)
        return self.session_token

    def touch_login(self) -> None:
        self.last_login_at = utcnow()

    @property
    def file_count(self) -> int:
        return len(self.files)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<User {self.id} {self.username!r}>"


class StoredFile(db.Model):
    __tablename__ = "stored_files"

    id = db.Column(db.Integer, primary_key=True)
    # Cryptographically random internal identifier.  Used in cloud object
    # names and as the AES-GCM additional-authenticated-data binding, so the
    # object name never reveals the original filename.
    public_id = db.Column(db.String(64), nullable=False, unique=True, index=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)

    original_filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.BigInteger, nullable=False, default=0)
    mime_type = db.Column(db.String(255), nullable=False, default="application/octet-stream")
    block_size = db.Column(db.Integer, nullable=False)
    block_count = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(16), nullable=False, default=STATUS_PENDING, index=True)
    plaintext_sha256 = db.Column(db.String(64), nullable=True)
    storage_backend = db.Column(db.String(32), nullable=False, default="local")
    last_error = db.Column(db.String(500), nullable=True)
    cleanup_pending = db.Column(db.Boolean, nullable=False, default=False)

    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    completed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    deleted_at = db.Column(db.DateTime(timezone=True), nullable=True)

    owner = relationship("User", back_populates="files")
    blocks = relationship(
        "EncryptedBlock",
        back_populates="file",
        cascade="all, delete-orphan",
        order_by="EncryptedBlock.block_index",
        passive_deletes=True,
    )
    wrapped_key = relationship(
        "WrappedKey",
        back_populates="file",
        uselist=False,
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    operations = relationship(
        "StorageOperation",
        back_populates="file",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    __table_args__ = (
        CheckConstraint(
            "status in ('pending','uploading','complete','failed','deleting','deleted')",
            name="ck_stored_files_status",
        ),
        CheckConstraint("block_size > 0", name="ck_stored_files_block_size"),
        CheckConstraint("block_count >= 0", name="ck_stored_files_block_count"),
        CheckConstraint("file_size >= 0", name="ck_stored_files_size"),
    )

    # --- helpers ----------------------------------------------------------
    @property
    def is_complete(self) -> bool:
        return self.status == STATUS_COMPLETE

    @property
    def is_downloadable(self) -> bool:
        return self.status in DOWNLOADABLE_STATUSES

    @property
    def is_deleted(self) -> bool:
        return self.status == STATUS_DELETED

    @property
    def pending_cleanup(self) -> bool:
        return bool(self.cleanup_pending) or self.status in (STATUS_FAILED, STATUS_DELETING)

    @property
    def stored_block_count(self) -> int:
        return len(self.blocks)

    @property
    def encrypted_bytes(self) -> int:
        return sum(b.encrypted_size or 0 for b in self.blocks)

    def is_owned_by(self, user) -> bool:
        return bool(user) and getattr(user, "id", None) == self.owner_id

    def status_label(self) -> str:
        return {
            STATUS_PENDING: "Pending",
            STATUS_UPLOADING: "Uploading",
            STATUS_COMPLETE: "Stored",
            STATUS_FAILED: "Failed",
            STATUS_DELETING: "Deleting",
            STATUS_DELETED: "Deleted",
        }.get(self.status, self.status.title())

    def status_css(self) -> str:
        return {
            STATUS_PENDING: "badge-warn",
            STATUS_UPLOADING: "badge-info",
            STATUS_COMPLETE: "badge-ok",
            STATUS_FAILED: "badge-danger",
            STATUS_DELETING: "badge-warn",
            STATUS_DELETED: "badge-muted",
        }.get(self.status, "badge-muted")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<StoredFile {self.id} {self.public_id[:8]} {self.status}>"


class EncryptedBlock(db.Model):
    __tablename__ = "encrypted_blocks"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("stored_files.id", ondelete="CASCADE"), nullable=False, index=True)
    block_index = db.Column(db.Integer, nullable=False)
    object_key = db.Column(db.String(512), nullable=False, unique=True)
    encrypted_size = db.Column(db.Integer, nullable=False)
    plaintext_size = db.Column(db.Integer, nullable=False)
    nonce = db.Column(db.LargeBinary(12), nullable=False)
    format_version = db.Column(db.Integer, nullable=False, default=1)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)

    file = relationship("StoredFile", back_populates="blocks")

    __table_args__ = (
        UniqueConstraint("file_id", "block_index", name="uq_encrypted_blocks_file_index"),
        CheckConstraint("block_index >= 0", name="ck_blocks_index"),
        CheckConstraint("encrypted_size >= 0", name="ck_blocks_encrypted_size"),
        CheckConstraint("plaintext_size >= 0", name="ck_blocks_plaintext_size"),
        Index("ix_encrypted_blocks_file_index", "file_id", "block_index"),
    )

    @property
    def nonce_hex(self) -> str:
        return self.nonce.hex() if self.nonce else ""

    @property
    def overhead_bytes(self) -> int:
        return max((self.encrypted_size or 0) - (self.plaintext_size or 0), 0)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<EncryptedBlock file={self.file_id} index={self.block_index}>"


class WrappedKey(db.Model):
    """Envelope-encryption record: the per-file DEK, wrapped by the KEK.

    Only ciphertext is stored.  The keystream used for unwrapping (the KEK)
    lives exclusively in the ``SECURECLOUD_KEY_ENCRYPTION_KEY`` environment
    variable / secret manager.
    """

    __tablename__ = "wrapped_keys"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(
        db.Integer,
        db.ForeignKey("stored_files.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    wrapped_dek = db.Column(db.LargeBinary, nullable=False)
    wrap_nonce = db.Column(db.LargeBinary(12), nullable=False)
    wrap_format_version = db.Column(db.Integer, nullable=False, default=1)
    kek_fingerprint = db.Column(db.String(64), nullable=False)
    key_size_bits = db.Column(db.Integer, nullable=False, default=256)
    algorithm = db.Column(db.String(64), nullable=False, default="AES-256-GCM")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    rotated_at = db.Column(db.DateTime(timezone=True), nullable=True)

    file = relationship("StoredFile", back_populates="wrapped_key")

    @property
    def wrap_nonce_hex(self) -> str:
        return self.wrap_nonce.hex() if self.wrap_nonce else ""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<WrappedKey file={self.file_id} kek={self.kek_fingerprint[:8]}>"


class StorageOperation(db.Model):
    """Audit / recovery record for storage work against object storage."""

    __tablename__ = "storage_operations"

    id = db.Column(db.String(40), primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("stored_files.id", ondelete="CASCADE"), nullable=True, index=True)
    operation_type = db.Column(db.String(16), nullable=False, index=True)
    status = db.Column(db.String(16), nullable=False, default="pending", index=True)
    error_category = db.Column(db.String(32), nullable=True)
    error_detail = db.Column(db.String(500), nullable=True)
    storage_backend = db.Column(db.String(32), nullable=False, default="local")
    objects_total = db.Column(db.Integer, nullable=False, default=0)
    objects_done = db.Column(db.Integer, nullable=False, default=0)
    bytes_processed = db.Column(db.BigInteger, nullable=False, default=0)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    finished_at = db.Column(db.DateTime(timezone=True), nullable=True)

    file = relationship("StoredFile", back_populates="operations")

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<StorageOperation {self.operation_type} {self.status}>"


class CleanupJob(db.Model):
    """Recoverable cleanup work for objects that could not be deleted inline."""

    __tablename__ = "cleanup_jobs"

    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(db.Integer, db.ForeignKey("stored_files.id", ondelete="CASCADE"), nullable=True, index=True)
    public_id = db.Column(db.String(64), nullable=True)
    reason = db.Column(db.String(120), nullable=False, default="cleanup")
    status = db.Column(db.String(16), nullable=False, default=CLEANUP_PENDING, index=True)
    object_keys = db.Column(db.JSON, nullable=False, default=list)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    last_error = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)

    @property
    def key_count(self) -> int:
        return len(self.object_keys or [])

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<CleanupJob {self.id} {self.status} keys={self.key_count}>"
