"""Object-storage abstractions.

Every adapter exposes the same small interface so the application never knows
(or cares) whether encrypted blocks live on a development filesystem or in
S3-compatible cloud object storage.  No adapter ever falls back to a different
backend: a failure is raised and reported, never hidden.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from securecloud.services import (
    CATEGORY_ACCESS_DENIED,
    CATEGORY_AUTHENTICATION,
    CATEGORY_CONFIGURATION,
    CATEGORY_INTEGRITY,
    CATEGORY_NETWORK,
    CATEGORY_NOT_FOUND,
    CATEGORY_PROVIDER,
    CATEGORY_STORAGE,
    CATEGORY_TIMEOUT,
    CATEGORY_UNKNOWN,
    SecureCloudError,
)


class StorageError(SecureCloudError):
    """Base class for object-storage failures."""

    category = CATEGORY_STORAGE
    http_status = 502


class StorageConfigurationError(StorageError):
    category = CATEGORY_CONFIGURATION
    http_status = 503


class StorageNotConfiguredError(StorageConfigurationError):
    """Raised when credentials/settings required by the backend are absent."""


class StorageAuthenticationError(StorageError):
    category = CATEGORY_AUTHENTICATION
    http_status = 502


class StorageAccessDeniedError(StorageError):
    category = CATEGORY_ACCESS_DENIED
    http_status = 502


class StorageObjectNotFoundError(StorageError):
    category = CATEGORY_NOT_FOUND
    http_status = 404

    def __init__(self, key: str = "", detail: str = ""):
        super().__init__(
            "A required encrypted block is missing from object storage.",
            detail=detail or f"missing object: {key}",
        )
        self.object_key = key


class StorageTimeoutError(StorageError):
    category = CATEGORY_TIMEOUT
    http_status = 504


class StorageUnavailableError(StorageError):
    category = CATEGORY_NETWORK
    http_status = 503


class StorageProviderError(StorageError):
    category = CATEGORY_PROVIDER
    http_status = 502


class StorageIntegrityError(StorageError):
    category = CATEGORY_INTEGRITY
    http_status = 502


@dataclass(frozen=True)
class StorageDescription:
    """Non-secret description of the active object-storage backend."""

    backend: str
    display_name: str
    is_local: bool
    configured: bool
    bucket: str = ""
    endpoint: str = ""
    region: str = ""
    addressing_style: str = ""
    prefix: str = ""
    location: str = ""
    missing_settings: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    extras: dict = field(default_factory=dict)

    @property
    def kind_label(self) -> str:
        return "Local development storage" if self.is_local else "Cloud object storage"

    def as_dict(self) -> dict:
        return {
            "backend": self.backend,
            "display_name": self.display_name,
            "is_local": self.is_local,
            "kind_label": self.kind_label,
            "configured": self.configured,
            "bucket": self.bucket,
            "endpoint": self.endpoint,
            "region": self.region,
            "addressing_style": self.addressing_style,
            "prefix": self.prefix,
            "location": self.location,
            "missing_settings": list(self.missing_settings),
            "notes": list(self.notes),
            "extras": dict(self.extras),
        }


class ObjectStorage(ABC):
    """Interface implemented by every storage backend."""

    backend_name = "unknown"
    display_name = "Object storage"
    is_local = False

    # --- description ------------------------------------------------------
    @abstractmethod
    def describe(self) -> StorageDescription:
        """Return a non-secret description of this backend's configuration."""

    @abstractmethod
    def health_check(self) -> dict:
        """Verify connectivity. Returns ``{ok, message, details}``."""

    # --- objects ----------------------------------------------------------
    @abstractmethod
    def upload_object(self, key: str, data: bytes, *, content_type: str = "application/octet-stream",
                      metadata: dict | None = None) -> dict:
        """Store *data* under *key*; returns ``{key, etag, size}``."""

    @abstractmethod
    def download_object(self, key: str) -> bytes:
        """Return the stored bytes for *key*; raises when absent."""

    @abstractmethod
    def delete_object(self, key: str) -> bool:
        """Delete *key*. Returns True when an object was removed, False when absent."""

    @abstractmethod
    def object_info(self, key: str) -> dict:
        """Return ``{exists, size, etag}`` without downloading the object."""

    @abstractmethod
    def list_objects(self, prefix: str = "", limit: int = 1000) -> list[str]:
        """List object keys under *prefix*."""

    # --- convenience ------------------------------------------------------
    def object_exists(self, key: str) -> bool:
        try:
            return bool(self.object_info(key).get("exists"))
        except StorageError:
            raise
        except Exception:
            return False

    def configuration_ok(self) -> bool:
        return self.describe().configured

    @staticmethod
    def categorize(exc: Exception) -> str:
        if isinstance(exc, SecureCloudError):
            return exc.category
        return CATEGORY_UNKNOWN
