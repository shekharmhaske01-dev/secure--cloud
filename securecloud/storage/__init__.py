"""Storage backend factory and registry.

The active backend is chosen by ``SECURECLOUD_STORAGE_BACKEND`` (``local`` or
``s3``).  Selection is explicit: when ``s3`` is configured but incomplete, the
application reports a configuration problem and cloud operations raise - it
never silently degrades to the local filesystem adapter.
"""
from __future__ import annotations

from flask import current_app

from securecloud.services import ConfigurationError
from securecloud.storage.base import (  # noqa: F401  (re-exported for convenience)
    ObjectStorage,
    StorageAccessDeniedError,
    StorageAuthenticationError,
    StorageConfigurationError,
    StorageDescription,
    StorageError,
    StorageIntegrityError,
    StorageNotConfiguredError,
    StorageObjectNotFoundError,
    StorageProviderError,
    StorageTimeoutError,
    StorageUnavailableError,
)
from securecloud.storage.local_storage import LocalObjectStorage
from securecloud.storage.s3_storage import S3ObjectStorage
from securecloud.storage.hdfs_storage import HDFSObjectStorage

LOCAL_BACKENDS = {"local", "filesystem", "dev", "development"}
CLOUD_BACKENDS = {"s3", "neon", "neon-s3", "neon_s3", "object", "objectstorage"}
HDFS_BACKENDS = {"hdfs", "hadoop", "webhdfs"}

__all__ = [
    "CLOUD_BACKENDS",
    "HDFS_BACKENDS",
    "HDFSObjectStorage",
    "LOCAL_BACKENDS",
    "LocalObjectStorage",
    "ObjectStorage",
    "S3ObjectStorage",
    "StorageAccessDeniedError",
    "StorageAuthenticationError",
    "StorageConfigurationError",
    "StorageDescription",
    "StorageError",
    "StorageIntegrityError",
    "StorageNotConfiguredError",
    "StorageObjectNotFoundError",
    "StorageProviderError",
    "StorageTimeoutError",
    "StorageUnavailableError",
    "create_storage",
    "get_storage",
]


def create_storage(config) -> ObjectStorage:
    """Instantiate the configured storage backend.

    Builds an adapter even when its settings are incomplete (the adapter
    reports ``configured=False``) so that the Settings page can display an
    accurate configuration status instead of the application failing to boot.
    """
    backend = str(config.get("STORAGE_BACKEND") or "local").strip().lower()
    prefix = config.get("STORAGE_PREFIX") or config.get("SECURECLOUD_OBJECT_PREFIX") or ""

    if backend in LOCAL_BACKENDS:
        return LocalObjectStorage(root=config.get("LOCAL_STORAGE_DIR") or "", prefix=prefix)
    if backend in CLOUD_BACKENDS:
        return S3ObjectStorage.from_config(config)
    if backend in HDFS_BACKENDS:
        return HDFSObjectStorage.from_config(config)
    raise ConfigurationError(
        "Unknown SECURECLOUD_STORAGE_BACKEND value. Use 'local', 's3', or 'hdfs'.",
        detail=f"configured={backend!r}",
    )


def get_storage() -> ObjectStorage:
    """Return the storage adapter bound to the current application."""
    storage = current_app.extensions.get("securecloud_storage")
    if storage is None:
        # Defensive: build on demand (e.g. inside scripts using an app context).
        storage = create_storage(current_app.config)
        current_app.extensions["securecloud_storage"] = storage
    return storage
