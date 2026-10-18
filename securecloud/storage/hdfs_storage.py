"""HDFS distributed object-storage adapter (WebHDFS REST API).

Connects to a Hadoop Distributed File System cluster through the WebHDFS REST
interface using the ``hdfs`` Python library (``InsecureClient``).  Encrypted
blocks are stored as regular HDFS files under a configurable root path.

Errors are translated into specific exceptions so the application can react
(missing object, access denied, timeout, provider failure) instead of
collapsing everything into a generic error.  There is no fallback to local
storage: a failed HDFS operation is reported as a failure.
"""
from __future__ import annotations

import hashlib
import posixpath
import time
import uuid

from hdfs import InsecureClient
from hdfs.util import HdfsError

from securecloud.storage.base import (
    ObjectStorage,
    StorageAccessDeniedError,
    StorageConfigurationError,
    StorageDescription,
    StorageIntegrityError,
    StorageNotConfiguredError,
    StorageObjectNotFoundError,
    StorageProviderError,
    StorageTimeoutError,
    StorageUnavailableError,
)

REQUIRED_SETTINGS = (
    "HDFS_NAMENODE_URL",
    "HDFS_USER",
    "HDFS_ROOT_PATH",
)

# Known HDFS/WebHDFS error fragments for classification.
_NOT_FOUND_FRAGMENTS = ("FileNotFoundException", "does not exist", "File not found")
_ACCESS_DENIED_FRAGMENTS = ("AccessControlException", "Permission denied", "not allowed")
_STANDBY_FRAGMENTS = ("StandbyException", "is not active")


class HDFSObjectStorage(ObjectStorage):
    """HDFS backend accessed through WebHDFS REST API."""

    backend_name = "hdfs"
    display_name = "HDFS Distributed Storage"
    is_local = False

    def __init__(
        self,
        *,
        namenode_url: str = "",
        hdfs_user: str = "",
        root_path: str = "",
        prefix: str = "",
        timeout: int = 30,
        source_map: dict | None = None,
    ):
        self.namenode_url = (namenode_url or "").strip().rstrip("/")
        self.hdfs_user = (hdfs_user or "").strip()
        self.root_path = (root_path or "").strip().rstrip("/") or "/"
        self.prefix = (prefix or "").strip("/")
        self.timeout = max(int(timeout or 30), 1)
        self.source_map = dict(source_map or {})
        self._client: InsecureClient | None = None

        missing = [name for name in REQUIRED_SETTINGS if not self._value_for(name)]
        self.missing_settings = tuple(missing)
        self._configured = not missing

    # --- configuration ----------------------------------------------------
    def _value_for(self, setting: str) -> str:
        mapping = {
            "HDFS_NAMENODE_URL": self.namenode_url,
            "HDFS_USER": self.hdfs_user,
            "HDFS_ROOT_PATH": self.root_path if self.root_path != "/" else "",
        }
        return mapping.get(setting, "")

    @classmethod
    def from_config(cls, config) -> "HDFSObjectStorage":
        """Build the adapter from an application config mapping.

        ``HDFS_*`` variables are read from the configuration dict.
        """
        return cls(
            namenode_url=(config.get("HDFS_NAMENODE_URL") or "").strip(),
            hdfs_user=(config.get("HDFS_USER") or "").strip(),
            root_path=(config.get("HDFS_ROOT_PATH") or "").strip(),
            prefix=(
                config.get("STORAGE_PREFIX")
                or config.get("SECURECLOUD_OBJECT_PREFIX")
                or ""
            ),
            timeout=config.get("STORAGE_TIMEOUT_SECONDS", 30),
        )

    # --- description ------------------------------------------------------
    def describe(self) -> StorageDescription:
        notes: list[str] = [
            "WebHDFS REST API backend.",
            "Encrypted blocks only: plaintext is never uploaded.",
        ]
        if not self._configured:
            notes.append(
                "Configuration incomplete - HDFS operations are disabled. "
                "SecureCloud will not fall back to local storage."
            )
        location = f"hdfs://{self.namenode_url or '(not set)'}{self.root_path}"
        if self.prefix:
            location = f"{location}/{self.prefix}"
        return StorageDescription(
            backend=self.backend_name,
            display_name=self.display_name,
            is_local=False,
            configured=self._configured,
            bucket="(hdfs)",
            endpoint=self.namenode_url or "(not set)",
            region="hadoop",
            addressing_style="webhdfs",
            prefix=self.prefix,
            location=location,
            missing_settings=self.missing_settings,
            notes=tuple(notes),
            extras={
                "hdfs_user": self.hdfs_user or "(not set)",
                "root_path": self.root_path,
            },
        )

    # --- client -----------------------------------------------------------
    def _require_configured(self) -> None:
        if not self._configured:
            raise StorageNotConfiguredError(
                "HDFS storage is not fully configured. Missing settings: "
                + ", ".join(self.missing_settings)
                + ". Set them in your environment (.env) - SecureCloud does not fall "
                  "back to local storage.",
                detail="missing: " + ",".join(self.missing_settings),
            )

    def client(self) -> InsecureClient:
        """Return the cached ``InsecureClient``, creating one on first call."""
        self._require_configured()
        if self._client is None:
            self._client = InsecureClient(
                self.namenode_url,
                user=self.hdfs_user,
                timeout=self.timeout,
            )
        return self._client

    def reset_client(self) -> None:
        """Drop the cached WebHDFS client so the next call creates a fresh one."""
        self._client = None

    # --- error translation ------------------------------------------------
    def _translate(self, exc: Exception, key: str = "") -> Exception:
        """Map HDFS / network exceptions to storage-layer exceptions."""
        msg = str(exc)

        if isinstance(exc, HdfsError):
            if any(frag in msg for frag in _NOT_FOUND_FRAGMENTS):
                return StorageObjectNotFoundError(key, detail=msg)
            if any(frag in msg for frag in _ACCESS_DENIED_FRAGMENTS):
                return StorageAccessDeniedError(
                    "HDFS refused the operation (access denied). "
                    "Check HDFS user permissions.",
                    detail=msg,
                )
            if any(frag in msg for frag in _STANDBY_FRAGMENTS):
                return StorageUnavailableError(
                    "The HDFS NameNode is in standby mode. "
                    "Ensure the active NameNode URL is configured.",
                    detail=msg,
                )
            return StorageProviderError(
                "HDFS returned an error for this operation.",
                detail=msg,
            )

        if isinstance(exc, ConnectionError):
            return StorageUnavailableError(
                "HDFS NameNode could not be reached. Check the URL and network.",
                detail=type(exc).__name__,
            )

        if isinstance(exc, TimeoutError):
            return StorageTimeoutError(
                "HDFS did not respond in time. Please try again.",
                detail=type(exc).__name__,
            )

        # requests.exceptions live under ConnectionError / Timeout in the
        # stdlib hierarchy, but we also catch them by name for safety.
        try:
            import requests.exceptions as reqexc

            if isinstance(exc, reqexc.ConnectionError):
                return StorageUnavailableError(
                    "HDFS NameNode could not be reached. Check the URL and network.",
                    detail=type(exc).__name__,
                )
            if isinstance(exc, (reqexc.Timeout, reqexc.ReadTimeout, reqexc.ConnectTimeout)):
                return StorageTimeoutError(
                    "HDFS did not respond in time. Please try again.",
                    detail=type(exc).__name__,
                )
        except ImportError:
            pass

        if isinstance(exc, OSError):
            return StorageUnavailableError(
                "An OS-level error occurred during HDFS operation.",
                detail=str(exc),
            )

        return exc

    # --- path helpers -----------------------------------------------------
    def _full_hdfs_path(self, key: str) -> str:
        """Build the absolute HDFS path for *key*.

        Structure: ``<root_path>/<prefix>/<key>``
        """
        clean = (key or "").strip("/")
        if not clean:
            raise StorageConfigurationError("An object key is required.")
        parts = [self.root_path]
        if self.prefix:
            parts.append(self.prefix)
        parts.append(clean)
        return posixpath.join(*parts)

    def _base_dir(self) -> str:
        """Return the HDFS directory that contains all objects for this adapter."""
        if self.prefix:
            return posixpath.join(self.root_path, self.prefix)
        return self.root_path

    def strip_prefix(self, key: str) -> str:
        """Remove the configured prefix from a fully-qualified key."""
        full_prefix = self._base_dir().rstrip("/") + "/"
        if key.startswith(full_prefix):
            return key[len(full_prefix):]
        return key

    # --- operations -------------------------------------------------------
    def health_check(self) -> dict:
        if not self._configured:
            return {
                "ok": False,
                "message": "HDFS storage is not configured. Missing: "
                           + ", ".join(self.missing_settings),
                "details": {"missing_settings": list(self.missing_settings)},
            }
        probe_name = f".healthcheck-{uuid.uuid4().hex[:8]}"
        probe_path = posixpath.join(self._base_dir(), probe_name)
        probe_data = f"securecloud-probe-{time.time()}".encode()
        try:
            hdfs = self.client()

            # Write probe
            with hdfs.write(probe_path, overwrite=True) as writer:
                writer.write(probe_data)

            # Read probe back
            with hdfs.read(probe_path) as reader:
                read_back = reader.read()

            if read_back != probe_data:
                return {
                    "ok": False,
                    "message": "HDFS probe data mismatch - data integrity issue.",
                    "details": {"probe_path": probe_path},
                }

            # Delete probe
            hdfs.delete(probe_path)

            return {
                "ok": True,
                "message": f"Connected to HDFS at '{self.namenode_url}'.",
                "details": {
                    "namenode_url": self.namenode_url,
                    "hdfs_user": self.hdfs_user,
                    "root_path": self.root_path,
                    "prefix": self.prefix,
                    "probe_bytes": len(probe_data),
                    "backend": self.backend_name,
                },
            }
        except Exception as exc:
            translated = self._translate(exc)
            return {
                "ok": False,
                "message": getattr(translated, "public_message", "HDFS health check failed."),
                "details": {"category": getattr(translated, "category", "unknown")},
            }

    def upload_object(
        self,
        key: str,
        data: bytes,
        *,
        content_type: str = "application/octet-stream",
        metadata: dict | None = None,
    ) -> dict:
        self._require_configured()
        hdfs_path = self._full_hdfs_path(key)

        try:
            hdfs = self.client()

            # Ensure the parent directory exists.
            parent = posixpath.dirname(hdfs_path)
            hdfs.makedirs(parent)

            # Write data.
            with hdfs.write(hdfs_path, overwrite=True) as writer:
                writer.write(data)

            # Verify stored size.
            status = hdfs.status(hdfs_path)
            stored_size = status.get("length", 0)
        except Exception as exc:
            raise self._translate(exc, key=key) from exc

        if stored_size != len(data):
            raise StorageIntegrityError(
                "The stored object size does not match the uploaded size.",
                detail=f"key={key} expected={len(data)} stored={stored_size}",
            )

        # Compute a deterministic etag from the data.
        etag = hashlib.md5(data).hexdigest()  # noqa: S324

        return {
            "key": key,
            "size": stored_size,
            "etag": etag,
        }

    def download_object(self, key: str) -> bytes:
        self._require_configured()
        hdfs_path = self._full_hdfs_path(key)
        try:
            hdfs = self.client()
            with hdfs.read(hdfs_path) as reader:
                return reader.read()
        except Exception as exc:
            translated = self._translate(exc, key=key)
            raise translated from exc

    def delete_object(self, key: str) -> bool:
        self._require_configured()
        hdfs_path = self._full_hdfs_path(key)
        try:
            hdfs = self.client()
            # Check existence first; hdfs.delete returns True even for
            # non-existent paths in some implementations.
            status = hdfs.status(hdfs_path, strict=False)
            if status is None:
                return False
            return hdfs.delete(hdfs_path, recursive=False)
        except Exception as exc:
            translated = self._translate(exc, key=key)
            # If the file was already gone treat it as "nothing deleted".
            if isinstance(translated, StorageObjectNotFoundError):
                return False
            raise translated from exc

    def object_info(self, key: str) -> dict:
        self._require_configured()
        hdfs_path = self._full_hdfs_path(key)
        try:
            hdfs = self.client()
            status = hdfs.status(hdfs_path, strict=False)
        except Exception as exc:
            translated = self._translate(exc, key=key)
            if isinstance(translated, StorageObjectNotFoundError):
                return {"exists": False, "size": None, "etag": None}
            raise translated from exc

        if status is None:
            return {"exists": False, "size": None, "etag": None}

        size = status.get("length", 0)
        return {
            "exists": True,
            "size": size,
            "etag": f"hdfs-{size}-{status.get('modificationTime', 0)}",
        }

    def list_objects(self, prefix: str = "", limit: int = 1000) -> list[str]:
        self._require_configured()

        if prefix:
            search_dir = self._full_hdfs_path(prefix)
            # prefix may point to a directory or a key-prefix; determine which.
            # If the exact path doesn't exist as a directory, fall back to
            # listing the parent and filtering by the basename prefix.
            try:
                status = self.client().status(search_dir, strict=False)
            except Exception:
                status = None

            if status is not None and status.get("type") == "DIRECTORY":
                return self._walk_directory(search_dir, limit)

            # Not a directory – treat *prefix* as a filename prefix inside its
            # parent directory.
            parent = posixpath.dirname(search_dir)
            basename_prefix = posixpath.basename(search_dir)
            return self._walk_directory(parent, limit, basename_prefix=basename_prefix)

        return self._walk_directory(self._base_dir(), limit)

    def _walk_directory(
        self,
        directory: str,
        limit: int,
        basename_prefix: str = "",
    ) -> list[str]:
        """Recursively list file keys under *directory*, stripping the root."""
        keys: list[str] = []
        try:
            hdfs = self.client()
            entries = hdfs.walk(directory)
        except Exception as exc:
            translated = self._translate(exc)
            if isinstance(translated, StorageObjectNotFoundError):
                return keys
            raise translated from exc

        base_dir = self._base_dir().rstrip("/") + "/"

        try:
            for dirpath, _dirnames, filenames in entries:
                for name in sorted(filenames):
                    if basename_prefix and not name.startswith(basename_prefix):
                        continue
                    full = posixpath.join(dirpath, name)
                    # Return keys relative to the base dir.
                    if full.startswith(base_dir):
                        rel = full[len(base_dir):]
                    else:
                        rel = full
                    keys.append(rel)
                    if len(keys) >= limit:
                        return keys
        except Exception as exc:
            translated = self._translate(exc)
            if isinstance(translated, StorageObjectNotFoundError):
                return keys
            raise translated from exc

        return keys

    # --- maintenance ------------------------------------------------------
    def reset_for_tests(self) -> None:
        """Test helper: remove all objects under the configured root/prefix."""
        self._require_configured()
        target = self._base_dir()
        try:
            hdfs = self.client()
            status = hdfs.status(target, strict=False)
            if status is None:
                return
            # Delete contents (but preserve the directory itself).
            listing = hdfs.list(target, status=False)
            for name in listing:
                child = posixpath.join(target, name)
                hdfs.delete(child, recursive=True)
        except Exception as exc:
            raise self._translate(exc) from exc
