"""Development-only local object-storage adapter.

This adapter stores encrypted blocks as files in a local directory so the whole
upload -> chunk -> encrypt -> store -> download -> decrypt pipeline can be
exercised without cloud credentials.

It is explicitly **not** cloud object storage and the application always
reports it as local development storage (see ``STORAGE_BACKEND=local``).
The application never silently switches to it when a cloud operation fails.
"""
from __future__ import annotations

import os
import shutil
import tempfile

from securecloud.services import FileIntegrityError
from securecloud.storage.base import (
    ObjectStorage,
    StorageConfigurationError,
    StorageIntegrityError,
    StorageObjectNotFoundError,
    StorageUnavailableError,
    StorageDescription,
)

MARKER_FILENAME = ".securecloud-local-storage"
MARKER_TEXT = (
    "SecureCloud local development object storage.\n"
    "This directory is NOT cloud object storage. Files here are encrypted\n"
    "AES-256-GCM blocks used for local development and testing only.\n"
)


class LocalObjectStorage(ObjectStorage):
    backend_name = "local"
    display_name = "Local development storage"
    is_local = True

    def __init__(self, root: str, prefix: str = ""):
        if not root:
            raise StorageConfigurationError(
                "SECURECLOUD_LOCAL_STORAGE_DIR is not configured.",
                detail="local storage root missing",
            )
        self.root = os.path.abspath(root)
        self.prefix = (prefix or "").strip("/")
        os.makedirs(self.root, exist_ok=True)
        marker = os.path.join(self.root, MARKER_FILENAME)
        if not os.path.exists(marker):
            with open(marker, "w", encoding="utf-8") as handle:
                handle.write(MARKER_TEXT)

    # --- description ------------------------------------------------------
    def describe(self) -> StorageDescription:
        return StorageDescription(
            backend=self.backend_name,
            display_name=self.display_name,
            is_local=True,
            configured=True,
            bucket="(filesystem)",
            endpoint=self.root,
            region="local",
            addressing_style="filesystem",
            prefix=self.prefix,
            location=self.root,
            notes=(
                "Development/test only - not cloud object storage.",
                "Records the same encrypted-block objects the S3 backend would store.",
            ),
        )

    def health_check(self) -> dict:
        try:
            probe = os.path.join(self.root, ".healthcheck")
            with open(probe, "wb") as handle:
                handle.write(b"securecloud")
            size = os.path.getsize(probe)
            os.remove(probe)
        except OSError as exc:
            return {"ok": False, "message": "Local storage directory is not writable.", "details": {"error": str(exc)}}
        return {
            "ok": True,
            "message": "Local development storage is writable.",
            "details": {"path": self.root, "probe_bytes": size, "backend": self.backend_name},
        }

    # --- internal helpers -------------------------------------------------
    def _resolve(self, key: str) -> str:
        safe = self._sanitize_key(key)
        path = os.path.join(self.root, safe.replace("/", os.sep))
        real_root = os.path.realpath(self.root)
        real_path = os.path.realpath(os.path.dirname(path))
        if not (real_path == real_root or real_path.startswith(real_root + os.sep)):
            raise StorageConfigurationError(
                "Refusing to use an object key outside the local storage root.",
                detail=f"key={key}",
            )
        return path

    @staticmethod
    def _sanitize_key(key: str) -> str:
        if not key or not str(key).strip():
            raise StorageConfigurationError("An object key is required.")
        value = str(key).replace("\\", "/").strip("/")
        parts = [p for p in value.split("/") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            raise StorageConfigurationError(
                "Invalid object key: path traversal is not permitted.",
                detail=f"key={key}",
            )
        return "/".join(parts)

    # --- objects ----------------------------------------------------------
    def upload_object(self, key: str, data: bytes, *, content_type: str = "application/octet-stream",
                      metadata: dict | None = None) -> dict:
        path = self._resolve(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".upload-")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, path)
        except OSError as exc:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            raise StorageUnavailableError(
                "The local storage directory could not be written.",
                detail=str(exc),
            ) from exc
        stored = os.path.getsize(path)
        if stored != len(data):
            raise StorageIntegrityError(
                "The stored object size does not match the uploaded size.",
                detail=f"key={key} expected={len(data)} stored={stored}",
            )
        return {"key": key, "size": stored, "etag": f"local-{stored}-{abs(hash(path)) & 0xFFFFFFFF:08x}"}

    def download_object(self, key: str) -> bytes:
        path = self._resolve(key)
        if not os.path.isfile(path):
            raise StorageObjectNotFoundError(key)
        try:
            with open(path, "rb") as handle:
                return handle.read()
        except OSError as exc:
            raise StorageUnavailableError(
                "The encrypted block could not be read from local storage.",
                detail=str(exc),
            ) from exc

    def delete_object(self, key: str) -> bool:
        path = self._resolve(key)
        if not os.path.isfile(path):
            return False
        try:
            os.remove(path)
        except OSError as exc:
            raise StorageUnavailableError(
                "The encrypted block could not be deleted from local storage.",
                detail=str(exc),
            ) from exc
        # Remove now-empty directories so cleanup leaves no residue.
        directory = os.path.dirname(path)
        try:
            if directory != self.root and not os.listdir(directory):
                os.rmdir(directory)
        except OSError:
            pass
        return True

    def object_info(self, key: str) -> dict:
        path = self._resolve(key)
        if not os.path.isfile(path):
            return {"exists": False, "size": None, "etag": None}
        stat = os.stat(path)
        return {"exists": True, "size": stat.st_size, "etag": f"local-{stat.st_size}"}

    def list_objects(self, prefix: str = "", limit: int = 1000) -> list[str]:
        base = self._sanitize_key(prefix) if prefix else ""
        results: list[str] = []
        search_root = os.path.join(self.root, base.replace("/", os.sep)) if base else self.root
        if not os.path.isdir(search_root):
            return results
        for dirpath, _dirnames, filenames in os.walk(search_root):
            for name in sorted(filenames):
                if name in (MARKER_FILENAME,) or name.startswith(".upload-"):
                    continue
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, self.root).replace(os.sep, "/")
                if base and not rel.startswith(base):
                    continue
                results.append(rel)
                if len(results) >= limit:
                    return results
        return results

    # --- maintenance ------------------------------------------------------
    def storage_usage_bytes(self) -> int:
        total = 0
        for dirpath, _dirnames, filenames in os.walk(self.root):
            for name in filenames:
                if name == MARKER_FILENAME:
                    continue
                try:
                    total += os.path.getsize(os.path.join(dirpath, name))
                except OSError:
                    continue
        return total

    def reset_for_tests(self) -> None:
        """Test helper: clear the local storage directory."""
        if not self.root or os.path.realpath(self.root) in ("/", os.path.expanduser("~")):
            raise StorageConfigurationError("Refusing to clear an unsafe local storage path.")
        for entry in os.listdir(self.root):
            target = os.path.join(self.root, entry)
            if os.path.isdir(target):
                shutil.rmtree(target, ignore_errors=True)
            else:
                try:
                    os.remove(target)
                except OSError:
                    pass


def ensure_integrity(condition: bool, message: str, detail: str = "") -> None:
    if not condition:
        raise FileIntegrityError(message, detail=detail)
