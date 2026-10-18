"""Small shared helpers (filenames, formatting, error sanitising)."""
from __future__ import annotations

import os
import re
import unicodedata

UNSAFE_FILENAME_CHARS = re.compile(r'[\x00-\x1f\x7f/\\:*?"<>|]+')
COLLAPSE_WHITESPACE = re.compile(r"\s+")
WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
}


def sanitize_filename(name: str | None, max_length: int = 255, fallback: str = "download.bin") -> str:
    """Return a display-safe filename.

    The result is used only for display and for the ``Content-Disposition``
    header of a download; it is never used as a filesystem path or as a cloud
    object key.  Unicode letters are preserved, path separators and control
    characters are removed, and traversal sequences cannot survive.
    """
    if not name:
        return fallback
    value = unicodedata.normalize("NFKC", str(name))
    value = value.replace("\u2044", "_").replace("\u2215", "_")
    # Strip any directory component supplied by a client.
    value = value.replace("\\", "/").split("/")[-1]
    value = UNSAFE_FILENAME_CHARS.sub("_", value)
    value = COLLAPSE_WHITESPACE.sub(" ", value).strip().strip(".")
    if not value:
        return fallback
    stem, ext = os.path.splitext(value)
    if stem.lower() in WINDOWS_RESERVED:
        stem = f"{stem}_file"
    if len(value) > max_length:
        keep = max(max_length - len(ext), 1)
        value = f"{stem[:keep]}{ext}"
    return value or fallback


def human_size(num_bytes: int | None) -> str:
    """Format a byte count for display."""
    if num_bytes is None:
        return "-"
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"


def short_hash(value: str | None, length: int = 12) -> str:
    if not value:
        return "-"
    return value[:length]


def redact(text: str | None, limit: int = 300) -> str:
    """Best-effort sanitising of unexpected exception text.

    Removes absolute filesystem paths, URLs with credentials and anything
    resembling a long base64 secret so that operator-facing strings never leak
    internals (they are still never shown to end users verbatim).
    """
    if not text:
        return ""
    value = str(text)
    value = re.sub(r"([A-Za-z]:\\[^\s'\"]+|/[^\s'\"]*/[^\s'\"]*)", "<path>", value)
    value = re.sub(r"://[^@\s/]+@", "://<credentials>@", value)
    value = re.sub(r"\b[A-Za-z0-9+/]{40,}={0,2}\b", "<redacted>", value)
    value = COLLAPSE_WHITESPACE.sub(" ", value).strip()
    return value[:limit]


def is_probably_secret(value: str | None) -> bool:
    """Heuristic used by the configuration checker to refuse secret values in templates."""
    if not value:
        return False
    upper = value.upper()
    markers = ("REPLACE_WITH", "CHANGEME", "CHANGE_ME", "YOUR_KEY", "<", ">", "XXXX", "EXAMPLE")
    return any(marker in upper for marker in markers)


def ensure_runtime_directories(app) -> list[str]:
    """Create every local directory the current configuration depends on.

    Flask-SQLAlchemy resolves a *relative* SQLite path against the application's
    ``instance_path``, so ``sqlite:///instance/securecloud.db`` needs the instance
    directory to exist before the first connection - SQLite will not create a
    missing parent directory and fails with "unable to open database file".
    Staging and download-temp directories are needed before the first upload for
    the same reason.
    """
    candidates: list[str] = []
    uri = str(app.config.get("SQLALCHEMY_DATABASE_URI") or "")
    rel = ""
    if uri.startswith("sqlite:////"):
        candidates.append(os.path.dirname(uri[len("sqlite:////") - 1:]))
    elif uri.startswith("sqlite:///"):
        rel = uri[len("sqlite:///"):]
    if rel and rel != ":memory:":
        # Flask-SQLAlchemy resolves a relative SQLite path against the app's
        # instance folder, so create the parent of that *resolved* location.
        resolved = rel if os.path.isabs(rel) else os.path.join(app.instance_path, rel)
        candidates.append(os.path.dirname(resolved) or app.instance_path)
    for key in ("STAGING_DIR", "DOWNLOAD_TEMP_DIR", "LOCAL_STORAGE_DIR"):
        value = app.config.get(key)
        if value:
            candidates.append(str(value))

    created: list[str] = []
    for path in candidates:
        if not path:
            continue
        try:
            os.makedirs(path, exist_ok=True)
            created.append(path)
        except OSError:  # pragma: no cover - non-fatal, surfaces on first use
            continue
    return created
