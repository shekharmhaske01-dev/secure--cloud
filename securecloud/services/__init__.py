"""Domain exceptions and error helpers shared by the service layer."""
from __future__ import annotations

from securecloud.utils import redact

# --------------------------------------------------------------------------
# Generic categories used for StorageOperation.error_category
# --------------------------------------------------------------------------
CATEGORY_CONFIGURATION = "configuration"
CATEGORY_AUTHENTICATION = "authentication"
CATEGORY_ACCESS_DENIED = "access_denied"
CATEGORY_NOT_FOUND = "not_found"
CATEGORY_TIMEOUT = "timeout"
CATEGORY_NETWORK = "network"
CATEGORY_PROVIDER = "provider"
CATEGORY_INTEGRITY = "integrity"
CATEGORY_VALIDATION = "validation"
CATEGORY_STATE = "invalid_state"
CATEGORY_STORAGE = "storage"
CATEGORY_CRYPTO = "crypto"
CATEGORY_UNKNOWN = "unknown"


class SecureCloudError(Exception):
    """Base class for expected application errors.

    ``public_message`` is safe to show to the user; ``detail`` is a redacted
    operator-facing string that never reaches the browser.
    """

    category = CATEGORY_UNKNOWN
    http_status = 500

    def __init__(self, public_message: str, detail: str = ""):
        super().__init__(public_message)
        self.public_message = public_message
        self.detail = redact(detail)


class ConfigurationError(SecureCloudError):
    category = CATEGORY_CONFIGURATION
    http_status = 503


class CryptoError(SecureCloudError):
    category = CATEGORY_CRYPTO
    http_status = 500


class FileOperationError(SecureCloudError):
    http_status = 500


class FileValidationError(FileOperationError):
    category = CATEGORY_VALIDATION
    http_status = 400


class FileTooLargeError(FileValidationError):
    http_status = 413


class FileNotFoundForUser(FileOperationError):
    """Raised when a file does not exist *or* is not owned by the caller."""

    category = CATEGORY_NOT_FOUND
    http_status = 404

    def __init__(self, detail: str = ""):
        super().__init__("File not found.", detail)


class InvalidFileStateError(FileOperationError):
    category = CATEGORY_STATE
    http_status = 409


class FileIntegrityError(FileOperationError):
    category = CATEGORY_INTEGRITY
    http_status = 422


class CleanupError(FileOperationError):
    pass


__all__ = [
    "CATEGORY_ACCESS_DENIED",
    "CATEGORY_AUTHENTICATION",
    "CATEGORY_CONFIGURATION",
    "CATEGORY_CRYPTO",
    "CATEGORY_INTEGRITY",
    "CATEGORY_NETWORK",
    "CATEGORY_NOT_FOUND",
    "CATEGORY_PROVIDER",
    "CATEGORY_STATE",
    "CATEGORY_STORAGE",
    "CATEGORY_TIMEOUT",
    "CATEGORY_UNKNOWN",
    "CATEGORY_VALIDATION",
    "CleanupError",
    "ConfigurationError",
    "CryptoError",
    "FileIntegrityError",
    "FileNotFoundForUser",
    "FileOperationError",
    "FileTooLargeError",
    "FileValidationError",
    "InvalidFileStateError",
    "SecureCloudError",
    "redact",
]
