"""Configuration classes for SecureCloud.

Every setting can be supplied through environment variables.  Values are read
from a local ``.env`` file when present (see ``.env.example``).

Security notes
--------------
* ``SECRET_KEY`` and ``SECURECLOUD_KEY_ENCRYPTION_KEY`` are secrets and must
  never be committed, logged or shipped inside a repository/ZIP.
* The key-encryption key has no default and is never generated automatically.
"""
from __future__ import annotations

import os
from datetime import timedelta

from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
STAGING_DIR = os.path.join(BASE_DIR, "staging")
LOCAL_STORAGE_DIR = os.path.join(STAGING_DIR, "local_object_storage")
DOWNLOAD_TEMP_DIR = os.path.join(STAGING_DIR, "downloads")

load_dotenv(os.path.join(BASE_DIR, ".env"))


def _env_str(name: str, default: str = "") -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


def resolve_path(value: str) -> str:
    """Return an absolute path; relative values are resolved against the project root."""
    if not value:
        return value
    return value if os.path.isabs(value) else os.path.join(BASE_DIR, value)


class Config:
    """Base configuration shared by every environment."""

    APP_NAME = "SecureCloud"
    APP_VERSION = "1.0.0"
    APP_TAGLINE = "Encrypted, chunked cloud file storage"
    ENVIRONMENT = "base"

    # --- Flask core -------------------------------------------------------
    SECRET_KEY = _env_str("SECRET_KEY", "")
    DEBUG = False
    TESTING = False
    JSON_SORT_KEYS = False
    PREFERRED_URL_SCHEME = "http"

    # --- Database (metadata only) ----------------------------------------
    SQLALCHEMY_DATABASE_URI = _env_str(
        "DATABASE_URL", "sqlite:///" + os.path.join(INSTANCE_DIR, "securecloud.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        # SQLite serialises writers; give competing requests time to finish
        # instead of failing immediately on a metadata lock.
        "connect_args": {"timeout": 20, "check_same_thread": False},
    }

    # --- Sessions ---------------------------------------------------------
    SESSION_COOKIE_NAME = "securecloud_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _env_bool("SECURECLOUD_SESSION_COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=_env_int("SECURECLOUD_SESSION_HOURS", 12))
    SESSION_TOKEN_TTL_HOURS = _env_int("SECURECLOUD_SESSION_HOURS", 12)
    SESSION_TOUCH_INTERVAL_SECONDS = _env_int("SECURECLOUD_SESSION_TOUCH_SECONDS", 300)
    SESSION_REFRESH_THRESHOLD_SECONDS = _env_int("SECURECLOUD_SESSION_REFRESH_SECONDS", 1800)

    # --- Crypto -----------------------------------------------------------
    KEK_ENV_VAR_NAME = "SECURECLOUD_KEY_ENCRYPTION_KEY"
    SECURECLOUD_KEY_ENCRYPTION_KEY = _env_str(KEK_ENV_VAR_NAME, "")
    BLOCK_FORMAT_VERSION = 1
    WRAP_FORMAT_VERSION = 1
    REQUIRE_KEY_AT_STARTUP = _env_bool("SECURECLOUD_REQUIRE_KEY_AT_STARTUP", True)
    ALLOW_START_WITHOUT_KEY = _env_bool("SECURECLOUD_ALLOW_START_WITHOUT_KEY", False)
    CRYPTO_READY = False  # set during app creation

    # --- Files ------------------------------------------------------------
    BLOCK_SIZE = _env_int("SECURECLOUD_BLOCK_SIZE", 1024 * 1024)
    MIN_BLOCK_SIZE = 4096
    MAX_BLOCK_SIZE = 64 * 1024 * 1024
    MAX_CONTENT_LENGTH = _env_int("SECURECLOUD_MAX_UPLOAD_BYTES", 256 * 1024 * 1024)
    STAGING_DIR = resolve_path(_env_str("SECURECLOUD_STAGING_DIR", STAGING_DIR))
    DOWNLOAD_TEMP_DIR = resolve_path(_env_str("SECURECLOUD_DOWNLOAD_TEMP_DIR", DOWNLOAD_TEMP_DIR))
    MAX_FILENAME_LENGTH = 255
    FILES_PER_PAGE = _env_int("SECURECLOUD_FILES_PER_PAGE", 20)

    # --- Object storage ---------------------------------------------------
    STORAGE_BACKEND = _env_str("SECURECLOUD_STORAGE_BACKEND", "local").lower()
    STORAGE_OBJECT_PREFIX = _env_str("SECURECLOUD_OBJECT_PREFIX", "securecloud/blocks").strip("/")
    STORAGE_PREFIX = STORAGE_OBJECT_PREFIX
    STORAGE_TIMEOUT_SECONDS = _env_int("SECURECLOUD_STORAGE_TIMEOUT", 30)
    STORAGE_MAX_RETRIES = _env_int("SECURECLOUD_STORAGE_MAX_RETRIES", 3)
    LOCAL_STORAGE_DIR = resolve_path(
        _env_str("SECURECLOUD_LOCAL_STORAGE_DIR", LOCAL_STORAGE_DIR)
    )

    # Neon Object Storage / S3-compatible settings.  ``AWS_*`` names are kept
    # as documented compatibility aliases (Neon injects those names in its
    # own functions).
    NEON_STORAGE_ENDPOINT_URL = _env_str("NEON_STORAGE_ENDPOINT_URL", "")
    NEON_STORAGE_REGION = _env_str("NEON_STORAGE_REGION", "")
    NEON_STORAGE_BUCKET = _env_str("NEON_STORAGE_BUCKET", "")
    NEON_STORAGE_ACCESS_KEY_ID = _env_str("NEON_STORAGE_ACCESS_KEY_ID", "")
    NEON_STORAGE_SECRET_ACCESS_KEY = _env_str("NEON_STORAGE_SECRET_ACCESS_KEY", "")
    AWS_ENDPOINT_URL_S3 = _env_str("AWS_ENDPOINT_URL_S3", "")
    AWS_REGION = _env_str("AWS_REGION", "")
    AWS_ACCESS_KEY_ID = _env_str("AWS_ACCESS_KEY_ID", "")
    AWS_SECRET_ACCESS_KEY = _env_str("AWS_SECRET_ACCESS_KEY", "")

    # --- HDFS distributed storage -----------------------------------------
    HDFS_NAMENODE_URL = _env_str("HDFS_NAMENODE_URL", "")
    HDFS_USER = _env_str("HDFS_USER", "root")
    HDFS_ROOT_PATH = _env_str("HDFS_ROOT_PATH", "/securecloud")

    # --- Rate limiting ----------------------------------------------------
    RATELIMIT_ENABLED = True
    RATELIMIT_DEFAULT = _env_str("RATELIMIT_DEFAULT", "1000 per hour")
    RATELIMIT_STORAGE_URI = _env_str("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_HEADERS_ENABLED = True
    RATELIMIT_LOGIN = _env_str("RATELIMIT_LOGIN", "10 per minute")
    RATELIMIT_REGISTER = _env_str("RATELIMIT_REGISTER", "5 per hour")
    RATELIMIT_UPLOAD = _env_str("RATELIMIT_UPLOAD", "60 per hour")
    RATELIMIT_DOWNLOAD = _env_str("RATELIMIT_DOWNLOAD", "240 per hour")
    RATELIMIT_SENSITIVE = _env_str("RATELIMIT_SENSITIVE", "30 per hour")

    # --- Upload lifecycle -------------------------------------------------
    STALE_UPLOAD_MINUTES = _env_int("SECURECLOUD_STALE_UPLOAD_MINUTES", 60)
    BLOCK_COMMIT_INTERVAL = _env_int("SECURECLOUD_BLOCK_COMMIT_INTERVAL", 16)

    # --- Logging / hardening ---------------------------------------------
    LOG_LEVEL = _env_str("LOG_LEVEL", "INFO").upper()
    SECURITY_HEADERS_ENABLED = _env_bool("SECURECLOUD_SECURITY_HEADERS", True)

    @classmethod
    def init_dirs(cls) -> None:
        for path in (INSTANCE_DIR, cls.STAGING_DIR, cls.LOCAL_STORAGE_DIR, cls.DOWNLOAD_TEMP_DIR):
            os.makedirs(path, exist_ok=True)


class DevelopmentConfig(Config):
    ENVIRONMENT = "development"
    DEBUG = _env_bool("FLASK_DEBUG", True)
    # A developer may open the UI to inspect the configuration without a key;
    # crypto endpoints render a clear 503 configuration page instead of
    # failing silently.  Nothing is ever encrypted with a fallback key.
    ALLOW_START_WITHOUT_KEY = _env_bool("SECURECLOUD_ALLOW_START_WITHOUT_KEY", True)


class TestingConfig(Config):
    ENVIRONMENT = "testing"
    TESTING = True
    DEBUG = False
    WTF_CSRF_ENABLED = True
    SQLALCHEMY_DATABASE_URI = "sqlite://"  # overridden per-test with a file DB
    RATELIMIT_ENABLED = False
    REQUIRE_KEY_AT_STARTUP = True
    ALLOW_START_WITHOUT_KEY = False


class ProductionConfig(Config):
    ENVIRONMENT = "production"
    DEBUG = False
    TESTING = False
    PREFERRED_URL_SCHEME = "https"
    SESSION_COOKIE_SECURE = _env_bool("SECURECLOUD_SESSION_COOKIE_SECURE", True)
    # Refuse to boot with a missing/invalid key or a missing SECRET_KEY.
    REQUIRE_KEY_AT_STARTUP = True
    ALLOW_START_WITHOUT_KEY = False


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "dev": DevelopmentConfig,
    "testing": TestingConfig,
    "test": TestingConfig,
    "production": ProductionConfig,
    "prod": ProductionConfig,
}


def get_config(name: str | None = None):
    """Return the configuration class for *name* (defaults to development)."""
    key = (name or "development").strip().lower()
    return CONFIG_MAP.get(key, DevelopmentConfig)
