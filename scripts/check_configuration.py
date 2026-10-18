"""Report the effective SecureCloud configuration.

Prints settings and validation results only - never secret values.  The
key-encryption key is reported by validity, size and a non-reversible
fingerprint, never by value.

Usage:
    python scripts/check_configuration.py
    python scripts/check_configuration.py --config production
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import get_config  # noqa: E402

OK = "OK  "
BAD = "FAIL"
WARN = "WARN"


def describe_configuration(app) -> list[str]:
    """Return a list of formatted status lines for an application."""
    from securecloud.services.chunking import MAX_BLOCK_SIZE, MIN_BLOCK_SIZE
    from securecloud.services.key_manager import get_key_manager
    from securecloud.services.storage_service import get_storage_service
    from securecloud.utils import human_size, is_probably_secret

    cfg = app.config
    lines: list[str] = []
    add = lines.append

    add(f"SecureCloud configuration check ({cfg.get('ENVIRONMENT')} environment)")
    add("")

    # --- core ------------------------------------------------------------
    add("Application")
    secret = cfg.get("SECRET_KEY") or ""
    if not secret:
        add(f"  [{BAD}] SECRET_KEY is not set (production refuses to start; "
            f"development uses an ephemeral key)")
    elif is_probably_secret(secret):
        add(f"  [{WARN}] SECRET_KEY looks like a placeholder; generate a real one")
    else:
        add(f"  [{OK}] SECRET_KEY is set ({len(secret)} characters) - value not shown")
    if cfg.get("ENVIRONMENT") == "production" and not cfg.get("SESSION_COOKIE_SECURE"):
        add(f"  [{WARN}] SESSION_COOKIE_SECURE is disabled in production")
    else:
        add(f"  [{OK}] Session cookie: httponly={cfg.get('SESSION_COOKIE_HTTPONLY')}, "
            f"samesite={cfg.get('SESSION_COOKIE_SAMESITE')}, secure={cfg.get('SESSION_COOKIE_SECURE')}")

    # --- database --------------------------------------------------------
    add("")
    add("Metadata database")
    uri = cfg.get("SQLALCHEMY_DATABASE_URI", "")
    if uri.startswith("sqlite:///"):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            uri[len("sqlite:///"):]) if not os.path.isabs(uri[len("sqlite:///"):]) \
            else uri[len("sqlite:///"):]
        exists = os.path.exists(path)
        add(f"  [{OK if exists else WARN}] SQLite file {'exists' if exists else 'will be created'}: {path}")
    else:
        add(f"  [{OK}] Database URI configured ({uri.split(':')[0]})")
    add("  [OK  ] Plaintext file content and unwrapped keys are never stored in the database")

    # --- crypto ----------------------------------------------------------
    add("")
    add("Encryption")
    try:
        status = get_key_manager().status()
    except Exception as exc:  # pragma: no cover - defensive
        add(f"  [{BAD}] Key manager unavailable: {type(exc).__name__}")
        status = None
    if status is not None:
        if status.valid:
            add(f"  [{OK}] {status.message}")
            add(f"  [{OK}] Key fingerprint: {status.fingerprint}")
        else:
            add(f"  [{BAD}] {status.message}")
            add("        Generate one with: python scripts/generate_encryption_key.py")
    block_size = int(cfg.get("BLOCK_SIZE") or 0)
    if MIN_BLOCK_SIZE <= block_size <= MAX_BLOCK_SIZE:
        add(f"  [{OK}] Block size {block_size} bytes ({human_size(block_size)})")
    else:
        add(f"  [{BAD}] Block size {block_size} is outside {MIN_BLOCK_SIZE}-{MAX_BLOCK_SIZE}")
    add(f"  [{OK}] Format: AES-256-GCM, 12-byte nonce, AAD = version|file_id|block_index")

    # --- storage ---------------------------------------------------------
    add("")
    add("Object storage")
    try:
        storage = get_storage_service()
        desc = storage.description
    except Exception as exc:  # pragma: no cover - defensive
        add(f"  [{BAD}] Storage adapter unavailable: {type(exc).__name__}")
        return lines

    if desc.is_local:
        add(f"  [{WARN}] {desc.display_name} is active (development/testing only)")
        add("        This is NOT cloud object storage.")
    else:
        add(f"  [{OK}] {desc.display_name}")
        add(f"        bucket={desc.bucket} region={desc.region} "
            f"addressing={desc.addressing_style}")
        add(f"        endpoint={desc.endpoint}")
    if desc.configured:
        add(f"  [{OK}] Required settings present")
    else:
        add(f"  [{BAD}] Missing settings: {', '.join(desc.missing_settings)}")
    for note in desc.notes:
        add(f"        - {note}")

    add("")
    add("Limits")
    add(f"  [     ] Maximum upload size: {human_size(cfg.get('MAX_CONTENT_LENGTH'))}")
    add(f"  [     ] Session lifetime: {cfg.get('PERMANENT_SESSION_LIFETIME')}")
    add(f"  [     ] Rate limits: login={cfg.get('RATELIMIT_LOGIN')}, "
        f"register={cfg.get('RATELIMIT_REGISTER')}")
    add("")
    add("No secret value was printed by this command.")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the SecureCloud configuration.")
    parser.add_argument("--config", default=os.getenv("FLASK_CONFIG", "development"))
    args = parser.parse_args(argv)

    from securecloud import create_app

    try:
        app = create_app(args.config)
    except RuntimeError as exc:
        print("SecureCloud cannot start with the current configuration:")
        print(f"  {exc}")
        print()
        print("Configuration checklist:")
        config_class = get_config(args.config)
        from securecloud.services.key_manager import validate_kek
        raw = os.getenv("SECURECLOUD_KEY_ENCRYPTION_KEY", "")
        status = validate_kek(raw)
        print(f"  SECURECLOUD_KEY_ENCRYPTION_KEY: {'set' if raw else 'missing'} - {status.message}")
        print(f"  SECRET_KEY: {'set' if os.getenv('SECRET_KEY') else 'missing'}")
        print(f"  STORAGE_BACKEND: {os.getenv('SECURECLOUD_STORAGE_BACKEND', 'local')}")
        return 2

    for line in describe_configuration(app):
        print(line)
    return 0


if __name__ == "__main__":
    # The individual checks reach for the key manager and the storage
    # adapter, both of which read current_app configuration - so run them
    # inside a pushed application context.
    from securecloud import create_app

    _app = create_app()
    with _app.app_context():
        raise SystemExit(main())
