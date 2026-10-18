"""SecureCloud application factory."""
from __future__ import annotations

import logging
import os
import sys

from flask import Flask, jsonify, make_response, render_template, request

# Make the project root importable when the package is used from a script or
# from the Flask CLI (the layout keeps ``config.py`` at the repository root).
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:  # pragma: no cover - import bootstrap
    sys.path.insert(0, _PROJECT_ROOT)

from config import CONFIG_MAP, get_config  # noqa: E402
from securecloud.errors import register_error_handlers  # noqa: E402
from securecloud.extensions import csrf, db, limiter  # noqa: E402
from securecloud.services.key_manager import KEK_ENV_VAR, load_key_manager, validate_kek  # noqa: E402
from securecloud.storage import create_storage  # noqa: E402

logger = logging.getLogger("securecloud")


def _configure_logging(app) -> None:
    level = getattr(logging, str(app.config.get("LOG_LEVEL", "INFO")).upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    app.logger.setLevel(level)


def _ensure_directories(app) -> None:
    for key in ("STAGING_DIR", "DOWNLOAD_TEMP_DIR", "LOCAL_STORAGE_DIR"):
        path = app.config.get(key)
        if path:
            os.makedirs(path, exist_ok=True)
    uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
    if uri.startswith("sqlite:///"):
        db_path = uri[len("sqlite:///"):]
        if db_path and db_path != ":memory:":
            folder = os.path.dirname(db_path)
            if folder:
                os.makedirs(folder, exist_ok=True)


def _check_secret_key(app) -> None:
    if app.config.get("SECRET_KEY"):
        return
    if app.config.get("ENVIRONMENT") == "production":
        raise RuntimeError(
            "SECRET_KEY is not set. Production refuses to start without a random "
            "session secret. Generate one with: python scripts/generate_encryption_key.py --secret"
        )
    # Development/testing convenience only: an ephemeral key invalidates
    # sessions on restart, which is safe but noisy.
    app.config["SECRET_KEY"] = os.urandom(32).hex()
    logger.warning(
        "SECRET_KEY is not set; using an ephemeral development key. "
        "Set SECRET_KEY in .env for stable sessions."
    )


def _init_key_manager(app) -> None:
    allow_missing = bool(app.config.get("ALLOW_START_WITHOUT_KEY")) and not bool(
        app.config.get("REQUIRE_KEY_AT_STARTUP")
    )
    raw = app.config.get("SECURECLOUD_KEY_ENCRYPTION_KEY")
    status = validate_kek(raw)
    try:
        manager = load_key_manager(app.config)
    except Exception as exc:
        message = getattr(exc, "public_message", str(exc))
        if app.config.get("ENVIRONMENT") == "production" or not allow_missing:
            raise RuntimeError(
                "Refusing to start without a usable key-encryption key.\n"
                f"{message}\n"
                "Generate one with: python scripts/generate_encryption_key.py\n"
                "If you only need to inspect the configuration without encrypting, "
                "set SECURECLOUD_ALLOW_START_WITHOUT_KEY=true (development only)."
            ) from exc
        logger.critical("Key-encryption key unavailable: %s", message)
        manager = load_key_manager({**app.config, "ALLOW_START_WITHOUT_KEY": True,
                                    "SECURECLOUD_KEY_ENCRYPTION_KEY": ""})
    app.extensions["securecloud_key_manager"] = manager
    app.config["CRYPTO_READY"] = manager.configured
    app.extensions["securecloud_key_status"] = status
    if manager.configured:
        logger.info("Key-encryption key loaded (fingerprint %s).", manager.fingerprint_short)
    else:
        logger.critical(
            "No key-encryption key configured (%s). Encrypted upload/download is disabled.",
            KEK_ENV_VAR,
        )


def _register_security_headers(app) -> None:
    @app.after_request
    def _set_headers(response):  # noqa: ANN001
        if not app.config.get("SECURITY_HEADERS_ENABLED", True):
            return response
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        # The UI ships no third-party assets, so a strict policy is possible.
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; font-src 'self'; form-action 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; object-src 'none'",
        )
        if response.mimetype == "text/html":
            response.headers.setdefault("Cache-Control", "no-store")
        if app.config.get("ENVIRONMENT") == "production" and request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


def _register_blueprints(app) -> None:
    from securecloud.auth.routes import auth_bp
    from securecloud.dashboard.routes import dashboard_bp
    from securecloud.files.routes import files_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(files_bp)


def _register_cli(app) -> None:
    from securecloud.services import cleanup_service, file_service, integrity
    from securecloud.storage import get_storage

    @app.cli.command("init-db")
    def init_db_command():  # pragma: no cover - CLI
        """Create missing tables (never drops or deletes existing data)."""
        db.create_all()
        print("Metadata database is ready. Existing data was preserved.")

    @app.cli.command("check-config")
    def check_config_command():  # pragma: no cover - CLI
        """Print the effective configuration (no secret values)."""
        from scripts.check_configuration import describe_configuration

        for line in describe_configuration(app):
            print(line)

    @app.cli.command("check-storage")
    def check_storage_command():  # pragma: no cover - CLI
        """Verify object-storage connectivity."""
        storage = get_storage()
        report = storage.health_check()
        print(f"{storage.display_name}: {'OK' if report['ok'] else 'FAILED'}")
        print(report["message"])

    @app.cli.command("cleanup-uploads")
    def cleanup_uploads_command():  # pragma: no cover - CLI
        """Recover/clean up unfinished or partially deleted uploads."""
        result = cleanup_service.run_maintenance()
        print(result)


def _register_context(app) -> None:
    from securecloud.security import current_user
    from securecloud.services.key_manager import get_key_manager
    from securecloud.utils import human_size, short_hash

    @app.context_processor
    def inject_globals():  # noqa: ANN001
        storage = app.extensions.get("securecloud_storage")
        storage_desc = storage.describe() if storage is not None else None
        try:
            key_status = get_key_manager().status()
        except Exception:  # pragma: no cover - defensive
            key_status = None
        return {
            "app_name": app.config.get("APP_NAME", "SecureCloud"),
            "app_version": app.config.get("APP_VERSION", "1.0.0"),
            "app_tagline": app.config.get("APP_TAGLINE", ""),
            "environment": app.config.get("ENVIRONMENT", "development"),
            "current_user": current_user(),
            "storage_description": storage_desc,
            "key_status": key_status,
            "crypto_ready": bool(app.config.get("CRYPTO_READY")),
            "max_upload_bytes": app.config.get("MAX_CONTENT_LENGTH"),
            "block_size": app.config.get("BLOCK_SIZE"),
            "human_size": human_size,
            "short_hash": short_hash,
        }

    @app.template_filter("filesize")
    def filesize_filter(value):  # noqa: ANN001
        return human_size(value)


def create_app(config_name: str | None = None, overrides: dict | None = None) -> Flask:
    """Create and configure the Flask application."""
    config_name = (
        config_name
        or os.getenv("FLASK_CONFIG")
        or os.getenv("SECURECLOUD_ENV")
        or "development"
    )
    config_class = get_config(config_name)

    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(config_class)
    if overrides:
        app.config.update(overrides)

    config_class.init_dirs()
    _ensure_directories(app)
    _configure_logging(app)
    _check_secret_key(app)

    # Extensions
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Storage adapter (created explicitly; no silent fallback)
    app.extensions["securecloud_storage"] = create_storage(app.config)

    # Key management (refuses to start without a key in production unless the
    # operator explicitly opted into configuration-only mode)
    _init_key_manager(app)

    _register_security_headers(app)

    # Session / authentication lifecycle
    from securecloud.security import load_current_user

    app.before_request(load_current_user)

    _register_blueprints(app)
    register_error_handlers(app)
    _register_context(app)
    _register_cli(app)

    @app.route("/healthz")
    def healthz():  # noqa: ANN202
        """Liveness probe used by the container healthcheck and load balancers."""
        return jsonify({
            "status": "ok",
            "app": app.config.get("APP_NAME"),
            "version": app.config.get("APP_VERSION"),
            "environment": app.config.get("ENVIRONMENT"),
            "crypto_ready": bool(app.config.get("CRYPTO_READY")),
        })

    @app.route("/robots.txt")
    def robots():  # noqa: ANN202
        response = make_response("User-agent: *\nDisallow: /\n")
        response.mimetype = "text/plain"
        return response

    with app.app_context():
        # Import models so create_all()/migrations see every table.  Nothing is
        # created or dropped automatically here: schema changes are explicit
        # (scripts/init_db.py) so an existing database is never deleted.
        from securecloud import models  # noqa: F401

    # Create the directories the configuration points at (instance, staging,
    # download temp) so a fresh checkout can start without a manual mkdir.
    from securecloud.utils import ensure_runtime_directories

    ensure_runtime_directories(app)

    @app.teardown_request
    def _clear_cached_csrf_token(exc=None):  # noqa: ANN001, ARG001
        """Drop Flask-WTF's request-scoped CSRF token cache.

        ``generate_csrf()`` memoises the token on ``g``, and ``g`` belongs to the
        *application* context.  Flask reuses an application context that is
        already pushed - which happens whenever requests are issued inside one
        (tests, CLI helpers, maintenance jobs) - so a cached token could be
        handed to a different client without ever being written to that client's
        session.  Its next form post would then fail with "The CSRF session
        token is missing."  Clearing the cache here forces every request to mint
        its own token and persist it in that client's session.
        """
        from flask import g

        try:
            g.pop("csrf_token", None)
        except Exception:  # pragma: no cover - defensive
            pass

    return app


__all__ = ["CONFIG_MAP", "create_app"]


def _render_stub():  # pragma: no cover - kept for import safety
    return render_template("index.html")
