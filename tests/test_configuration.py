"""Configuration, startup-safety and page-rendering tests."""
from __future__ import annotations

import base64
import os

import pytest

from securecloud import create_app
from securecloud.services.key_manager import validate_kek
from securecloud.storage import LocalObjectStorage, S3ObjectStorage, create_storage


def test_app_refuses_to_start_without_a_key():
    """No key-encryption key -> no startup (never auto-generated)."""
    with pytest.raises(RuntimeError) as excinfo:
        create_app("testing", {
            "SECURECLOUD_KEY_ENCRYPTION_KEY": "",
            "ALLOW_START_WITHOUT_KEY": False,
            "REQUIRE_KEY_AT_STARTUP": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
        })
    assert "key-encryption key" in str(excinfo.value).lower()
    assert "generate_encryption_key" in str(excinfo.value)


def test_app_refuses_an_invalid_key():
    with pytest.raises(RuntimeError):
        create_app("testing", {
            "SECURECLOUD_KEY_ENCRYPTION_KEY": "not-valid-base64!!",
            "ALLOW_START_WITHOUT_KEY": False,
            "REQUIRE_KEY_AT_STARTUP": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
        })


def test_configuration_only_mode_disables_crypto_endpoints():
    app = create_app("testing", {
        "SECURECLOUD_KEY_ENCRYPTION_KEY": "",
        "ALLOW_START_WITHOUT_KEY": True,
        "REQUIRE_KEY_AT_STARTUP": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite://",
    })
    assert app.config["CRYPTO_READY"] is False
    from securecloud.extensions import db as _db

    with app.app_context():
        _db.create_all()
        client = app.test_client()
        from tests.conftest import get_csrf, register

        register(client, username="cfguser", email="cfg@example.com")
        response = client.post(
            "/files/upload",
            data={"csrf_token": get_csrf(client, "/files/upload")},
            content_type="multipart/form-data",
            headers={"X-Requested-With": "XMLHttpRequest"},
            follow_redirects=False,
        )
        assert response.status_code in (400, 503)
        body = response.get_data(as_text=True)
        assert "key-encryption key" in body.lower() or "SECURECLOUD_KEY_ENCRYPTION_KEY" in body


def test_storage_factory_selects_local_backend():
    config = {"STORAGE_BACKEND": "local", "LOCAL_STORAGE_DIR": "/tmp",
              "STORAGE_PREFIX": "p"}
    storage = create_storage(config)
    assert isinstance(storage, LocalObjectStorage)
    assert storage.is_local is True


def test_storage_factory_selects_s3_backend():
    config = {
        "STORAGE_BACKEND": "s3",
        "NEON_STORAGE_BUCKET": "b", "NEON_STORAGE_ENDPOINT_URL": "https://x.invalid",
        "NEON_STORAGE_REGION": "us-east-1", "NEON_STORAGE_ACCESS_KEY_ID": "k",
        "NEON_STORAGE_SECRET_ACCESS_KEY": "s", "STORAGE_PREFIX": "p",
        "STORAGE_TIMEOUT_SECONDS": 5, "STORAGE_MAX_RETRIES": 2,
    }
    storage = create_storage(config)
    assert isinstance(storage, S3ObjectStorage)
    assert storage.is_local is False


def test_storage_factory_rejects_unknown_backend():
    from securecloud.services import ConfigurationError

    with pytest.raises(ConfigurationError):
        create_storage({"STORAGE_BACKEND": "quantum", "STORAGE_PREFIX": ""})


def test_no_local_fallback_when_s3_is_misconfigured(app):
    """Selecting s3 with incomplete settings must not silently use local storage."""
    config = {
        "STORAGE_BACKEND": "s3",
        "NEON_STORAGE_BUCKET": "", "NEON_STORAGE_ENDPOINT_URL": "",
        "NEON_STORAGE_REGION": "", "NEON_STORAGE_ACCESS_KEY_ID": "",
        "NEON_STORAGE_SECRET_ACCESS_KEY": "", "STORAGE_PREFIX": "p",
        "STORAGE_TIMEOUT_SECONDS": 5, "STORAGE_MAX_RETRIES": 2,
    }
    storage = create_storage(config)
    assert isinstance(storage, S3ObjectStorage)
    assert storage.describe().configured is False
    from securecloud.storage import StorageNotConfiguredError

    with pytest.raises(StorageNotConfiguredError):
        storage.upload_object("a/b.blk", b"data")


def test_rate_limit_configuration_is_present(app):
    for key in ("RATELIMIT_LOGIN", "RATELIMIT_REGISTER", "RATELIMIT_UPLOAD", "RATELIMIT_DOWNLOAD"):
        assert app.config.get(key)


def test_security_headers_are_set(client):
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in response.headers
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_error_pages_render_without_leaking_internals(client):
    response = client.get("/definitely-not-a-page")
    assert response.status_code == 404
    body = response.get_data(as_text=True).lower()
    assert "traceback" not in body
    assert "/home/" not in body
    assert "sqlalchemy" not in body


def test_storage_unavailable_page_renders(app):
    from securecloud.storage import StorageNotConfiguredError

    with app.app_context():
        app.extensions["securecloud_storage"] = create_storage({
            "STORAGE_BACKEND": "s3", "NEON_STORAGE_BUCKET": "", "NEON_STORAGE_ENDPOINT_URL": "",
            "NEON_STORAGE_REGION": "", "NEON_STORAGE_ACCESS_KEY_ID": "",
            "NEON_STORAGE_SECRET_ACCESS_KEY": "", "STORAGE_PREFIX": "p",
            "STORAGE_TIMEOUT_SECONDS": 5, "STORAGE_MAX_RETRIES": 2,
        })
        from securecloud.services.storage_service import get_storage_service

        service = get_storage_service()
        try:
            service.adapter.upload_object("x/y.blk", b"data")
        except StorageNotConfiguredError:
            pass
        else:  # pragma: no cover
            raise AssertionError("expected a configuration error")

        client = app.test_client()
        from tests.conftest import get_csrf, register, login

        register(client, username="storuser", email="stor@example.com")
        response = client.get("/settings")
        assert response.status_code == 200
        body = response.get_data(as_text=True)
        assert "not configured" in body.lower() or "missing settings" in body.lower()


def test_all_pages_render_for_a_signed_in_user(app, client):
    from tests.conftest import register, login, upload_bytes

    register(client)
    upload_bytes(client, os.urandom(5000), "render.bin")
    for path in ("/", "/dashboard", "/files/", "/files/upload", "/settings", "/about", "/auth/session"):
        response = client.get(path)
        assert response.status_code == 200, f"{path} returned {response.status_code}"
        body = response.get_data(as_text=True)
        for forbidden in ("SECURECLOUD_KEY_ENCRYPTION_KEY=", "secret_access_key", "Traceback"):
            assert forbidden not in body, f"{path} leaked {forbidden}"


def test_registration_page_renders(client):
    assert client.get("/auth/register").status_code == 200
    assert client.get("/auth/login").status_code == 200


def test_settings_page_never_shows_secret_values(app, client):
    from tests.conftest import register

    register(client)
    response = client.get("/settings")
    body = response.get_data(as_text=True)
    assert os.environ["SECURECLOUD_KEY_ENCRYPTION_KEY"] not in body
    assert app.config["SECRET_KEY"] not in body
    # The fingerprint is safe to show and should be present instead.
    assert "fingerprint" in body.lower()


def test_healthz_reports_crypto_readiness(app, client):
    payload = client.get("/healthz").get_json()
    assert payload["crypto_ready"] is True


def test_init_db_script_check_only_runs(app):
    """scripts/init_db.py must be runnable and never destructive."""
    import subprocess
    import sys

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run(
        [sys.executable, os.path.join(root, "scripts", "init_db.py"), "--check-only"],
        capture_output=True, text=True, cwd=root, timeout=120,
        env={**os.environ, "FLASK_CONFIG": "testing"},
    )
    assert result.returncode in (0, 1), result.stderr
    assert "no table was dropped" in result.stdout or "missing tables" in result.stdout


def test_generate_key_script_prints_a_valid_key():
    import subprocess
    import sys

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result = subprocess.run(
        [sys.executable, os.path.join(root, "scripts", "generate_encryption_key.py")],
        capture_output=True, text=True, cwd=root, timeout=120,
    )
    assert result.returncode == 0, result.stderr
    assert "UNRECOVERABLE" in result.stdout
    for line in result.stdout.splitlines():
        if line.startswith("SECURECLOUD_KEY_ENCRYPTION_KEY="):
            value = line.split("=", 1)[1].strip()
            status = validate_kek(value)
            assert status.valid is True and status.key_size_bits == 256
            break
    else:  # pragma: no cover
        raise AssertionError("the script did not print a key")
