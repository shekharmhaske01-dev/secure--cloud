"""Test configuration and shared fixtures.

Environment variables are set *before* the application package is imported,
because ``config.py`` reads them when the configuration classes are defined.
"""
from __future__ import annotations

import base64
import os
import re
import shutil
import tempfile

import pytest

# ---------------------------------------------------------------------------
# Environment for the whole test session
# ---------------------------------------------------------------------------
SESSION_TMP = tempfile.mkdtemp(prefix="securecloud-tests-")

os.environ.setdefault("FLASK_CONFIG", "testing")
os.environ["SECURECLOUD_ENV"] = "testing"
os.environ["SECRET_KEY"] = "test-session-secret-not-used-in-production"
os.environ["SECURECLOUD_KEY_ENCRYPTION_KEY"] = base64.b64encode(
    bytes(range(32))  # deterministic test KEK (32 bytes -> AES-256)
).decode("ascii")
os.environ["SECURECLOUD_KEY_ENCRYPTION_KEY_ALT"] = base64.b64encode(bytes(range(1, 33))).decode("ascii")
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(SESSION_TMP, 'test.db')}"
os.environ["SECURECLOUD_STORAGE_BACKEND"] = "local"
os.environ["SECURECLOUD_LOCAL_STORAGE_DIR"] = os.path.join(SESSION_TMP, "objects")
os.environ["SECURECLOUD_STAGING_DIR"] = os.path.join(SESSION_TMP, "staging")
os.environ["SECURECLOUD_DOWNLOAD_TEMP_DIR"] = os.path.join(SESSION_TMP, "downloads")
os.environ["SECURECLOUD_BLOCK_SIZE"] = "4096"          # small blocks -> multi-block files
os.environ["SECURECLOUD_MAX_UPLOAD_BYTES"] = str(4 * 1024 * 1024)
os.environ["SECURECLOUD_STALE_UPLOAD_MINUTES"] = "1"
os.environ.pop("NEON_STORAGE_ENDPOINT_URL", None)

from securecloud import create_app  # noqa: E402
from securecloud.extensions import db as _db  # noqa: E402
from securecloud.models import StoredFile, User  # noqa: E402

TEST_KEK = os.environ["SECURECLOUD_KEY_ENCRYPTION_KEY"]
TEST_KEK_ALT = os.environ["SECURECLOUD_KEY_ENCRYPTION_KEY_ALT"]
BLOCK_SIZE = 4096


@pytest.fixture(scope="session")
def app_config_overrides():
    return {
        "SERVER_NAME": None,
        "WTF_CSRF_ENABLED": True,
        "RATELIMIT_ENABLED": False,
        "STAGING_DIR": os.path.join(SESSION_TMP, "staging"),
        "DOWNLOAD_TEMP_DIR": os.path.join(SESSION_TMP, "downloads"),
        "LOCAL_STORAGE_DIR": os.path.join(SESSION_TMP, "objects"),
    }


@pytest.fixture()
def app(app_config_overrides):
    """Fresh application bound to a per-test SQLite file."""
    db_path = os.path.join(SESSION_TMP, f"test-{os.getpid()}.db")
    overrides = dict(app_config_overrides)
    overrides["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    application = create_app("testing", overrides)
    with application.app_context():
        _db.drop_all()
        _db.create_all()
        clear_storage(application)
        yield application
        _db.session.remove()


@pytest.fixture()
def client(app):
    return app.test_client()


def clear_storage(application) -> None:
    adapter = application.extensions.get("securecloud_storage")
    if adapter is not None and hasattr(adapter, "reset_for_tests"):
        try:
            adapter.reset_for_tests()
        except Exception:  # pragma: no cover - defensive
            pass


@pytest.fixture(autouse=True)
def _clean_directories(app):
    for key in ("STAGING_DIR", "DOWNLOAD_TEMP_DIR"):
        path = app.config.get(key)
        if path and os.path.isdir(path):
            for name in os.listdir(path):
                target = os.path.join(path, name)
                if os.path.isfile(target):
                    try:
                        os.remove(target)
                    except OSError:
                        pass
    yield


def _extract_csrf(html: str) -> str:
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    if not match:
        raise AssertionError("No CSRF token found in the rendered page.")
    return match.group(1)


def get_csrf(client, url: str) -> str:
    response = client.get(url)
    assert response.status_code == 200, f"GET {url} returned {response.status_code}"
    return _extract_csrf(response.get_data(as_text=True))


def register(client, username="alice", email="alice@example.com", password="Correct-Horse-9!"):
    token = get_csrf(client, "/auth/register")
    return client.post(
        "/auth/register",
        data={
            "csrf_token": token,
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password,
            "accept_terms": "y",
        },
        follow_redirects=False,
    )


def login(client, identifier="alice", password="Correct-Horse-9!"):
    token = get_csrf(client, "/auth/login")
    return client.post(
        "/auth/login",
        data={"csrf_token": token, "username": identifier, "password": password},
        follow_redirects=False,
    )


def logout(client):
    return client.get("/auth/logout", follow_redirects=False)


def upload_bytes(client, data: bytes, filename="sample.bin", mime="application/octet-stream",
                 json_response: bool = True):
    """Upload raw bytes through the real upload endpoint."""
    from io import BytesIO

    token = get_csrf(client, "/files/upload")
    headers = {"X-Requested-With": "XMLHttpRequest"} if json_response else {}
    return client.post(
        "/files/upload",
        data={"csrf_token": token, "file": (BytesIO(data), filename, mime)},
        content_type="multipart/form-data",
        headers=headers,
    )


@pytest.fixture()
def alice(client):
    register(client)
    login(client)
    return client


@pytest.fixture()
def users(app):
    """Create two accounts directly in the database (bypasses the HTTP flow)."""
    with app.app_context():
        a = User(username="alice", email="alice@example.com")
        a.set_password("Correct-Horse-9!")
        b = User(username="bob", email="bob@example.com")
        b.set_password("Correct-Horse-9!")
        _db.session.add_all([a, b])
        _db.session.commit()
        return {"alice": a.id, "bob": b.id}


def pytest_sessionfinish(session, exitstatus):  # noqa: ANN001, ANN201, ARG001
    shutil.rmtree(SESSION_TMP, ignore_errors=True)
