"""Authentication, session, CSRF and rate-limiting tests."""
from __future__ import annotations

import os

import pytest

from securecloud import create_app
from securecloud.extensions import db as _db
from securecloud.models import User

from tests.conftest import get_csrf, login, register


def test_landing_page_is_public(client):
    response = client.get("/")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "SecureCloud" in body
    assert "AES-256-GCM" in body
    assert "Create account" in body


def test_healthz(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "ok"
    assert payload["crypto_ready"] is True


def test_registration_creates_hashed_password(app, client):
    response = register(client)
    assert response.status_code == 302, response.get_data(as_text=True)
    with app.app_context():
        user = User.query.filter_by(username="alice").one()
        assert user.password_hash != "Correct-Horse-9!"
        assert user.password_hash.startswith("$argon2")
        assert user.check_password("Correct-Horse-9!")
        assert not user.check_password("wrong-password")


def test_registration_rejects_duplicate_username(app, client):
    register(client)
    client.get("/auth/logout")
    response = register(client, username="alice", email="other@example.com")
    assert response.status_code in (400, 409)
    with app.app_context():
        assert User.query.count() == 1


def test_registration_rejects_mismatched_passwords(client):
    token = get_csrf(client, "/auth/register")
    response = client.post("/auth/register", data={
        "csrf_token": token, "username": "bob", "email": "bob@example.com",
        "password": "Correct-Horse-9!", "confirm_password": "Different-1234!",
        "accept_terms": "y",
    })
    assert response.status_code == 200
    assert "do not match" in response.get_data(as_text=True).lower()


@pytest.mark.parametrize("password", ["short", "1234567890123", "abcdefghijklm"])
def test_registration_enforces_password_policy(client, password):
    token = get_csrf(client, "/auth/register")
    response = client.post("/auth/register", data={
        "csrf_token": token, "username": "carol", "email": "carol@example.com",
        "password": password, "confirm_password": password, "accept_terms": "y",
    })
    assert response.status_code == 200
    assert "password" in response.get_data(as_text=True).lower()


def test_registration_requires_terms_acknowledgement(client):
    token = get_csrf(client, "/auth/register")
    response = client.post("/auth/register", data={
        "csrf_token": token, "username": "dave", "email": "dave@example.com",
        "password": "Correct-Horse-9!", "confirm_password": "Correct-Horse-9!",
    })
    assert response.status_code == 200


def test_csrf_protection_blocks_post_without_token(client):
    response = client.post("/auth/register", data={
        "username": "evil", "email": "evil@example.com",
        "password": "Correct-Horse-9!", "confirm_password": "Correct-Horse-9!",
        "accept_terms": "y",
    })
    assert response.status_code == 400
    assert "csrf" in response.get_data(as_text=True).lower() or "token" in response.get_data(as_text=True).lower()


def test_login_with_wrong_password_is_rejected(client):
    register(client)
    client.get("/auth/logout")
    response = login(client, password="Not-The-Password-1!")
    assert response.status_code == 401
    body = response.get_data(as_text=True)
    assert "Invalid username/email or password." in body
    assert "argon2" not in body and "traceback" not in body.lower()


def test_login_unknown_account_uses_same_message(client):
    response = login(client, identifier="ghost", password="Correct-Horse-9!")
    assert response.status_code == 401
    assert "Invalid username/email or password." in response.get_data(as_text=True)


def test_login_with_email_works(client):
    register(client)
    client.get("/auth/logout")
    response = login(client, identifier="alice@example.com")
    assert response.status_code == 302


def test_dashboard_requires_authentication(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_file_pages_require_authentication(client):
    for path in ("/files/", "/files/upload", "/settings", "/files/1", "/files/1/download"):
        response = client.get(path)
        assert response.status_code == 302, path
        assert "/auth/login" in response.headers["Location"], path


def test_api_requires_authentication_returns_401(client):
    response = client.get("/files/api/list", headers={"X-Requested-With": "XMLHttpRequest"})
    assert response.status_code == 401
    assert response.get_json()["error"] == "authentication_required"


def test_logout_invalidates_the_session(client):
    register(client)
    assert client.get("/dashboard").status_code == 200
    token = get_csrf(client, "/files/upload")
    response = client.post("/auth/logout", data={"csrf_token": token})
    assert response.status_code == 302
    assert client.get("/dashboard").status_code == 302


def test_session_token_rotation_invalidates_other_sessions(app, client):
    """A second client using a stolen-but-rotated token must be rejected."""
    register(client)
    with app.app_context():
        user = User.query.filter_by(username="alice").one()
        old_token = user.session_token
        user.rotate_session_token()
        _db.session.commit()

    with client.session_transaction() as sess:
        sess["session_token"] = old_token
    response = client.get("/dashboard")
    assert response.status_code == 302, "a stale server-side token must invalidate the session"


def test_session_cookie_flags(client):
    register(client)
    response = client.get("/dashboard")
    cookie_header = response.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie_header
    assert "SameSite=Lax" in cookie_header or "SameSite=lax" in cookie_header


def test_open_redirect_is_blocked(client):
    """A crafted ?next= must not send the user to another site."""
    response = client.post(
        "/auth/register",
        data={
            "csrf_token": get_csrf(client, "/auth/register"),
            "username": "erin", "email": "erin@example.com",
            "password": "Correct-Horse-9!", "confirm_password": "Correct-Horse-9!",
            "accept_terms": "y",
            "next": "https://evil.example.com/steal",
        },
        follow_redirects=False,
    )
    assert response.status_code == 302
    assert "evil.example.com" not in response.headers["Location"]

    client.get("/auth/logout")
    response = client.post(
        "/auth/login",
        data={
            "csrf_token": get_csrf(client, "/auth/login"),
            "username": "erin", "password": "Correct-Horse-9!",
            "next": "//evil.example.com",
        },
        follow_redirects=False,
    )
    assert "evil.example.com" not in response.headers.get("Location", "")


def test_rate_limit_triggers_on_login():
    """With rate limiting enabled, repeated sign-in attempts are blocked (429)."""
    import os as _os

    app = create_app("testing", {
        "RATELIMIT_ENABLED": True,
        "RATELIMIT_LOGIN": "3 per minute",
        "RATELIMIT_DEFAULT": "1000 per hour",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{_os.path.join(_os.environ.get('TMPDIR', '/tmp'), 'rl-test.db')}",
    })
    with app.app_context():
        _db.create_all()
        client = app.test_client()
        statuses = []
        for _ in range(8):
            token = get_csrf(client, "/auth/login")
            response = client.post("/auth/login", data={
                "csrf_token": token, "username": "nobody", "password": "Whatever-1234!",
            })
            statuses.append(response.status_code)
        assert 429 in statuses, f"expected a 429 after repeated attempts, got {statuses}"


def client_for(app):
    return app.test_client()


def test_session_diagnostics_endpoint(client):
    response = client.get("/auth/session", headers={"X-Requested-With": "XMLHttpRequest"})
    assert response.status_code == 401
    register(client)
    response = client.get("/auth/session", headers={"X-Requested-With": "XMLHttpRequest"})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["authenticated"] is True
    assert "session_token" not in payload
