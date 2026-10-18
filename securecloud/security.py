"""Session handling, authentication decorators and request hardening."""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import current_app, flash, g, jsonify, redirect, request, session, url_for

from securecloud.extensions import db
from securecloud.models import User, utcnow

SESSION_USER_KEY = "user_id"
SESSION_AUTH_TIME = "auth_time"
SESSION_TOKEN_KEY = "session_token"
SESSION_ISSUED_AT = "issued_at"
SESSION_LAST_SEEN = "last_seen"
CSRF_SESSION_KEY = "csrf_token"


def current_user() -> User | None:
    return getattr(g, "user", None)


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def login_user(user: User) -> None:
    """Start an authenticated session (rotating the server-side token)."""
    session.clear()  # prevent session fixation
    session.permanent = True
    # session.clear() also drops Flask-WTF's CSRF session token, which would make
    # every later state-changing form fail with "The CSRF session token is
    # missing."  Mint a fresh one immediately *and* drop any token Flask-WTF may
    # have cached on ``g`` for this request: generate_csrf() returns that cached
    # value without re-seeding the (now empty) session, so the form token and the
    # session token would silently disagree.
    session[CSRF_SESSION_KEY] = secrets.token_hex(32)
    try:  # Flask >= 2.2 supports namespaced pop(); ignore if unavailable.
        g.pop("csrf_token", None)
    except Exception:  # pragma: no cover - defensive
        pass
    token = user.rotate_session_token()
    now = utcnow()
    session[SESSION_USER_KEY] = user.id
    session[SESSION_TOKEN_KEY] = token
    session[SESSION_AUTH_TIME] = now.isoformat()
    session[SESSION_ISSUED_AT] = now.isoformat()
    session[SESSION_LAST_SEEN] = now.isoformat()
    g.user = user
    # The rotated server-side token must be persisted immediately: without this
    # commit the session teardown rolls it back and the very next request would
    # fail the server-side token check (logging the user straight back out).
    try:
        db.session.commit()
    except Exception:  # pragma: no cover - defensive
        db.session.rollback()
        raise


def logout_user() -> None:
    session.clear()
    g.user = None


def invalidate_user_sessions(user: User) -> None:
    """Rotate the stored token so every existing session becomes invalid."""
    user.rotate_session_token()
    db.session.commit()


def session_lifetime() -> timedelta:
    return current_app.config.get("PERMANENT_SESSION_LIFETIME") or timedelta(hours=12)


def load_current_user() -> None:
    """``before_request`` hook: restore and validate the session user."""
    g.user = None
    user_id = session.get(SESSION_USER_KEY)
    if not user_id:
        return

    lifetime = session_lifetime()
    issued = _parse_iso(session.get(SESSION_ISSUED_AT)) or _parse_iso(session.get(SESSION_AUTH_TIME))
    now = utcnow()
    if issued is None or now - issued > lifetime:
        logout_user()
        flash("Your session expired. Please sign in again.", "warning")
        return

    user = db.session.get(User, user_id)
    if user is None or not user.is_active:
        logout_user()
        return
    # Server-side session validation: a rotated token invalidates old sessions.
    if not session.get(SESSION_TOKEN_KEY) or session.get(SESSION_TOKEN_KEY) != user.session_token:
        logout_user()
        flash("Your session is no longer valid. Please sign in again.", "warning")
        return

    g.user = user
    # Sliding idle timeout: extend the session while it is actively used.
    last_seen = _parse_iso(session.get(SESSION_LAST_SEEN))
    touch_interval = int(current_app.config.get("SESSION_TOUCH_INTERVAL_SECONDS", 300))
    if last_seen is None or (now - last_seen).total_seconds() > touch_interval:
        session[SESSION_LAST_SEEN] = now.isoformat()
        session.modified = True


def wants_json() -> bool:
    if request.path.startswith("/api/"):
        return True
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return True
    accept = request.accept_mimetypes
    return accept["application/json"] >= accept["text/html"] and accept["application/json"] > 0


def login_required(view):
    """Require an authenticated session; JSON requests receive 401."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            if wants_json():
                return jsonify({"error": "authentication_required"}), 401
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("auth.login", next=request.full_path if request.method == "GET" else None))
        return view(*args, **kwargs)

    return wrapper


def generate_csrf_token() -> str:
    """Expose a CSRF token to templates that are not WTForms-based."""
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def json_error(message: str, status: int, code: str = "error"):
    return jsonify({"error": code, "message": message}), status
