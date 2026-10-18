"""Registration, login, logout and session routes."""
from __future__ import annotations

import logging
from datetime import timedelta

from flask import (
    Blueprint,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError

from securecloud.auth.forms import LoginForm, RegistrationForm
from securecloud.extensions import db, limiter
from securecloud.models import User, utcnow
from securecloud.security import current_user, login_user, logout_user
from securecloud.utils import redact

logger = logging.getLogger("securecloud.auth")

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

GENERIC_LOGIN_ERROR = "Invalid username/email or password."
# A dummy hash keeps the response time of unknown accounts close to that of
# real ones, limiting username enumeration through timing.
_DUMMY_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$c2VjdXJlY2xvdWRkdW1teQ$"
    "Zm9yLXRpbWluZy1lcXVhbGlzYXRpb24tb25seS1ub3QtYS1yZWFsLWhhc2g"
)


def _safe_next_url(default_endpoint: str = "dashboard.index") -> str:
    """Only allow same-site relative redirect targets (no open redirect)."""
    target = request.args.get("next") or request.form.get("next")
    if not target:
        return url_for(default_endpoint)
    if target.startswith("//") or "://" in target or "\\" in target:
        return url_for(default_endpoint)
    if not target.startswith("/"):
        return url_for(default_endpoint)
    return target


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit(lambda: _rate("RATELIMIT_REGISTER", "5 per hour"), methods=["POST"])
def register():  # noqa: ANN202
    if current_user() is not None:
        flash("You are already signed in.", "info")
        return redirect(url_for("dashboard.index"))

    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        existing = User.query.filter(
            or_(func.lower(User.username) == username.lower(), func.lower(User.email) == email)
        ).first()
        if existing is not None:
            field = "username" if existing.username.lower() == username.lower() else "email"
            form_errors = {field: ["That value is already registered. Try signing in instead."]}
            flash("That account already exists. Please sign in instead.", "warning")
            return render_template("register.html", form=form, errors=form_errors), 409

        user = User(username=username, email=email)
        user.set_password(form.password.data)
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("That account already exists. Please sign in instead.", "warning")
            return render_template("register.html", form=form,
                                   errors={"username": ["Please choose different details."]}), 409
        logger.info("New account registered: id=%s", user.id)
        login_user(user)
        flash("Welcome to SecureCloud. Your account is ready.", "success")
        return redirect(url_for("dashboard.index"))

    if form.errors:
        flash("Please correct the highlighted fields.", "danger")
    return render_template("register.html", form=form, errors=form.errors)


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: _rate("RATELIMIT_LOGIN", "10 per minute"), methods=["POST"])
def login():  # noqa: ANN202
    if current_user() is not None:
        return redirect(url_for("dashboard.index"))

    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.username.data.strip()
        password = form.password.data
        user = User.query.filter(
            or_(func.lower(User.username) == identifier.lower(), func.lower(User.email) == identifier.lower())
        ).first()

        authenticated = False
        if user is not None and user.is_active:
            authenticated = user.check_password(password)
        else:
            # Constant-ish work for unknown accounts.
            User(username="x", email="x@example.invalid", password_hash=_DUMMY_HASH).check_password(password)

        if not authenticated:
            logger.warning("Failed sign-in attempt for %r", redact(identifier, 60))
            flash(GENERIC_LOGIN_ERROR, "danger")
            return render_template("login.html", form=form), 401

        if user.is_active is False:
            flash("This account is disabled.", "danger")
            return render_template("login.html", form=form), 403

        login_user(user)
        if form.remember.data:
            # A longer cookie lifetime is still bounded by the server-side
            # session record, which can be invalidated at any time.
            session.permanent = True
        user.touch_login()
        user.set_password(password)  # upgrades the hash if parameters changed
        db.session.commit()
        logger.info("Successful sign-in: user id=%s", user.id)
        flash("Signed in successfully.", "success")
        return redirect(_safe_next_url())

    if form.errors:
        flash(GENERIC_LOGIN_ERROR, "danger")
        return render_template("login.html", form=form), 400
    return render_template("login.html", form=form)


@auth_bp.route("/logout", methods=["POST", "GET"])
def logout():  # noqa: ANN202
    user = g.get("user")
    if user is not None:
        logger.info("Sign-out: user id=%s", user.id)
    logout_user()
    flash("You have been signed out.", "info")
    return redirect(url_for("dashboard.index"))


@auth_bp.route("/session")
def session_info():  # noqa: ANN202
    """Small diagnostics endpoint (no secrets, no internal identifiers)."""
    user = current_user()
    if user is None:
        return jsonify({"authenticated": False}), 401
    return jsonify({
        "authenticated": True,
        "username": user.username,
        "issued_at": session.get("issued_at"),
        "lifetime_hours": int(
            (timedelta(seconds=0) + _lifetime()).total_seconds() // 3600
        ),
    })


def _lifetime() -> timedelta:
    from flask import current_app

    return current_app.config.get("PERMANENT_SESSION_LIFETIME") or timedelta(hours=12)


def _rate(config_key: str, fallback: str) -> str:
    from flask import current_app

    return current_app.config.get(config_key) or fallback
