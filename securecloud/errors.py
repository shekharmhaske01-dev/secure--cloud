"""Error handling: safe error pages for HTML and clean JSON for API clients.

No handler ever returns exception text, stack traces, database messages,
filesystem paths or secret values to the browser - the detail is logged
server-side instead.  JSON responses carry a stable machine-readable ``error``
code (the error category where one is known) plus a human ``title``.
"""
from __future__ import annotations

import logging

from flask import flash, redirect, url_for, current_app, jsonify, render_template, request
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge

from securecloud.security import wants_json
from securecloud.services import SecureCloudError
from securecloud.storage import (
    StorageAccessDeniedError,
    StorageAuthenticationError,
    StorageNotConfiguredError,
    StorageObjectNotFoundError,
    StorageTimeoutError,
    StorageUnavailableError,
)

logger = logging.getLogger("securecloud.errors")

ERROR_PAGES = {
    400: ("Bad request", "The request could not be understood. Please check the form and try again."),
    403: ("Access denied", "You do not have permission to access this resource."),
    404: ("Page not found", "The page or file you requested does not exist."),
    413: ("File too large", "The uploaded file exceeds the configured size limit."),
    429: ("Too many requests", "You have made too many requests. Please wait a moment and try again."),
    500: ("Something went wrong", "An unexpected error occurred. Please try again later."),
    503: ("Service unavailable", "The service is temporarily unavailable. Please try again shortly."),
}


def _render_error(status: int, title: str, message: str, *, code: str | None = None,
                  template: str | None = None, extra: dict | None = None):
    """Render a safe error response (JSON for API callers, HTML otherwise)."""
    details = dict(extra or {})
    error_code = code or details.get("category") or f"http_{status}"
    if wants_json():
        return jsonify({
            "error": error_code,
            "title": title,
            "status": status,
            "message": message,
            "details": details,
        }), status
    ctx = {
        "status_code": status,
        "error_title": title,
        "error_message": message,
        "details": details,
    }
    return render_template(template or "errors/error_page.html", **ctx), status


def register_error_handlers(app) -> None:
    """Attach handlers for HTTP errors and application exceptions."""

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):  # noqa: ANN001
        # A visitor who is not signed in cannot have a session token to send, and
        # for a file endpoint the honest answer is "please sign in" rather than a
        # security-check error.  CSRF is still enforced for every signed-in
        # request and for all account forms.
        from flask import g, session

        # Only the session is trustworthy here: this handler runs from CSRFProtect's
        # before_request, which fires before the session loader, and a reused
        # application context can still carry the previous request's g.user.
        _ = g
        signed_in = session.get("user_id") is not None
        if not signed_in and str(request.endpoint or "").startswith("files."):
            flash("Please sign in to continue.", "info")
            return redirect(url_for("auth.login", next=request.path))
        logger.warning("CSRF validation failed: %s", error.description)
        return _render_error(
            400,
            "Security check failed",
            "Your session or form token was missing or expired. Reload the page and try again.",
            code="csrf_error",
        )

    @app.errorhandler(RequestEntityTooLarge)
    def handle_too_large(error):  # noqa: ANN001
        limit = current_app.config.get("MAX_CONTENT_LENGTH")
        message = "The uploaded file is larger than the configured limit."
        if limit:
            message = f"The uploaded file is larger than the configured limit of {limit // (1024 * 1024)} MiB."
        return _render_error(413, "File too large", message, code="file_too_large",
                             template="errors/413.html")

    @app.errorhandler(StorageNotConfiguredError)
    def handle_storage_config(error):  # noqa: ANN001
        logger.warning("Storage configuration problem: %s", error.detail or error.public_message)
        return _render_error(
            503,
            "Object storage is not configured",
            error.public_message,
            code=error.category,
            template="errors/storage_unavailable.html",
        )

    @app.errorhandler(StorageObjectNotFoundError)
    def handle_missing_object(error):  # noqa: ANN001
        logger.warning("Missing storage object: %s", error.detail or error.object_key)
        return _render_error(
            503,
            "A stored block is missing",
            error.public_message,
            code=error.category,
            template="errors/storage_unavailable.html",
        )

    @app.errorhandler(StorageAccessDeniedError)
    @app.errorhandler(StorageAuthenticationError)
    @app.errorhandler(StorageTimeoutError)
    @app.errorhandler(StorageUnavailableError)
    def handle_storage_unavailable(error):  # noqa: ANN001
        logger.warning("Storage failure (%s): %s", error.category, error.detail or error.public_message)
        return _render_error(
            503,
            "Object storage is unavailable",
            error.public_message,
            code=error.category,
            template="errors/storage_unavailable.html",
        )

    @app.errorhandler(SecureCloudError)
    def handle_domain_error(error: SecureCloudError):  # noqa: ANN001
        status = getattr(error, "http_status", 500) or 500
        logger.info("Handled application error (%s): %s", error.category,
                    error.detail or error.public_message)
        title, default_message = ERROR_PAGES.get(
            status, ("Request could not be completed", "Please try again.")
        )
        return _render_error(status, title, error.public_message or default_message,
                             code=error.category)

    @app.errorhandler(HTTPException)
    def handle_http_exception(error: HTTPException):  # noqa: ANN001
        status = error.code or 500
        title, message = ERROR_PAGES.get(status, (error.name, error.description))
        template = f"errors/{status}.html" if status in (400, 403, 404, 413, 429, 500) else None
        return _render_error(status, title, message, code=f"http_{status}", template=template)

    @app.errorhandler(Exception)
    def handle_unexpected(error: Exception):  # noqa: ANN001
        logger.exception("Unhandled exception while processing %s", request.path)
        return _render_error(
            500,
            "Something went wrong",
            "An unexpected error occurred and has been logged. No file data was modified.",
            code="internal_error",
            template="errors/500.html",
        )
