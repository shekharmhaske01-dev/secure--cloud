"""SecureCloud - WSGI / CLI entry point.

Run in development:
    python app.py

Run in production (Linux):
    gunicorn app:app --config gunicorn.conf.py

Flask CLI:
    flask --app app init-db
    flask --app app check-storage
"""
from __future__ import annotations

import os

from securecloud import create_app

# Environment selection: development | testing | production
app = create_app(os.getenv("FLASK_CONFIG") or os.getenv("SECURECLOUD_ENV") or "development")


if __name__ == "__main__":  # pragma: no cover - manual development entry point
    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=app.config.get("DEBUG", False),
        use_reloader=app.config.get("DEBUG", False),
    )
