"""Create the metadata database schema.

Safe to run repeatedly: it only creates tables that do not exist yet.  It never
drops, truncates or deletes an existing database, so previously stored files and
wrapped-key records are preserved.

Usage (from the project root, virtual environment activated):
    python scripts/init_db.py
    python scripts/init_db.py --check-only
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import inspect  # noqa: E402

from config import get_config  # noqa: E402
from securecloud import create_app  # noqa: E402
from securecloud.extensions import db  # noqa: E402

EXPECTED_TABLES = (
    "users",
    "stored_files",
    "encrypted_blocks",
    "wrapped_keys",
    "storage_operations",
    "cleanup_jobs",
)


def describe_uri(uri: str) -> str:
    if uri.startswith("sqlite:///"):
        path = uri[len("sqlite:///"):]
        return f"SQLite file: {os.path.abspath(path)}"
    return "configured database"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Initialise the SecureCloud metadata database.")
    parser.add_argument("--config", default=os.getenv("FLASK_CONFIG", "development"),
                        help="configuration name: development | testing | production")
    parser.add_argument("--check-only", action="store_true",
                        help="report the current schema without creating anything")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    config_class = get_config(args.config)
    app = create_app(args.config)

    print(f"SecureCloud database initialisation ({args.config} environment)")
    print(f"  {describe_uri(app.config['SQLALCHEMY_DATABASE_URI'])}")

    with app.app_context():
        inspector = inspect(db.engine)
        before = sorted(inspector.get_table_names())
        if before:
            print(f"  existing tables: {', '.join(before)}")
        else:
            print("  existing tables: (none - a new database will be created)")

        if args.check_only:
            missing = [t for t in EXPECTED_TABLES if t not in before]
            print(f"  missing tables: {', '.join(missing) if missing else 'none'}")
            return 0 if not missing else 1

        db.create_all()
        after = sorted(inspect(db.engine).get_table_names())

    created = [t for t in after if t not in before]
    print(f"  created tables: {', '.join(created) if created else 'none (already up to date)'}")
    print("  existing data was preserved - no table was dropped or emptied.")

    missing = [t for t in EXPECTED_TABLES if t not in after]
    if missing:
        print(f"  ERROR: expected tables are still missing: {', '.join(missing)}")
        return 1

    if args.verbose:
        for table in after:
            print(f"  - {table}")
    print("Metadata database is ready.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
