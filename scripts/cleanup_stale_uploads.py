"""Recover unfinished uploads and retry pending object cleanup.

Usage:
    python scripts/cleanup_stale_uploads.py
    python scripts/cleanup_stale_uploads.py --minutes 30 --hard-delete
    python scripts/cleanup_stale_uploads.py --report

What it does (safe to run repeatedly):
  1. Retries every pending/failed cleanup job (orphaned objects from failed
     uploads or partial deletions).
  2. Recovers uploads that never completed: the objects they created are
     deleted and their metadata row is marked failed.
  3. Removes abandoned staging files and leftover plaintext download files.
  4. With --hard-delete, also removes the metadata rows of recovered failed
     uploads once their objects are confirmed gone.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from securecloud import create_app  # noqa: E402
from securecloud.services import cleanup_service  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Clean up unfinished SecureCloud uploads.")
    parser.add_argument("--config", default=os.getenv("FLASK_CONFIG", "development"))
    parser.add_argument("--minutes", type=int, default=None,
                        help="age threshold for 'stale' upload records (default from config)")
    parser.add_argument("--hard-delete", action="store_true",
                        help="delete metadata rows of recovered failed uploads")
    parser.add_argument("--report", action="store_true",
                        help="only print the current recovery counters")
    parser.add_argument("--json", action="store_true", help="print machine-readable output")
    args = parser.parse_args(argv)

    app = create_app(args.config)
    with app.app_context():
        if args.report:
            summary = cleanup_service.recovery_summary()
            if args.json:
                print(json.dumps(summary, indent=2))
            else:
                print("SecureCloud recovery status")
                for key, value in summary.items():
                    print(f"  {key.replace('_', ' ')}: {value}")
            return 0

        result = cleanup_service.run_maintenance(minutes=args.minutes, hard_delete=args.hard_delete)

    if args.json:
        print(json.dumps(result, indent=2, default=str))
        return 0

    print("SecureCloud maintenance run")
    jobs = result["cleanup_jobs"]
    print(f"  cleanup jobs processed : {jobs['jobs']}")
    print(f"  objects deleted        : {jobs['objects_deleted']}")
    print(f"  objects already absent : {jobs['objects_missing']}")
    print(f"  objects still failing  : {jobs['still_failed']}")
    uploads = result["incomplete_uploads"]
    print(f"  unfinished uploads     : {uploads['count']} recovered")
    for item in uploads["recovered"][:10]:
        print(f"    - id={item['file_id']} {item['filename']!r} -> {item['status']}")
    print(f"  staging files removed  : {len(result['staging']['removed'])}")
    print(f"  temp downloads removed : {len(result['download_temp']['removed'])}")
    if jobs["still_failed"]:
        print()
        print("  Some objects could not be deleted. SecureCloud recorded them in")
        print("  cleanup_jobs and will retry; check object-storage permissions.")
        return 1
    print("\nDone. No file was reported as stored while blocks were missing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
