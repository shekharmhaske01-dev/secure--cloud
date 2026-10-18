"""Verify object-storage configuration and connectivity.

Usage:
    python scripts/check_storage.py
    python scripts/check_storage.py --config production
    python scripts/check_storage.py --round-trip      # write/read/delete a test object

The round-trip test uploads a small AES-GCM encrypted probe (never plaintext
data of yours) and deletes it again, so it also proves read/write/delete
permissions on the configured bucket.
"""
from __future__ import annotations

import argparse
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from securecloud import create_app  # noqa: E402
from securecloud.services import encryption  # noqa: E402
from securecloud.services.storage_service import get_storage_service  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check SecureCloud object storage.")
    parser.add_argument("--config", default=os.getenv("FLASK_CONFIG", "development"))
    parser.add_argument("--round-trip", action="store_true",
                        help="store, fetch and delete an encrypted probe object")
    args = parser.parse_args(argv)

    app = create_app(args.config)
    with app.app_context():
        service = get_storage_service()
        desc = service.description

        print("SecureCloud object-storage check")
        print(f"  backend      : {desc.backend}")
        print(f"  provider     : {desc.display_name}")
        print(f"  kind         : {desc.kind_label}")
        print(f"  configured   : {'yes' if desc.configured else 'no'}")
        print(f"  bucket       : {desc.bucket}")
        print(f"  region       : {desc.region}")
        print(f"  endpoint     : {desc.endpoint}")
        print(f"  addressing   : {desc.addressing_style} (path-style is required by Neon Object Storage)")
        print(f"  prefix       : {desc.prefix or '(none)'}")
        if not desc.configured:
            print(f"  missing      : {', '.join(desc.missing_settings)}")
        for note in desc.notes:
            print(f"  note         : {note}")
        print()

        health = service.health_check()
        print(f"Connectivity: {'OK' if health['ok'] else 'FAILED'} - {health['message']}")
        for key, value in (health.get("details") or {}).items():
            print(f"  {key}: {value}")

        if not health["ok"]:
            print()
            print("Fix the configuration (see .env.example and README) and run this check again.")
            print("SecureCloud will not fall back to a different storage backend.")
            return 1

        if args.round_trip:
            print()
            print("Round-trip test (encrypted probe object):")
            probe_id = f"probe-{secrets.token_hex(6)}"
            dek = encryption.KeyManager.generate_data_key() if hasattr(encryption, "KeyManager") \
                else os.urandom(32)
            payload = b"SecureCloud storage probe " + secrets.token_bytes(32)
            nonce, ciphertext = encryption.encrypt_block(dek, payload, probe_id, 0)
            key = f"_healthcheck/{probe_id}.blk"
            try:
                stored = service.adapter.upload_object(key, ciphertext)
                print(f"  upload  : OK ({stored['size']} bytes, key={key})")
                fetched = service.adapter.download_object(key)
                print(f"  download: OK ({len(fetched)} bytes)")
                if fetched != ciphertext:
                    print("  MISMATCH: retrieved object differs from the uploaded object")
                    return 1
                plaintext = encryption.decrypt_block(dek, nonce, fetched, probe_id, 0)
                print(f"  decrypt : OK ({len(plaintext)} bytes, tag verified)")
                info = service.adapter.object_info(key)
                print(f"  head    : exists={info.get('exists')} size={info.get('size')}")
                removed = service.adapter.delete_object(key)
                print(f"  delete  : {'OK' if removed else 'object was already absent'}")
                remaining = service.adapter.object_info(key)
                print(f"  verify  : exists={remaining.get('exists')} (expected False)")
            except Exception as exc:
                print(f"  FAILED: {getattr(exc, 'public_message', type(exc).__name__)}")
                return 1

        print()
        print("Object storage is usable." if not desc.is_local else
              "Local development storage is usable (not cloud object storage).")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
