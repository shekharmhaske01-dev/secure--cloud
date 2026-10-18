"""Generate cryptographic secrets for SecureCloud.

Two modes:

1. Key-encryption key (KEK) - used only to wrap/unwrap per-file data keys::

       python scripts/generate_encryption_key.py

   Writes nothing by default: it prints the base64 value plus the exact line to
   paste into your ``.env`` (and warns where to back it up).  Add ``--write-env``
   to append/update the variable in ``.env`` locally.

2. Flask session secret::

       python scripts/generate_encryption_key.py --secret

Neither value is ever committed, logged or printed by the application itself.
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import BASE_DIR  # noqa: E402
from securecloud.services.key_manager import (  # noqa: E402
    KEK_ENV_VAR,
    generate_kek_b64,
    generate_secret_key,
    validate_kek,
)

WARNING = """
IMPORTANT - BACK UP THIS KEY NOW
  * The key-encryption key lives OUTSIDE the database and OUTSIDE object storage.
  * It is the only way to unwrap the per-file data keys.
  * If it is lost, every file stored with it becomes PERMANENTLY UNRECOVERABLE.
  * Store it in a password manager or a secret manager (never in Git, never in a
    screenshot, never in the README or report).
  * Use the same key for every instance that must read the same stored files.
"""


def update_env_file(path: str, name: str, value: str) -> str:
    """Set ``name=value`` in the .env file, preserving other lines."""
    lines: list[str] = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    replaced = False
    for index, line in enumerate(lines):
        if line.strip().startswith(f"{name}="):
            lines[index] = f"{name}={value}"
            replaced = True
            break
    if not replaced:
        if lines and lines[-1].strip():
            lines.append("")
        lines.append(f"{name}={value}")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a SecureCloud secret.")
    parser.add_argument("--secret", action="store_true",
                        help="generate a Flask SECRET_KEY instead of a KEK")
    parser.add_argument("--write-env", action="store_true",
                        help="write the generated value into the local .env file")
    parser.add_argument("--count", type=int, default=1, help="how many keys to print")
    args = parser.parse_args(argv)

    if args.secret:
        value = generate_secret_key()
        name = "SECRET_KEY"
        print("Generated Flask session secret (SECRET_KEY).")
    else:
        value = generate_kek_b64()
        name = KEK_ENV_VAR
        status = validate_kek(value)
        if not status.valid:  # pragma: no cover - only if the module is broken
            print(f"ERROR: generated key failed self-validation: {status.message}")
            return 1
        print("Generated key-encryption key (AES-256, base64 of 32 random bytes).")
        print(f"  self-check: {status.message}")
        print(f"  fingerprint: {status.fingerprint}")

    for _ in range(max(args.count, 1)):
        print()
        print(f"{name}={value}")

    if args.write_env:
        env_path = os.path.join(BASE_DIR, ".env")
        if not os.path.exists(env_path):
            template = os.path.join(BASE_DIR, ".env.example")
            if os.path.exists(template):
                with open(template, "r", encoding="utf-8") as src, open(env_path, "w", encoding="utf-8") as dst:
                    dst.write(src.read())
                print(f"\nCreated {env_path} from .env.example.")
        update_env_file(env_path, name, value)
        print(f"Wrote {name} to {env_path} (file permissions restricted). Make sure .env stays out of version control.")
    else:
        print("\nAdd the line above to your .env file (never commit it).")

    if not args.secret:
        print(WARNING)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
