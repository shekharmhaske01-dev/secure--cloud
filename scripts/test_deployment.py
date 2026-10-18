#!/usr/bin/env python3
"""Test a deployed SecureCloud instance end-to-end.

Usage:
    python scripts/test_deployment.py [URL]

Defaults to http://localhost:8000 if no URL is given.  The script exercises:
  - Health check  (/healthz)
  - User registration and login
  - File upload, download, and integrity verification
  - File deletion

Exit code 0 = all tests passed; 1 = at least one failure.
"""
from __future__ import annotations

import hashlib
import os
import re
import sys

try:
    import requests
except ImportError:
    sys.exit("ERROR: 'requests' is not installed.  Run: pip install requests")


class DeploymentTester:
    """Stateful tester that keeps a session cookie across requests."""

    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.session = requests.Session()
        self.passed = 0
        self.failed = 0

    # --- helpers ----------------------------------------------------------

    def _extract_csrf(self, html: str) -> str:
        m = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)', html)
        return m.group(1) if m else ""

    def _report(self, name: str, ok: bool, detail: str = ""):
        status = "PASS" if ok else "FAIL"
        msg = f"  [{status}] {name}"
        if detail:
            msg += f"  ({detail})"
        print(msg)
        if ok:
            self.passed += 1
        else:
            self.failed += 1

    # --- tests ------------------------------------------------------------

    def test_health(self):
        try:
            r = self.session.get(f"{self.base}/healthz", timeout=10)
            self._report("Health check", r.status_code == 200, f"status={r.status_code}")
        except Exception as e:
            self._report("Health check", False, str(e))

    def test_register(self):
        # Get the registration page (for CSRF)
        r = self.session.get(f"{self.base}/auth/register", timeout=10)
        csrf = self._extract_csrf(r.text)
        r = self.session.post(
            f"{self.base}/auth/register",
            data={
                "csrf_token": csrf,
                "username": "deploy_test_user",
                "email": "deploy_test@example.com",
                "password": "DeployTest!123",
                "confirm_password": "DeployTest!123",
            },
            allow_redirects=True,
            timeout=10,
        )
        ok = r.status_code == 200 and b"deploy_test" in r.content.lower()
        self._report("User registration", ok, f"status={r.status_code}")

    def test_login(self):
        r = self.session.get(f"{self.base}/auth/login", timeout=10)
        csrf = self._extract_csrf(r.text)
        r = self.session.post(
            f"{self.base}/auth/login",
            data={
                "csrf_token": csrf,
                "email": "deploy_test@example.com",
                "password": "DeployTest!123",
            },
            allow_redirects=True,
            timeout=10,
        )
        ok = r.status_code == 200
        self._report("User login", ok, f"status={r.status_code}")

    def test_upload_download(self):
        # Upload
        r = self.session.get(f"{self.base}/files/upload", timeout=10)
        csrf = self._extract_csrf(r.text)
        test_data = os.urandom(8192)
        test_sha = hashlib.sha256(test_data).hexdigest()

        r = self.session.post(
            f"{self.base}/files/upload",
            data={"csrf_token": csrf},
            files={"file": ("deploy_test.bin", test_data, "application/octet-stream")},
            allow_redirects=True,
            timeout=30,
        )
        upload_ok = r.status_code == 200
        self._report("File upload", upload_ok, f"status={r.status_code}")

        if not upload_ok:
            self._report("File download", False, "skipped (upload failed)")
            self._report("File integrity", False, "skipped (upload failed)")
            return

        # Find the file ID from the listing or redirect URL
        m = re.search(r'/files/(\d+)', r.url or r.text)
        if not m:
            # Try listing
            r2 = self.session.get(f"{self.base}/files/", timeout=10)
            m = re.search(r'/files/(\d+)', r2.text)

        if not m:
            self._report("File download", False, "could not find file ID")
            return

        file_id = m.group(1)

        # Download
        r = self.session.get(f"{self.base}/files/{file_id}/download", timeout=30)
        download_ok = r.status_code == 200 and len(r.content) == len(test_data)
        self._report("File download", download_ok, f"status={r.status_code} size={len(r.content)}")

        if download_ok:
            dl_sha = hashlib.sha256(r.content).hexdigest()
            self._report("File integrity", test_sha == dl_sha, f"match={test_sha == dl_sha}")

    def test_delete(self):
        r = self.session.get(f"{self.base}/files/", timeout=10)
        m = re.search(r'/files/(\d+)', r.text)
        if not m:
            self._report("File delete", False, "no files to delete")
            return

        file_id = m.group(1)
        r = self.session.get(f"{self.base}/files/{file_id}", timeout=10)
        csrf = self._extract_csrf(r.text)
        r = self.session.post(
            f"{self.base}/files/{file_id}/delete",
            data={"csrf_token": csrf},
            allow_redirects=True,
            timeout=15,
        )
        self._report("File delete", r.status_code == 200, f"status={r.status_code}")

    # --- runner -----------------------------------------------------------

    def run_all(self) -> int:
        print(f"\nSecureCloud Deployment Tests — {self.base}\n{'=' * 50}")
        self.test_health()
        self.test_register()
        self.test_login()
        self.test_upload_download()
        self.test_delete()
        print(f"\n{'=' * 50}")
        print(f"Results: {self.passed} passed, {self.failed} failed")
        return 0 if self.failed == 0 else 1


def main():
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    tester = DeploymentTester(url)
    sys.exit(tester.run_all())


if __name__ == "__main__":
    main()
