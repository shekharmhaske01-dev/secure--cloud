# Testing Guide

Comprehensive testing documentation for SecureCloud.

---

## Overview

SecureCloud uses **pytest** for all testing. The test suite covers unit tests,
integration tests, and end-to-end pipeline tests.

---

## Running Tests

### Prerequisites

```bash
pip install -r requirements-dev.txt
```

### Run All Tests

```bash
pytest
```

### Run with Verbose Output

```bash
pytest -v
```

### Run a Specific Test File

```bash
pytest tests/test_full_pipeline.py -v
```

### Run a Specific Test Class or Function

```bash
pytest tests/test_full_pipeline.py::TestUploadDownloadRoundTrip -v
pytest tests/test_full_pipeline.py::TestUploadDownloadRoundTrip::test_download_matches_original -v
```

### Run with Coverage Report

```bash
# Terminal report
pytest --cov=securecloud --cov-report=term-missing

# HTML report (opens in browser)
pytest --cov=securecloud --cov-report=html
open htmlcov/index.html
```

---

## Test Categories

### `test_auth.py` — Authentication

Tests user registration, login, logout, and session handling.

| Test | What it verifies |
|------|-----------------|
| Registration with valid data | User created, redirected |
| Registration with duplicate email | Error displayed |
| Login with correct credentials | Session established |
| Login with wrong password | Access denied |
| Logout | Session cleared |

### `test_crypto.py` — Encryption Engine

Tests the AES-256-GCM encryption and decryption functions directly.

| Test | What it verifies |
|------|-----------------|
| Encrypt/decrypt round-trip | Data matches after decrypt |
| Wrong key fails | Decryption raises error |
| Wrong AAD fails | Authentication tag invalid |
| Nonce uniqueness | Each encryption produces unique nonce |
| Block format version | Correct version in AAD |

### `test_chunking.py` — File Block Splitting

Tests the file chunking and reassembly logic.

| Test | What it verifies |
|------|-----------------|
| Small file → single block | Only 1 block produced |
| Large file → multiple blocks | Correct number of blocks |
| Exact block size boundary | Edge case handled |
| Reassembly matches original | Concatenated blocks = original |

### `test_storage.py` — Storage Backends

Tests the storage abstraction layer operations.

| Test | What it verifies |
|------|-----------------|
| Upload object | Returns key, size, etag |
| Download object | Returns original bytes |
| Delete object | Object removed |
| Object info (exists) | Correct metadata |
| Object info (missing) | `exists=False` |
| List objects | Correct keys returned |
| Health check | Probe write/read/delete |

### `test_files_flow.py` — Upload/Download Flow

Tests the web-layer file upload and download through the Flask test client.

| Test | What it verifies |
|------|-----------------|
| Upload via form | File created in DB |
| Download after upload | Content matches |
| File listing shows upload | Filename in listing |

### `test_full_pipeline.py` — End-to-End Pipeline

Comprehensive tests covering the full lifecycle.

| Test | What it verifies |
|------|-----------------|
| Upload small file | DB record created, correct size |
| Upload multi-block file | Multiple EncryptedBlock records |
| Download matches original | Byte-for-byte identical |
| Download integrity (SHA-256) | Hash verification |
| Various MIME types | .txt, .pdf, .jpg round-trip |
| Encrypted blocks exist | Blocks present in storage |
| Blocks are not plaintext | Ciphertext ≠ plaintext |
| Decryption produces original | Full crypto round-trip |
| Delete removes blocks | Storage objects deleted |
| Delete updates metadata | Status = DELETED |
| File listing | All uploads shown |
| File details page | Correct info displayed |
| Block reconstruction | Manual reassembly works |
| Unauthorized access blocked | User B can't get User A's file |
| Exact block boundary | 4096 bytes → 1 block |
| One byte over block | 4097 bytes → 2 blocks |
| Very small file | 1 byte file works |

### `test_integrity.py` — Data Integrity

Tests SHA-256 hash verification and corruption detection.

### `test_key_manager.py` — Key Management

Tests KEK/DEK wrapping, unwrapping, and key rotation.

### `test_authorization.py` — Access Control

Tests that users can only access their own files.

### `test_configuration.py` — Configuration

Tests that configuration loading and validation works correctly.

---

## Test Fixtures (conftest.py)

The shared `conftest.py` provides these fixtures:

| Fixture | Scope | Description |
|---------|-------|-------------|
| `app` | function | Fresh Flask app with TestingConfig, in-memory SQLite |
| `client` | function | Flask test client from `app` |
| `alice` | function | Pre-registered and logged-in test client |

### Helper Functions

| Function | Description |
|----------|-------------|
| `register(client, username, email, password)` | Register a new user |
| `login(client, email, password)` | Log in an existing user |
| `upload_bytes(client, data, filename, content_type)` | Upload raw bytes as a file |
| `get_csrf(client, url)` | GET a page and extract the CSRF token |

### Test Configuration

Tests use `TestingConfig` which sets:
- `TESTING = True` — enables test mode
- `SQLALCHEMY_DATABASE_URI = "sqlite://"` — in-memory database
- `RATELIMIT_ENABLED = False` — disables rate limiting
- `BLOCK_SIZE = 4096` — small blocks for fast tests
- `WTF_CSRF_ENABLED = True` — CSRF is tested too

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install -r requirements.txt -r requirements-dev.txt
      - run: pytest --cov=securecloud --cov-report=xml
      - uses: codecov/codecov-action@v4
        with:
          file: coverage.xml
```

### Pre-commit Hook

```bash
# .git/hooks/pre-commit
#!/bin/sh
pytest tests/ -x -q || exit 1
```

---

## Writing New Tests

1. Place test files in `tests/` with the `test_` prefix
2. Use the shared fixtures from `conftest.py`
3. Follow existing patterns for CSRF-protected endpoints
4. For multi-user tests, register additional users (bob, charlie, etc.)
5. Always verify both success and failure paths
