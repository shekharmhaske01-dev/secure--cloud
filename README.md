# SecureCloud

**Encrypted, chunked cloud file storage built with Flask.**

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)](https://python.org)
[![Flask 3.x](https://img.shields.io/badge/flask-3.x-green)](https://flask.palletsprojects.com)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow)](LICENSE)

---

## Overview

SecureCloud is a secure file storage application that encrypts files using **AES-256-GCM** with **envelope encryption** before storing them across configurable backends. Files are split into fixed-size blocks, individually encrypted, and can be stored on the local filesystem, S3-compatible object stores (AWS S3, MinIO, Neon), or HDFS clusters.

```
┌───────────────────────────────────────────────────────┐
│                    SecureCloud                        │
│                                                       │
│  ┌─────────┐   ┌───────────────┐   ┌───────────────┐ │
│  │  Flask   │──▶│  Encryption   │──▶│   Storage     │ │
│  │  Web UI  │   │  AES-256-GCM  │   │   Backend     │ │
│  └─────────┘   │  Envelope     │   │               │ │
│       │        │  Encryption   │   │  ┌─────────┐  │ │
│       ▼        └───────────────┘   │  │  Local   │  │ │
│  ┌─────────┐                       │  │  S3/Neon │  │ │
│  │ SQLite  │◀──  Metadata          │  │  HDFS    │  │ │
│  │   DB    │     (file records,    │  └─────────┘  │ │
│  └─────────┘      block keys)      └───────────────┘ │
└───────────────────────────────────────────────────────┘
```

## Features

- 🔐 **AES-256-GCM Encryption** — Military-grade authenticated encryption per block
- 🔑 **Envelope Encryption** — Per-file DEK wrapped by a master KEK
- 📦 **Chunked Storage** — Large files split into configurable blocks (default 1 MB)
- 🗄️ **Multiple Backends** — Local filesystem, S3-compatible, HDFS
- 🔒 **Argon2id Password Hashing** — State-of-the-art password security
- 🛡️ **CSRF Protection** — All state-changing operations protected
- 🚦 **Rate Limiting** — Configurable per-endpoint throttling
- 🐳 **Docker Ready** — Full Docker Compose setup with optional HDFS
- ✅ **Comprehensive Tests** — pytest suite with end-to-end pipeline tests
- ☁️ **Free Deployment** — Configs for Render, Fly.io, and Railway

## Prerequisites

- **Python 3.12+**
- **pip** (Python package manager)
- **Docker Desktop** (optional, for containerised deployment)

## Quick Start

### 1. Clone and install

```bash
git clone <repository-url>
cd SecureCloud
python -m venv venv
source venv/bin/activate          # Linux/macOS
# venv\Scripts\activate           # Windows
pip install -r requirements.txt
pip install -r requirements-dev.txt   # for testing
```

### 2. Generate configuration

```bash
python scripts/generate_env.py
```

Or manually:

```bash
cp .env.example .env
# Edit .env — set SECRET_KEY and SECURECLOUD_KEY_ENCRYPTION_KEY
python scripts/generate_encryption_key.py   # generates a KEK
```

### 3. Initialise the database

```bash
python scripts/init_db.py
```

### 4. Run

```bash
# Development
flask run --debug

# Production
gunicorn app:app --config gunicorn.conf.py
```

Visit **http://localhost:8000** (gunicorn) or **http://localhost:5000** (flask dev).

## Docker Deployment

### Basic (local storage)

```bash
docker compose up -d --build
```

### With HDFS distributed storage

```bash
docker compose -f docker-compose.yml -f docker-compose.hdfs.yml up -d --build

# Wait for HDFS to initialise, then:
python scripts/setup_hdfs.py
```

### With MinIO (S3-compatible)

The default `docker-compose.yml` includes a MinIO service:

```bash
docker compose up -d --build
# MinIO console: http://localhost:9001 (user: minioadmin / pass: minioadmin)
```

## HDFS Integration

SecureCloud supports Apache Hadoop HDFS as a distributed storage backend:

```bash
# Set in .env:
SECURECLOUD_STORAGE_BACKEND=hdfs
HDFS_NAMENODE_URL=http://namenode:9870
HDFS_USER=root
HDFS_ROOT_PATH=/securecloud

# Or use Docker:
docker compose -f docker-compose.yml -f docker-compose.hdfs.yml up -d
```

See [docs/HDFS_GUIDE.md](docs/HDFS_GUIDE.md) for the full guide.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | *(required)* | Flask secret key for sessions |
| `SECURECLOUD_KEY_ENCRYPTION_KEY` | *(required)* | Base64-encoded 32-byte master KEK |
| `FLASK_ENV` | `development` | `development` / `production` |
| `SECURECLOUD_STORAGE_BACKEND` | `local` | `local`, `s3`, `hdfs` |
| `SECURECLOUD_BLOCK_SIZE` | `1048576` | Block size in bytes (min 4096) |
| `SECURECLOUD_MAX_UPLOAD_BYTES` | `268435456` | Max upload size (256 MB) |
| `DATABASE_URL` | `sqlite:///instance/securecloud.db` | Database connection string |
| `HDFS_NAMENODE_URL` | *(empty)* | WebHDFS NameNode URL |
| `HDFS_USER` | `root` | HDFS user |
| `HDFS_ROOT_PATH` | `/securecloud` | HDFS root directory |
| `NEON_STORAGE_ENDPOINT_URL` | *(empty)* | S3 endpoint URL |
| `NEON_STORAGE_BUCKET` | *(empty)* | S3 bucket name |
| `LOG_LEVEL` | `INFO` | Application log level |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Landing page |
| `GET` | `/healthz` | Health check (returns JSON) |
| `GET/POST` | `/auth/register` | User registration |
| `GET/POST` | `/auth/login` | User login |
| `GET` | `/auth/logout` | Logout |
| `GET` | `/dashboard` | User dashboard |
| `GET` | `/files/` | File listing |
| `GET/POST` | `/files/upload` | Upload a file |
| `GET` | `/files/<id>` | File details |
| `GET` | `/files/<id>/download` | Download (decrypts & reconstructs) |
| `POST` | `/files/<id>/delete` | Delete file and blocks |

## Security Architecture

- **Encryption:** AES-256-GCM with 96-bit nonces, per-block AAD
- **Key Management:** Envelope encryption — per-file Data Encryption Key (DEK) wrapped by master Key Encryption Key (KEK)
- **Authentication:** Argon2id password hashing with automatic parameter tuning
- **Sessions:** HMAC-signed cookies, configurable lifetime, secure flags
- **CSRF:** Double-submit token on all POST endpoints
- **Headers:** Strict CSP, X-Frame-Options, X-Content-Type-Options, HSTS

See [docs/SECURITY.md](docs/SECURITY.md) for the full security analysis.

## Testing

```bash
# Run all tests
pytest

# With coverage
pytest --cov=securecloud --cov-report=html

# Specific test file
pytest tests/test_full_pipeline.py -v
```

**Test categories:**
- `test_auth.py` — Registration, login, logout
- `test_crypto.py` — AES-256-GCM encryption/decryption
- `test_chunking.py` — File chunking and reassembly
- `test_storage.py` — Storage backend operations
- `test_files_flow.py` — Upload/download flow
- `test_full_pipeline.py` — End-to-end pipeline (upload → encrypt → store → download → decrypt → verify)
- `test_integrity.py` — Data integrity verification
- `test_key_manager.py` — KEK/DEK management
- `test_authorization.py` — Access control

See [docs/TESTING.md](docs/TESTING.md) for details.

## Free Hosting Deployment

### Render.com
```bash
# Push to GitHub, then connect in Render Dashboard
# render.yaml is auto-detected
# Set SECURECLOUD_KEY_ENCRYPTION_KEY in environment variables
```

### Fly.io
```bash
fly launch --config fly.toml
fly volumes create securecloud_data --size 1 --region iad
fly secrets set SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
fly secrets set SECURECLOUD_KEY_ENCRYPTION_KEY=$(python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())")
fly deploy
```

### Railway
```bash
railway init
railway variables set SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
railway variables set SECURECLOUD_KEY_ENCRYPTION_KEY=$(python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())")
railway up
```

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the full deployment guide.

## Project Structure

```
SecureCloud/
├── app.py                      # Application entry point
├── config.py                   # Configuration classes
├── extensions.py               # Flask extension instances
├── Dockerfile                  # Container build
├── docker-compose.yml          # Docker (app + MinIO)
├── docker-compose.hdfs.yml     # HDFS overlay
├── hadoop.env                  # Hadoop environment
├── Procfile                    # PaaS process file
├── gunicorn.conf.py            # Gunicorn configuration
├── render.yaml                 # Render.com blueprint
├── fly.toml                    # Fly.io configuration
├── railway.json                # Railway configuration
├── requirements.txt            # Runtime dependencies
├── requirements-dev.txt        # Dev/test dependencies
│
├── securecloud/                # Application package
│   ├── __init__.py             # App factory
│   ├── models.py               # SQLAlchemy models
│   ├── errors.py               # Error handlers
│   ├── security.py             # Security headers
│   ├── utils.py                # Utility functions
│   │
│   ├── auth/                   # Authentication blueprint
│   ├── dashboard/              # Dashboard blueprint
│   ├── files/                  # File operations blueprint
│   │
│   ├── services/               # Business logic layer
│   │   ├── encryption.py       # AES-256-GCM encryption
│   │   ├── chunking.py         # File block splitting
│   │   ├── file_service.py     # File orchestration
│   │   ├── storage_service.py  # Storage coordination
│   │   ├── key_manager.py      # KEK/DEK management
│   │   ├── integrity.py        # Data integrity checks
│   │   └── cleanup_service.py  # Stale upload cleanup
│   │
│   ├── storage/                # Storage abstraction layer
│   │   ├── base.py             # Abstract base class
│   │   ├── local_storage.py    # Local filesystem backend
│   │   ├── s3_storage.py       # S3-compatible backend
│   │   └── hdfs_storage.py     # HDFS distributed backend
│   │
│   ├── templates/              # Jinja2 HTML templates
│   └── static/                 # CSS, JS, images
│
├── tests/                      # Test suite
│   ├── conftest.py             # Shared fixtures
│   ├── test_full_pipeline.py   # End-to-end tests
│   └── ...                     # Unit/integration tests
│
├── scripts/                    # Utility scripts
│   ├── deploy.sh               # Deployment helper
│   ├── generate_env.py         # .env generator
│   ├── generate_encryption_key.py
│   ├── setup_hdfs.py           # HDFS initialisation
│   ├── init_db.py              # Database setup
│   ├── test_deployment.py      # Deployment verification
│   └── ...
│
├── docs/                       # Documentation
│   ├── ARCHITECTURE.md
│   ├── DEPLOYMENT.md
│   ├── HDFS_GUIDE.md
│   ├── SECURITY.md
│   └── TESTING.md
│
├── instance/                   # SQLite database (gitignored)
└── staging/                    # Temporary files
```

## License

MIT License — see [LICENSE](LICENSE) for details.
