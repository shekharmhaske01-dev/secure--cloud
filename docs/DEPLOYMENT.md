# Deployment Guide

This guide covers deploying SecureCloud to various platforms.

---

## Table of Contents

1. [Local Development](#local-development)
2. [Docker Desktop](#docker-desktop)
3. [Docker with HDFS](#docker-with-hdfs)
4. [Render.com (Free)](#rendercom)
5. [Fly.io (Free)](#flyio)
6. [Railway (Free)](#railway)
7. [Production Checklist](#production-checklist)
8. [Persistent Storage](#persistent-storage)
9. [Backup & Restore](#backup--restore)

---

## Local Development

### Prerequisites
- Python 3.12+
- pip

### Setup

```bash
# 1. Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# 2. Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# 3. Generate configuration
python scripts/generate_env.py
# Or manually:
cp .env.example .env
python scripts/generate_encryption_key.py  # save the output as KEK

# 4. Edit .env with your SECRET_KEY and SECURECLOUD_KEY_ENCRYPTION_KEY

# 5. Initialise database
python scripts/init_db.py

# 6. Run
flask run --debug
# Or: gunicorn app:app --config gunicorn.conf.py
```

---

## Docker Desktop

### Prerequisites
- Docker Desktop installed and running

### Quick Start

```bash
# Build and start (app + MinIO)
docker compose up -d --build

# Check status
docker compose ps

# View logs
docker compose logs -f app

# Stop
docker compose down
```

The application runs at **http://localhost:8000**.
MinIO console: **http://localhost:9001** (minioadmin/minioadmin).

### Custom Environment

Create a `.env` file before starting:

```bash
python scripts/generate_env.py
docker compose up -d --build
```

---

## Docker with HDFS

### Start HDFS Cluster

```bash
# Start app + HDFS (NameNode + DataNode)
docker compose -f docker-compose.yml -f docker-compose.hdfs.yml up -d --build

# Wait for HDFS to initialise (~30 seconds)
sleep 30

# Initialise HDFS directories
python scripts/setup_hdfs.py --url http://localhost:9870
```

### Verify HDFS

- **HDFS WebUI:** http://localhost:9870
- **Application:** http://localhost:8000

### Persistent Volumes

HDFS data is stored in named Docker volumes:
- `hadoop_namenode` — NameNode metadata
- `hadoop_datanode` — DataNode block storage

These persist across container restarts. To fully reset:

```bash
docker compose -f docker-compose.yml -f docker-compose.hdfs.yml down -v
```

---

## Render.com

### Deploy via Blueprint

1. Push code to a GitHub repository
2. In [Render Dashboard](https://dashboard.render.com), click **New → Blueprint**
3. Connect your repository — Render auto-detects `render.yaml`
4. Set the `SECURECLOUD_KEY_ENCRYPTION_KEY` secret in Environment variables:
   ```bash
   python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())"
   ```
5. Click **Apply** to deploy

### Render Features Used
- **Docker** runtime
- **Persistent Disk** (1 GB) for SQLite database and local storage
- **Health check** on `/healthz`
- Auto-generated `SECRET_KEY`

### Limitations
- Free tier spins down after 15 minutes of inactivity
- 1 GB persistent disk on free tier

---

## Fly.io

### Deploy

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Authenticate
fly auth login

# Launch (creates app)
fly launch --config fly.toml --no-deploy

# Create persistent volume
fly volumes create securecloud_data --size 1 --region iad

# Set secrets
fly secrets set SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
fly secrets set SECURECLOUD_KEY_ENCRYPTION_KEY=$(python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())")

# Deploy
fly deploy
```

### Check Status

```bash
fly status
fly logs
```

---

## Railway

### Deploy

```bash
# Install Railway CLI
npm i -g @railway/cli

# Authenticate
railway login

# Initialise project
railway init

# Set environment variables
railway variables set SECRET_KEY=$(python -c "import secrets; print(secrets.token_urlsafe(48))")
railway variables set SECURECLOUD_KEY_ENCRYPTION_KEY=$(python -c "import base64,os; print(base64.b64encode(os.urandom(32)).decode())")
railway variables set FLASK_ENV=production
railway variables set SECURECLOUD_SESSION_COOKIE_SECURE=true

# Deploy
railway up
```

---

## Production Checklist

Before deploying to production, verify:

- [ ] `SECRET_KEY` is set to a strong random value (not the default)
- [ ] `SECURECLOUD_KEY_ENCRYPTION_KEY` is set and **backed up securely**
- [ ] `FLASK_ENV=production`
- [ ] `SECURECLOUD_SESSION_COOKIE_SECURE=true` (if using HTTPS)
- [ ] `DEBUG` is not enabled
- [ ] Rate limiting is enabled
- [ ] Database is initialised (`python scripts/init_db.py` or release command)
- [ ] Storage backend is configured and accessible
- [ ] Health check passes: `curl http://your-app/healthz`
- [ ] SSL/TLS is configured (via reverse proxy or platform)
- [ ] KEK is backed up — **losing the KEK = losing ALL encrypted files**

---

## Persistent Storage

### Local Backend
- **Database:** `instance/securecloud.db` (SQLite)
- **Blocks:** `staging/local_object_storage/`
- **Temp:** `staging/downloads/`

### Docker Volumes
The `docker-compose.yml` maps named volumes. To inspect:

```bash
docker volume ls | grep securecloud
docker volume inspect securecloud_namenode
```

### Cloud Platforms
- **Render:** Uses persistent disk mounted at `/app/persistent`
- **Fly.io:** Uses Fly Volume mounted at `/app/persistent`
- **Railway:** Ephemeral — use S3 or HDFS backend for persistence

---

## Backup & Restore

### Backup

```bash
# 1. Stop the application
docker compose stop app

# 2. Copy the SQLite database
cp instance/securecloud.db backups/securecloud-$(date +%Y%m%d).db

# 3. Copy encrypted blocks (if using local storage)
tar -czf backups/blocks-$(date +%Y%m%d).tar.gz staging/local_object_storage/

# 4. Save your KEK (if not already backed up)
echo $SECURECLOUD_KEY_ENCRYPTION_KEY > backups/kek-$(date +%Y%m%d).txt
# chmod 600 backups/kek-*.txt

# 5. Restart
docker compose start app
```

### Restore

```bash
# 1. Stop the application
docker compose stop app

# 2. Restore the database
cp backups/securecloud-YYYYMMDD.db instance/securecloud.db

# 3. Restore blocks
tar -xzf backups/blocks-YYYYMMDD.tar.gz

# 4. Ensure .env has the same KEK as when the backup was made

# 5. Start
docker compose start app
```

> ⚠️ **Critical:** The KEK at restore time MUST match the KEK used when files were encrypted. A mismatched KEK will make all files unrecoverable.

---

## Verify Deployment

Run the deployment test script against your deployed instance:

```bash
python scripts/test_deployment.py https://your-app-url.com
```

This tests health check, registration, login, upload, download, integrity, and deletion.
