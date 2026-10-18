#!/usr/bin/env bash
# deploy.sh — SecureCloud deployment helper
#
# Usage:
#   bash scripts/deploy.sh [docker|render|fly|railway]
#
# Without arguments it generates the .env file and initialises the local DB.

set -euo pipefail
cd "$(dirname "$0")/.."

# ── Helpers ───────────────────────────────────────────────────────────────

generate_secret() {
    python3 -c "import secrets; print(secrets.token_urlsafe(48))"
}

generate_kek() {
    python3 -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
}

# ── Create .env from .env.example ─────────────────────────────────────────

setup_env() {
    if [ -f .env ]; then
        echo "[deploy] .env already exists — skipping generation."
        return
    fi

    echo "[deploy] Generating .env from .env.example ..."
    cp .env.example .env

    SECRET=$(generate_secret)
    KEK=$(generate_kek)

    # Inject generated values
    sed -i "s|^SECRET_KEY=.*|SECRET_KEY=${SECRET}|" .env
    sed -i "s|^SECURECLOUD_KEY_ENCRYPTION_KEY=.*|SECURECLOUD_KEY_ENCRYPTION_KEY=${KEK}|" .env

    echo "[deploy] .env created.  Generated:"
    echo "         SECRET_KEY = ${SECRET}"
    echo "         KEK        = ${KEK}"
    echo ""
    echo "  ⚠  SAVE THESE VALUES — losing the KEK means losing all encrypted files."
    echo ""
}

# ── Initialise database ──────────────────────────────────────────────────

init_db() {
    echo "[deploy] Initialising database ..."
    python3 -c "
from securecloud import create_app
from securecloud.extensions import db
app = create_app('production')
with app.app_context():
    db.create_all()
    print('[deploy] Database tables created.')
"
}

# ── Health check ─────────────────────────────────────────────────────────

health_check() {
    local url="${1:-http://localhost:8000}"
    echo "[deploy] Health check → ${url}/healthz ..."
    if curl -sf "${url}/healthz" > /dev/null 2>&1; then
        echo "[deploy] ✓ Application is healthy."
    else
        echo "[deploy] ✗ Health check failed."
        return 1
    fi
}

# ── Docker deployment ────────────────────────────────────────────────────

deploy_docker() {
    setup_env
    echo "[deploy] Building and starting Docker containers ..."
    docker compose up -d --build
    sleep 5
    health_check http://localhost:8000
}

deploy_docker_hdfs() {
    setup_env
    echo "[deploy] Building with HDFS overlay ..."
    docker compose -f docker-compose.yml -f docker-compose.hdfs.yml up -d --build
    echo "[deploy] Waiting for HDFS to be ready ..."
    sleep 30
    python3 scripts/setup_hdfs.py
    health_check http://localhost:8000
}

# ── Cloud deployments ────────────────────────────────────────────────────

deploy_render() {
    echo "[deploy] For Render.com:"
    echo "  1. Push this repo to GitHub"
    echo "  2. Connect repo in Render Dashboard"
    echo "  3. render.yaml will be auto-detected"
    echo "  4. Set SECURECLOUD_KEY_ENCRYPTION_KEY manually in Render env vars"
    echo ""
    echo "  KEK (save this): $(generate_kek)"
}

deploy_fly() {
    echo "[deploy] Deploying to Fly.io ..."
    fly launch --config fly.toml --no-deploy
    fly volumes create securecloud_data --size 1 --region iad
    echo ""
    echo "  Set secrets:"
    echo "    fly secrets set SECRET_KEY=$(generate_secret)"
    echo "    fly secrets set SECURECLOUD_KEY_ENCRYPTION_KEY=$(generate_kek)"
    echo ""
    echo "  Then deploy:"
    echo "    fly deploy"
}

deploy_railway() {
    echo "[deploy] For Railway:"
    echo "  1. Install Railway CLI: npm i -g @railway/cli"
    echo "  2. railway login"
    echo "  3. railway init"
    echo "  4. Set environment variables:"
    echo "     railway variables set SECRET_KEY=$(generate_secret)"
    echo "     railway variables set SECURECLOUD_KEY_ENCRYPTION_KEY=$(generate_kek)"
    echo "  5. railway up"
}

# ── Main ─────────────────────────────────────────────────────────────────

case "${1:-local}" in
    local)
        setup_env
        init_db
        echo "[deploy] Ready!  Start with:  gunicorn app:app --config gunicorn.conf.py"
        ;;
    docker)
        deploy_docker
        ;;
    docker-hdfs)
        deploy_docker_hdfs
        ;;
    render)
        deploy_render
        ;;
    fly)
        deploy_fly
        ;;
    railway)
        deploy_railway
        ;;
    *)
        echo "Usage: bash scripts/deploy.sh [local|docker|docker-hdfs|render|fly|railway]"
        exit 1
        ;;
esac
