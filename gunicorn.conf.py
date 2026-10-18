"""Gunicorn configuration for SecureCloud (production / Linux)."""
import multiprocessing
import os

bind = os.getenv("GUNICORN_BIND", "0.0.0.0:" + os.getenv("PORT", "8000"))
workers = int(os.getenv("WEB_CONCURRENCY", min(4, multiprocessing.cpu_count() * 2 + 1)))
worker_class = "sync"
threads = int(os.getenv("GUNICORN_THREADS", "4"))
timeout = int(os.getenv("GUNICORN_TIMEOUT", "120"))
graceful_timeout = 30
keepalive = 5

accesslog = os.getenv("GUNICORN_ACCESS_LOG", "-")
errorlog = os.getenv("GUNICORN_ERROR_LOG", "-")
loglevel = os.getenv("GUNICORN_LOG_LEVEL", "info")
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(L)s'

# TLS is terminated by the reverse proxy (nginx / cloud load balancer).
forwarded_allow_ips = os.getenv("FORWARDED_ALLOW_IPS", "*")
proxy_allow_ips = os.getenv("FORWARDED_ALLOW_IPS", "*")
secure_scheme_headers = {"X-FORWARDED-PROTO": "https"}

preload_app = False
max_requests = int(os.getenv("GUNICORN_MAX_REQUESTS", "1200"))
max_requests_jitter = 100
