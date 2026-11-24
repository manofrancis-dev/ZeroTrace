#!/bin/sh
set -e
# Zero-config hardening for single-container deployments (e.g. a Render
# service created without the blueprint env vars):
# - The API must talk to the local worker.
# - Both processes must share the same sandbox key. If the host provides no
#   key, generate one inside the container and export it so the worker and
#   the API can never disagree. The sandbox binds to loopback here, so a
#   generated key never leaves the container.
if [ -z "${SANDBOX_API_URL:-}" ]; then
  SANDBOX_API_URL="http://127.0.0.1:8001"
  export SANDBOX_API_URL
fi
if [ -z "${SANDBOX_API_KEY:-}" ]; then
  SANDBOX_API_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
  export SANDBOX_API_KEY
  echo "SANDBOX_API_KEY was not set; generated an ephemeral in-container key."
fi
# Start the dynamic sandbox locally inside the same container.
uvicorn sandbox.worker:app --host 127.0.0.1 --port 8001 &
# Start the API on Render's PORT (default 8000).
exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
