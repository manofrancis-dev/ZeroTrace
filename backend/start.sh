#!/bin/sh
set -e
# Start the dynamic sandbox locally inside the same container.
uvicorn sandbox.worker:app --host 127.0.0.1 --port 8001 &
# Start the API on Render's PORT (default 8000).
exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}