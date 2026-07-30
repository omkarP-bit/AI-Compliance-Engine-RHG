#!/bin/bash
set -e

# Start OPA in background (non-blocking)
echo "[entrypoint] Starting OPA on :8181 ..."
opa run --server --addr=0.0.0.0:8181 --set=decision_logs.console=true /app/policies &

echo "[entrypoint] Starting ACE on :8000 ..."
exec uvicorn ace.main:app --host 0.0.0.0 --port 8000
