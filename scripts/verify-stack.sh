#!/usr/bin/env bash
set -euo pipefail

services=(nebula-agent nebula-api nebula-worker nebula-web nginx pdns postfix dovecot)
for svc in "${services[@]}"; do
  if systemctl is-active --quiet "$svc"; then
    echo "[ok] $svc"
  else
    echo "[fail] $svc"
  fi
done

curl -fsS http://127.0.0.1:8080/healthz >/dev/null && echo "[ok] API health" || echo "[fail] API health"
