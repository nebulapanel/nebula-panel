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

if [[ -S /run/nebula-agent.sock ]]; then
  curl --unix-socket /run/nebula-agent.sock -fsS http://localhost/healthz >/dev/null \
    && echo "[ok] Agent socket" || echo "[fail] Agent socket"
else
  echo "[fail] Agent socket (missing /run/nebula-agent.sock)"
fi

nginx -t >/dev/null 2>&1 && echo "[ok] nginx -t" || echo "[fail] nginx -t"
