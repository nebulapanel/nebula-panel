#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_URL="${NEBULA_DATABASE_URL:-postgres://nebula:nebula@127.0.0.1:5432/nebula?sslmode=disable}"
COMPOSE_FILE="${ROOT_DIR}/scripts/docker-compose.dev.yml"

if ! command -v psql >/dev/null 2>&1 && ! command -v docker >/dev/null 2>&1; then
  echo "Error: install either 'psql' or 'docker' to run migrations." >&2
  exit 1
fi

if ! command -v psql >/dev/null 2>&1; then
  docker compose -f "${COMPOSE_FILE}" up -d postgres >/dev/null
fi

for file in "${ROOT_DIR}"/apps/api/migrations/*.sql; do
  echo "Applying $(basename "${file}")"
  if command -v psql >/dev/null 2>&1; then
    psql "${DB_URL}" -f "${file}"
  else
    docker compose -f "${COMPOSE_FILE}" exec -T postgres \
      psql -v ON_ERROR_STOP=1 -U nebula -d nebula -f - < "${file}"
  fi
done
