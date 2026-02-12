#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required"
  exit 1
fi

make dev-up
make migrate

echo "Dev dependencies started and DB migrations applied."
