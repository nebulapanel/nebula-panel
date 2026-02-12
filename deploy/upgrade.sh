#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/nebula-panel"
BACKUP_DIR="/var/backups/nebula-panel/upgrade-$(date +%Y%m%d-%H%M%S)"
SECRETS_FILE="/etc/nebula-panel/secrets.env"

mkdir -p "${BACKUP_DIR}"
if [[ -d "${INSTALL_DIR}" ]]; then
  rsync -a "${INSTALL_DIR}/" "${BACKUP_DIR}/"
fi

install -m 755 "${ROOT_DIR}/bin/nebula-api" /usr/local/bin/nebula-api
install -m 755 "${ROOT_DIR}/bin/nebula-agent" /usr/local/bin/nebula-agent
install -m 755 "${ROOT_DIR}/bin/nebula-worker" /usr/local/bin/nebula-worker

rsync -a --delete --exclude '.git' --exclude 'node_modules' "${ROOT_DIR}/" "${INSTALL_DIR}/"

cd "${INSTALL_DIR}/apps/web"
npm ci
npm run build

if [[ -f "${SECRETS_FILE}" ]]; then
  source "${SECRETS_FILE}"
  db_url="${NEBULA_DATABASE_URL:-}"
  if [[ -n "${db_url}" ]]; then
    db_user="$(echo "${db_url}" | sed -E 's#^postgres://([^:]+):.*#\1#')"
    db_pass="$(echo "${db_url}" | sed -E 's#^postgres://[^:]+:([^@]+)@.*#\1#')"
    db_name="$(echo "${db_url}" | sed -E 's#.*/([^?]+)\?.*#\1#')"
    export PGPASSWORD="${db_pass}"
    for file in "${ROOT_DIR}"/apps/api/migrations/*.sql; do
      psql -h 127.0.0.1 -U "${db_user}" -d "${db_name}" -f "${file}"
    done
  fi
fi

systemctl daemon-reload
systemctl restart nebula-agent nebula-api nebula-worker nebula-web

echo "Upgrade complete. Backup saved at ${BACKUP_DIR}"
