#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash deploy/install.sh"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/nebula-panel"
SECRETS_FILE="/etc/nebula-panel/secrets.env"

check_os() {
  if [[ ! -f /etc/os-release ]]; then
    echo "Unsupported OS"
    exit 1
  fi
  . /etc/os-release
  if [[ "${ID}" != "ubuntu" ]]; then
    echo "Nebula Panel installer supports Ubuntu only"
    exit 1
  fi
  if [[ "${VERSION_ID}" != "22.04" && "${VERSION_ID}" != "24.04" ]]; then
    echo "Warning: tested on Ubuntu 22.04/24.04, found ${VERSION_ID}"
  fi
}

install_packages() {
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    curl jq rsync ca-certificates unzip openssl \
    nginx php-fpm mariadb-server postgresql redis-server \
    pdns-server pdns-backend-sqlite3 \
    postfix dovecot-core dovecot-imapd opendkim opendkim-tools \
    certbot python3-certbot-nginx fail2ban

  if ! command -v node >/dev/null 2>&1 || [[ "$(node -v | sed 's/^v//;s/\..*$//')" -lt 20 ]]; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
  fi
}

setup_user_dirs() {
  id -u nebula >/dev/null 2>&1 || useradd --system --home /var/lib/nebula-panel --shell /usr/sbin/nologin nebula
  mkdir -p /etc/nebula-panel /var/lib/nebula-panel /var/log/nebula-panel /var/backups/nebula-panel
  chown -R nebula:nebula /var/lib/nebula-panel /var/log/nebula-panel
}

setup_secrets() {
  if [[ ! -f "${SECRETS_FILE}" ]]; then
    local db_password
    local pdns_key
    local agent_secret
    db_password="$(openssl rand -hex 18)"
    pdns_key="$(openssl rand -hex 24)"
    agent_secret="$(openssl rand -hex 32)"
    umask 077
    cat > "${SECRETS_FILE}" <<SECRETS
NEBULA_API_ADDR=:8080
NEBULA_DATA_ROOT=/var/lib/nebula-panel
NEBULA_DATABASE_URL=postgres://nebula:${db_password}@127.0.0.1:5432/nebula?sslmode=disable
NEBULA_AGENT_SOCKET=/run/nebula-agent.sock
NEBULA_AGENT_SHARED_SECRET=${agent_secret}
NEBULA_ADMIN_EMAIL=admin@localhost
NEBULA_ADMIN_PASSWORD=$(openssl rand -base64 18)
NEBULA_ADMIN_TOTP_CODE=000000
NEBULA_ACME_EMAIL=admin@localhost
NEBULA_ACME_WEBROOT=/var/www/nebula-acme
NEBULA_ZEROSSL_EAB_KID=
NEBULA_ZEROSSL_EAB_HMAC_KEY=
NEBULA_PDNS_API_URL=http://127.0.0.1:8081
NEBULA_PDNS_API_KEY=${pdns_key}
NEBULA_PDNS_SERVER_ID=localhost
NEBULA_GENERATED_CONFIG_DIR=/etc/nebula-panel/generated
NEBULA_SESSION_TTL=12h
NEBULA_AGENT_DRY_RUN=false
NEBULA_SSL_RENEW_INTERVAL=12h
NEBULA_BACKUP_INTERVAL=24h
NEBULA_BACKUP_SCOPE=full
NEXT_PUBLIC_NEBULA_API_URL=/v1
NEBULA_INTERNAL_API_PROXY=http://127.0.0.1:8080/v1/:path*
SECRETS
    chmod 600 "${SECRETS_FILE}"
    echo "Created ${SECRETS_FILE}. Update NEBULA_ADMIN_TOTP_CODE before production use."
  fi
}

setup_postgres() {
  systemctl enable --now postgresql >/dev/null 2>&1 || true
  source "${SECRETS_FILE}"
  local db_url db_user db_pass db_name
  local as_postgres
  db_url="${NEBULA_DATABASE_URL}"
  db_user="$(echo "${db_url}" | sed -E 's#^postgres://([^:]+):.*#\1#')"
  db_pass="$(echo "${db_url}" | sed -E 's#^postgres://[^:]+:([^@]+)@.*#\1#')"
  db_name="$(echo "${db_url}" | sed -E 's#.*/([^?]+)\?.*#\1#')"

  if command -v sudo >/dev/null 2>&1; then
    as_postgres="sudo -u postgres"
  else
    as_postgres="runuser -u postgres --"
  fi

  eval "${as_postgres} psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='${db_user}'\"" | grep -q 1 \
    || eval "${as_postgres} psql -c \"CREATE ROLE ${db_user} WITH LOGIN PASSWORD '${db_pass}';\""
  eval "${as_postgres} psql -tAc \"SELECT 1 FROM pg_database WHERE datname='${db_name}'\"" | grep -q 1 \
    || eval "${as_postgres} psql -c \"CREATE DATABASE ${db_name} OWNER ${db_user};\""

  export PGPASSWORD="${db_pass}"
  for file in "${ROOT_DIR}"/apps/api/migrations/*.sql; do
    psql -h 127.0.0.1 -U "${db_user}" -d "${db_name}" -f "${file}"
  done
}

setup_runtime_dirs() {
  source "${SECRETS_FILE}"
  mkdir -p "${NEBULA_ACME_WEBROOT}" "${NEBULA_GENERATED_CONFIG_DIR}"
  chown -R nebula:nebula "${NEBULA_ACME_WEBROOT}" "${NEBULA_GENERATED_CONFIG_DIR}"
}

install_code() {
  rm -rf "${INSTALL_DIR}"
  mkdir -p "${INSTALL_DIR}"
  rsync -a --exclude '.git' --exclude 'node_modules' "${ROOT_DIR}/" "${INSTALL_DIR}/"

  install -m 755 "${ROOT_DIR}/bin/nebula-api" /usr/local/bin/nebula-api
  install -m 755 "${ROOT_DIR}/bin/nebula-agent" /usr/local/bin/nebula-agent
  install -m 755 "${ROOT_DIR}/bin/nebula-worker" /usr/local/bin/nebula-worker

  cd "${INSTALL_DIR}/apps/web"
  npm ci
  npm run build
  chown -R nebula:nebula "${INSTALL_DIR}"
}

install_templates() {
  install -m 644 "${ROOT_DIR}/deploy/templates/nginx-nebula.conf" /etc/nginx/sites-available/nebula-panel.conf
  ln -sf /etc/nginx/sites-available/nebula-panel.conf /etc/nginx/sites-enabled/nebula-panel.conf

  install -m 644 "${ROOT_DIR}/deploy/templates/postfix-main.cf" /etc/postfix/main.cf
  install -m 644 "${ROOT_DIR}/deploy/templates/dovecot.conf" /etc/dovecot/dovecot.conf
  install -m 644 "${ROOT_DIR}/deploy/templates/pdns.conf" /etc/powerdns/pdns.conf
  install -m 644 "${ROOT_DIR}/deploy/templates/fail2ban-jail.local" /etc/fail2ban/jail.local

  source "${SECRETS_FILE}"
  sed -i "s#api-key=.*#api-key=${NEBULA_PDNS_API_KEY}#g" /etc/powerdns/pdns.conf
}

install_systemd() {
  install -m 644 "${ROOT_DIR}/deploy/systemd/nebula-agent.service" /etc/systemd/system/nebula-agent.service
  install -m 644 "${ROOT_DIR}/deploy/systemd/nebula-api.service" /etc/systemd/system/nebula-api.service
  install -m 644 "${ROOT_DIR}/deploy/systemd/nebula-worker.service" /etc/systemd/system/nebula-worker.service
  install -m 644 "${ROOT_DIR}/deploy/systemd/nebula-web.service" /etc/systemd/system/nebula-web.service

  systemctl daemon-reload
  systemctl enable --now nebula-agent.service nebula-api.service nebula-worker.service nebula-web.service
  systemctl enable --now nginx redis-server postgresql mariadb fail2ban
}

print_next_steps() {
  cat <<MSG
Nebula Panel installed.

Next steps:
1. Edit ${SECRETS_FILE} and set real admin email/password/TOTP.
2. Replace panel.local in nginx template with your domain and reload nginx.
3. Set NEBULA_PDNS_API_KEY and ACME/ZeroSSL values as needed.
4. Configure DNS glue records for ns1/ns2 to this server IP.
5. Restart Nebula services:
   systemctl restart nebula-agent nebula-api nebula-worker nebula-web
MSG
}

check_os
install_packages
setup_user_dirs
setup_secrets
setup_postgres
setup_runtime_dirs
install_code
install_templates
install_systemd
print_next_steps
