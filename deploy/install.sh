#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash deploy/install.sh"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_DIR="/opt/nebula-panel"
SECRETS_FILE="/etc/nebula-panel/secrets.env"
GO_MIN_VERSION="1.22.0"

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
    curl jq rsync ca-certificates unzip openssl git \
    ssl-cert \
    openssh-server \
    nginx php-fpm mariadb-server postgresql redis-server \
    pdns-server pdns-backend-sqlite3 \
    postfix postfix-pcre dovecot-core dovecot-imapd dovecot-lmtpd opendkim opendkim-tools \
    certbot python3-certbot-nginx fail2ban \
    restic

  if ! command -v node >/dev/null 2>&1 || [[ "$(node -v | sed 's/^v//;s/\..*$//')" -lt 20 ]]; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
  fi
}

have_tty() {
  [[ -t 0 && -t 1 ]]
}

prompt_default() {
  local var="$1"
  local prompt="$2"
  local def="$3"

  if [[ -n "${!var:-}" ]]; then
    return
  fi

  if ! have_tty; then
    echo "Missing required env var ${var} for non-interactive install." >&2
    exit 1
  fi

  local val
  read -r -p "${prompt} [${def}]: " val
  val="${val:-${def}}"
  export "${var}=${val}"
}

prompt_optional() {
  local var="$1"
  local prompt="$2"
  local def="$3"

  if [[ -n "${!var:-}" ]]; then
    return
  fi
  if ! have_tty; then
    export "${var}=${def}"
    return
  fi

  local val
  read -r -p "${prompt} [${def}]: " val
  val="${val:-${def}}"
  export "${var}=${val}"
}

NEBULA_INSTALL_GENERATED_ADMIN_PASSWORD=""

collect_install_config() {
  if [[ -f "${SECRETS_FILE}" ]]; then
    return
  fi

  local host_fqdn
  host_fqdn="$(hostname -f 2>/dev/null || hostname)"
  host_fqdn="$(echo "${host_fqdn}" | tr -d '[:space:]')"
  if [[ -z "${host_fqdn}" ]]; then
    host_fqdn="localhost"
  fi

  prompt_default "NEBULA_ADMIN_EMAIL" "Admin email" "admin@${host_fqdn}"

  if [[ -z "${NEBULA_ADMIN_PASSWORD:-}" ]]; then
    if ! have_tty; then
      echo "Missing required env var NEBULA_ADMIN_PASSWORD for non-interactive install." >&2
      exit 1
    fi
    local pw1 pw2
    while true; do
      read -r -s -p "Admin password (leave empty to generate): " pw1
      echo
      if [[ -z "${pw1}" ]]; then
        pw1="$(openssl rand -base64 18)"
        NEBULA_INSTALL_GENERATED_ADMIN_PASSWORD="${pw1}"
        break
      fi
      if [[ "${pw1}" =~ [[:space:]] ]]; then
        echo "Password must not contain spaces." >&2
        continue
      fi
      read -r -s -p "Confirm admin password: " pw2
      echo
      if [[ "${pw1}" != "${pw2}" ]]; then
        echo "Passwords do not match." >&2
        continue
      fi
      break
    done
    export NEBULA_ADMIN_PASSWORD="${pw1}"
  fi

  prompt_optional "NEBULA_ACME_EMAIL" "ACME email" "${NEBULA_ADMIN_EMAIL}"
  prompt_optional "NEBULA_PANEL_FQDN" "Panel domain (optional, leave blank for IP)" ""
  prompt_optional "NEBULA_MAIL_FQDN" "Mail hostname (used for MX/TLS)" "${host_fqdn}"
  prompt_optional "NEBULA_NS1_FQDN" "Global NS1 hostname (optional)" ""
  prompt_optional "NEBULA_NS2_FQDN" "Global NS2 hostname (optional)" ""
}

version_ge() {
  # True when $2 is greater than or equal to $1
  printf '%s\n%s\n' "$1" "$2" | sort -V -C
}

current_go_version() {
  if command -v go >/dev/null 2>&1; then
    go env GOVERSION 2>/dev/null | sed 's/^go//' || true
  fi
}

go_arch_from_system() {
  case "$(dpkg --print-architecture)" in
    amd64) echo "amd64" ;;
    arm64) echo "arm64" ;;
    *)
      echo "Unsupported architecture for Go toolchain: $(dpkg --print-architecture)" >&2
      exit 1
      ;;
  esac
}

ensure_go_toolchain() {
  local cur
  cur="$(current_go_version)"
  if [[ -n "${cur}" ]] && version_ge "${GO_MIN_VERSION}" "${cur}"; then
    return
  fi

  local go_arch latest tarball
  go_arch="$(go_arch_from_system)"
  latest="$(curl -fsSL https://go.dev/VERSION?m=text | sed -n '1p')"
  if [[ ! "${latest}" =~ ^go[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
    echo "Could not determine latest Go version from go.dev"
    exit 1
  fi

  tarball="${latest}.linux-${go_arch}.tar.gz"
  curl -fsSL "https://go.dev/dl/${tarball}" -o "/tmp/${tarball}"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "/tmp/${tarball}"
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
  ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
  rm -f "/tmp/${tarball}"
}

build_binaries() {
  export PATH="/usr/local/go/bin:/usr/local/bin:${PATH}"
  mkdir -p "${ROOT_DIR}/bin"
  (
    cd "${ROOT_DIR}"
    CGO_ENABLED=0 GOOS=linux go build -o bin/nebula-api ./apps/api/cmd/api
    CGO_ENABLED=0 GOOS=linux go build -o bin/nebula-agent ./apps/agent/cmd/agent
    CGO_ENABLED=0 GOOS=linux go build -o bin/nebula-worker ./apps/worker/cmd/worker
  )
}

have_prebuilt_binaries() {
  [[ -x "${ROOT_DIR}/bin/nebula-api" && -x "${ROOT_DIR}/bin/nebula-agent" && -x "${ROOT_DIR}/bin/nebula-worker" ]]
}

ensure_binaries() {
  if have_prebuilt_binaries; then
    echo "Using prebuilt Nebula binaries from ${ROOT_DIR}/bin"
    return
  fi
  echo "Building Nebula binaries on this server..."
  ensure_go_toolchain
  build_binaries
}

setup_user_dirs() {
  getent group nebula >/dev/null 2>&1 || groupadd --system nebula
  id -u nebula >/dev/null 2>&1 || useradd --system --home /var/lib/nebula-panel --shell /usr/sbin/nologin --gid nebula nebula
  getent group nebula-sftp >/dev/null 2>&1 || groupadd --system nebula-sftp
  mkdir -p /etc/nebula-panel /var/lib/nebula-panel /var/log/nebula-panel /var/backups/nebula-panel
  chown -R nebula:nebula /var/lib/nebula-panel /var/log/nebula-panel

  # Minimal mail prerequisites so Postfix/Dovecot can start out-of-the-box.
  getent group vmail >/dev/null 2>&1 || groupadd --system vmail
  id -u vmail >/dev/null 2>&1 || useradd --system --home /var/mail/vhosts --shell /usr/sbin/nologin --gid vmail vmail
  mkdir -p /var/mail/vhosts
  chown -R vmail:vmail /var/mail/vhosts
  touch /etc/dovecot/nebula-users
  chmod 600 /etc/dovecot/nebula-users

  if [[ ! -f /etc/mailname ]]; then
    hostname -f > /etc/mailname || echo "mail.local" > /etc/mailname
  fi
}

setup_secrets() {
  if [[ ! -f "${SECRETS_FILE}" ]]; then
    collect_install_config
    local db_password
    local pdns_key
    local agent_secret
    local app_key
    local public_ipv4
    db_password="$(openssl rand -hex 18)"
    pdns_key="$(openssl rand -hex 24)"
    agent_secret="$(openssl rand -hex 32)"
    app_key="$(openssl rand -hex 32)"
    public_ipv4="$(curl -fsSL https://api.ipify.org || true)"
    umask 077
    cat > "${SECRETS_FILE}" <<SECRETS
NEBULA_API_ADDR=:8080
NEBULA_DATA_ROOT=/var/lib/nebula-panel
NEBULA_DATABASE_URL=postgres://nebula:${db_password}@127.0.0.1:5432/nebula?sslmode=disable
NEBULA_APP_KEY=${app_key}
NEBULA_AGENT_SOCKET=/run/nebula-agent.sock
NEBULA_AGENT_SHARED_SECRET=${agent_secret}
NEBULA_AGENT_CMD_TIMEOUT=10m
NEBULA_ADMIN_EMAIL=${NEBULA_ADMIN_EMAIL}
NEBULA_ADMIN_PASSWORD=${NEBULA_ADMIN_PASSWORD}
NEBULA_ACME_EMAIL=${NEBULA_ACME_EMAIL}
NEBULA_ACME_WEBROOT=/var/www/nebula-acme
NEBULA_ZEROSSL_EAB_KID=
NEBULA_ZEROSSL_EAB_HMAC_KEY=
NEBULA_PDNS_API_URL=http://127.0.0.1:8081
NEBULA_PDNS_API_KEY=${pdns_key}
NEBULA_PDNS_SERVER_ID=localhost
NEBULA_PANEL_FQDN=${NEBULA_PANEL_FQDN}
NEBULA_MAIL_FQDN=${NEBULA_MAIL_FQDN}
NEBULA_NS1_FQDN=${NEBULA_NS1_FQDN}
NEBULA_NS2_FQDN=${NEBULA_NS2_FQDN}
NEBULA_PUBLIC_IPV4=${public_ipv4}
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
    echo "Created ${SECRETS_FILE}."
  fi
}

setup_sftp_jail() {
  mkdir -p /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/nebula-sftp.conf <<'EOF'
# Managed by Nebula Panel. Members of nebula-sftp are jailed to /home/%u with SFTP only.
Match Group nebula-sftp
  ChrootDirectory /home/%u
  ForceCommand internal-sftp
  AllowTcpForwarding no
  X11Forwarding no
  PermitTunnel no
EOF
  if command -v sshd >/dev/null 2>&1; then
    sshd -t
  fi
  systemctl reload ssh >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1 || true
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
  rm -f /etc/nginx/sites-enabled/default >/dev/null 2>&1 || true

  install -m 644 "${ROOT_DIR}/deploy/templates/postfix-main.cf" /etc/postfix/main.cf
  install -m 644 "${ROOT_DIR}/deploy/templates/dovecot.conf" /etc/dovecot/dovecot.conf
  install -m 644 "${ROOT_DIR}/deploy/templates/pdns.conf" /etc/powerdns/pdns.conf
  install -m 644 "${ROOT_DIR}/deploy/templates/fail2ban-jail.local" /etc/fail2ban/jail.local

  source "${SECRETS_FILE}"
  if [[ -n "${NEBULA_PANEL_FQDN:-}" ]]; then
    sed -i "s/server_name _;/server_name ${NEBULA_PANEL_FQDN} _;/" /etc/nginx/sites-available/nebula-panel.conf
  fi

  if [[ -n "${NEBULA_MAIL_FQDN:-}" ]]; then
    sed -i "s/^myhostname = .*/myhostname = ${NEBULA_MAIL_FQDN}/" /etc/postfix/main.cf
  fi

  sed -i "s#api-key=.*#api-key=${NEBULA_PDNS_API_KEY}#g" /etc/powerdns/pdns.conf

  nginx -t
  systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx
}

install_systemd() {
  install -m 644 "${ROOT_DIR}/deploy/systemd/nebula-agent.service" /etc/systemd/system/nebula-agent.service
  install -m 644 "${ROOT_DIR}/deploy/systemd/nebula-api.service" /etc/systemd/system/nebula-api.service
  install -m 644 "${ROOT_DIR}/deploy/systemd/nebula-worker.service" /etc/systemd/system/nebula-worker.service
  install -m 644 "${ROOT_DIR}/deploy/systemd/nebula-web.service" /etc/systemd/system/nebula-web.service

  systemctl daemon-reload
  systemctl enable --now nebula-agent.service nebula-api.service nebula-worker.service nebula-web.service
  systemctl enable --now nginx redis-server postgresql mariadb fail2ban pdns postfix dovecot opendkim
}

finalize_install() {
  source "${SECRETS_FILE}"

  # Wait for API to come up so bootstrap can create the admin.
  for _ in $(seq 1 60); do
    if curl -fsS http://127.0.0.1:8080/healthz >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  local db_url db_user db_pass db_name
  db_url="${NEBULA_DATABASE_URL}"
  db_user="$(echo "${db_url}" | sed -E 's#^postgres://([^:]+):.*#\\1#')"
  db_pass="$(echo "${db_url}" | sed -E 's#^postgres://[^:]+:([^@]+)@.*#\\1#')"
  db_name="$(echo "${db_url}" | sed -E 's#.*/([^?]+)\\?.*#\\1#')"

  export PGPASSWORD="${db_pass}"
  if psql -h 127.0.0.1 -U "${db_user}" -d "${db_name}" -tAc "SELECT 1 FROM users WHERE email='${NEBULA_ADMIN_EMAIL}'" | grep -q 1; then
    # Remove bootstrap password from disk; it isn't needed after admin exists.
    sed -i "s/^NEBULA_ADMIN_PASSWORD=.*/NEBULA_ADMIN_PASSWORD=/" "${SECRETS_FILE}"
    systemctl restart nebula-api >/dev/null 2>&1 || true
  fi
}

print_next_steps() {
  cat <<MSG
Nebula Panel installed.

Open:
- http://<your-server-ip>/

Login:
- Email: ${NEBULA_ADMIN_EMAIL}
MSG

  if [[ -n "${NEBULA_INSTALL_GENERATED_ADMIN_PASSWORD}" ]]; then
    cat <<MSG
- Password: ${NEBULA_INSTALL_GENERATED_ADMIN_PASSWORD}

NOTE: The admin password is shown only once. It is not stored in ${SECRETS_FILE}.
MSG
  else
    cat <<MSG
- Password: (the password you entered during install)

NOTE: The admin password is not stored in ${SECRETS_FILE}.
MSG
  fi

  cat <<MSG

2FA:
- Enable Google Authenticator in: Settings -> Security

Services:
- systemctl status nebula-agent nebula-api nebula-worker nebula-web --no-pager
MSG
}

check_os
install_packages
ensure_binaries
setup_user_dirs
setup_secrets
setup_sftp_jail
setup_postgres
setup_runtime_dirs
install_code
install_templates
install_systemd
finalize_install
print_next_steps
