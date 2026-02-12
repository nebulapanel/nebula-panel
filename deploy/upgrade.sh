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
GO_MIN_VERSION="1.22.0"

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
  if ! command -v curl >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates
  fi

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
  ensure_go_toolchain
  build_binaries
}

mkdir -p "${BACKUP_DIR}"
if [[ -d "${INSTALL_DIR}" ]]; then
  rsync -a "${INSTALL_DIR}/" "${BACKUP_DIR}/"
fi

ensure_binaries

install -m 755 "${ROOT_DIR}/bin/nebula-api" /usr/local/bin/nebula-api
install -m 755 "${ROOT_DIR}/bin/nebula-agent" /usr/local/bin/nebula-agent
install -m 755 "${ROOT_DIR}/bin/nebula-worker" /usr/local/bin/nebula-worker

# Ensure SFTP jail is configured for tenant users (safe to re-run).
getent group nebula-sftp >/dev/null 2>&1 || groupadd --system nebula-sftp
mkdir -p /etc/ssh/sshd_config.d
if [[ ! -f /etc/ssh/sshd_config.d/nebula-sftp.conf ]]; then
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
    sshd -t || true
  fi
  systemctl reload ssh >/dev/null 2>&1 || systemctl restart ssh >/dev/null 2>&1 || true
fi

# Refresh Nebula systemd units (safe to overwrite; keeps upgrades consistent).
install -m 644 "${ROOT_DIR}/deploy/systemd/nebula-agent.service" /etc/systemd/system/nebula-agent.service
install -m 644 "${ROOT_DIR}/deploy/systemd/nebula-api.service" /etc/systemd/system/nebula-api.service
install -m 644 "${ROOT_DIR}/deploy/systemd/nebula-worker.service" /etc/systemd/system/nebula-worker.service
install -m 644 "${ROOT_DIR}/deploy/systemd/nebula-web.service" /etc/systemd/system/nebula-web.service

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
