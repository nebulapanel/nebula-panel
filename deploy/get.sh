#!/usr/bin/env bash
set -euo pipefail

# Nebula Panel release installer.
# Downloads the latest GitHub Release, verifies SHA256, then runs deploy/install.sh.

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash -c \"curl -fsSL ... | bash\""
  exit 1
fi

REPO="nebulapanel/nebula-panel"
DEPLOY_DIR="${NEBULA_DEPLOY_DIR:-/opt/src/Nebula}"

arch_from_system() {
  case "$(uname -m)" in
    x86_64) echo "amd64" ;;
    aarch64|arm64) echo "arm64" ;;
    *)
      echo "Unsupported architecture: $(uname -m)" >&2
      exit 1
      ;;
  esac
}

ARCH="$(arch_from_system)"
ASSET="nebula-panel_linux_${ARCH}.tar.gz"
BASE_URL="https://github.com/${REPO}/releases/latest/download"

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "${tmpdir}"; }
trap cleanup EXIT

echo "Downloading ${ASSET}..."
curl -fsSL "${BASE_URL}/${ASSET}" -o "${tmpdir}/${ASSET}"
curl -fsSL "${BASE_URL}/SHA256SUMS" -o "${tmpdir}/SHA256SUMS"

echo "Verifying SHA256..."
(cd "${tmpdir}" && grep " ${ASSET}\$" SHA256SUMS | sha256sum -c -)

ts="$(date +%Y%m%d-%H%M%S)"
if [[ -d "${DEPLOY_DIR}" ]]; then
  mv "${DEPLOY_DIR}" "${DEPLOY_DIR}.bak.${ts}"
fi
mkdir -p "${DEPLOY_DIR}"
tar -xzf "${tmpdir}/${ASSET}" -C "${DEPLOY_DIR}"

cd "${DEPLOY_DIR}"
bash deploy/install.sh

