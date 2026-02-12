#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root: sudo bash scripts/install-ubuntu.sh"
  exit 1
fi

if [[ ! -f /etc/os-release ]]; then
  echo "Unsupported OS"
  exit 1
fi
. /etc/os-release
if [[ "${ID}" != "ubuntu" ]]; then
  echo "Nebula Panel installer supports Ubuntu only"
  exit 1
fi

REPO_URL="${NEBULA_REPO_URL:-https://github.com/nebulapanel/nebula-panel.git}"
REPO_REF="${NEBULA_REPO_REF:-main}"
SRC_DIR="${NEBULA_SRC_DIR:-/opt/src/Nebula}"

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y git ca-certificates curl

if [[ -d "${SRC_DIR}/.git" ]]; then
  git -C "${SRC_DIR}" fetch origin "${REPO_REF}"
  git -C "${SRC_DIR}" checkout "${REPO_REF}" || git -C "${SRC_DIR}" checkout -b "${REPO_REF}" "origin/${REPO_REF}"
  git -C "${SRC_DIR}" pull --ff-only origin "${REPO_REF}"
else
  rm -rf "${SRC_DIR}"
  git clone --branch "${REPO_REF}" --depth 1 "${REPO_URL}" "${SRC_DIR}"
fi

cd "${SRC_DIR}"
bash deploy/install.sh
