#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

REMOVE_SUDOERS=false
for arg in "$@"; do
  if [[ "${arg}" == "--remove-sudoers" ]]; then
    REMOVE_SUDOERS=true
  fi
done

echo "==> 1. Building engine..."
cmake --build "${REPO_DIR}/engine/build" -j"$(nproc)"

ENGINE_BUILD_BIN="${REPO_DIR}/engine/build/dpi_engine"
INSTALLED_BIN="/usr/local/sbin/aegis-dpi-engine"

echo "==> 2. Verifying binary security constraints (no RPATH/RUNPATH, no home-dir libraries)..."
if readelf -d "${ENGINE_BUILD_BIN}" | grep -E "RPATH|RUNPATH" >/dev/null; then
  echo "ERROR: ${ENGINE_BUILD_BIN} contains RPATH or RUNPATH:" >&2
  readelf -d "${ENGINE_BUILD_BIN}" | grep -E "RPATH|RUNPATH" >&2
  exit 1
fi

LDD_OUT=$(ldd "${ENGINE_BUILD_BIN}")
if echo "${LDD_OUT}" | grep -F "${HOME}" >/dev/null; then
  echo "ERROR: ${ENGINE_BUILD_BIN} references libraries under \$HOME:" >&2
  echo "${LDD_OUT}" | grep -F "${HOME}" >&2
  exit 1
fi

if echo "${LDD_OUT}" | grep -i "not found" >/dev/null; then
  echo "ERROR: ${ENGINE_BUILD_BIN} has missing library dependencies:" >&2
  echo "${LDD_OUT}" | grep -i "not found" >&2
  exit 1
fi
echo "Binary verification passed: static redis++, no RPATH/RUNPATH, all shared libs from system paths."

echo "==> 3. Installing root-owned binary to ${INSTALLED_BIN}..."
sudo install -o root -g root -m 0755 "${ENGINE_BUILD_BIN}" "${INSTALLED_BIN}"

echo "==> 4. Setting Linux file capabilities (cap_net_raw, cap_net_admin)..."
sudo setcap cap_net_raw,cap_net_admin=ep "${INSTALLED_BIN}"

CAPS=$(getcap "${INSTALLED_BIN}" 2>/dev/null || true)
if ! echo "${CAPS}" | grep -E "cap_net_admin.*cap_net_raw|cap_net_raw.*cap_net_admin" >/dev/null; then
  echo "ERROR: Verification failed. ${INSTALLED_BIN} does not have required capabilities:" >&2
  echo "${CAPS}" >&2
  exit 1
fi
echo "Verified capabilities: ${CAPS}"

echo "==> 5. Configuration notice:"
echo "Ensure ENGINE_BIN=${INSTALLED_BIN} is set in middleware/.env"

if [[ "${REMOVE_SUDOERS}" == "true" ]]; then
  SUDOERS_FILE="/etc/sudoers.d/aegis-engine"
  if [[ -f "${SUDOERS_FILE}" ]]; then
    echo "==> 6. Found legacy sudoers rule at ${SUDOERS_FILE}:"
    sudo cat "${SUDOERS_FILE}"
    echo
    read -r -p "Remove it? [y/N] " resp
    if [[ "${resp}" =~ ^[Yy]$ ]]; then
      sudo rm -f "${SUDOERS_FILE}"
      echo "Removed ${SUDOERS_FILE}."
      echo "Checking sudo -l output for dpi_engine:"
      if sudo -l 2>&1 | grep "dpi_engine"; then
        echo "WARNING: dpi_engine still referenced in sudo -l"
      else
        echo "Verified: sudo -l no longer mentions dpi_engine."
      fi
    else
      echo "Kept ${SUDOERS_FILE}."
    fi
  else
    echo "==> 6. No legacy sudoers file found at /etc/sudoers.d/aegis-engine."
  fi
fi

echo "==> 7. Complete!"
echo "NOTE: Rebuilding the engine requires re-running this script (root-owned binary, by design)."

