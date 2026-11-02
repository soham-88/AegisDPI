#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DATE_STR=$(date +%Y%m%d)
OUTPUT_ZIP="${REPO_ROOT}/../AegisDPI-submission-${DATE_STR}.zip"

# Ensure zip and unzip are available
if ! command -v zip >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
    echo "Installing zip and unzip tools..."
    sudo apt-get update -y
    sudo apt-get install -y zip unzip
fi

echo "=========================================================="
echo "          Packaging AegisDPI Submission Archive           "
echo "=========================================================="
echo "Target archive: ${OUTPUT_ZIP}"

pushd "${REPO_ROOT}" >/dev/null

# Clean any leftover output zip at destination
rm -f "${OUTPUT_ZIP}"

# Exclude patterns:
# - node_modules, venv, engine/build, frontend/dist, logs, run, *.pid, .git, .env
# Include: .env.example, *.joblib
zip -r "${OUTPUT_ZIP}" . \
    -x "node_modules*" "*/node_modules*" "*/node_modules/*" \
    -x "venv*" "*/venv*" "*/venv/*" \
    -x "engine/build*" "engine/build/*" \
    -x "frontend/dist*" "frontend/dist/*" \
    -x "logs/*" \
    -x "run/*" \
    -x "*.pid" \
    -x ".git*" ".git/*" "*/.git/*" \
    -x ".env" "*/.env" "./.env" \
    -x ".system_generated*" "*/.system_generated*"

echo
echo "==> Verifying archive contents..."
ZIP_CONTENTS=$(unzip -l "${OUTPUT_ZIP}")

# 1. Check for any node_modules
if echo "${ZIP_CONTENTS}" | grep -E "(^|[ /])node_modules([ /]|$)" >/dev/null 2>&1; then
    echo "ERROR: Package contains 'node_modules'!" >&2
    echo "${ZIP_CONTENTS}" | grep -E "(^|[ /])node_modules([ /]|$)" >&2
    rm -f "${OUTPUT_ZIP}"
    exit 1
fi

# 2. Check for any .env (excluding .env.example)
ENV_LEAKS=$(echo "${ZIP_CONTENTS}" | grep -E "(^|[ /])\.env$" || true)
if [ -n "${ENV_LEAKS}" ]; then
    echo "ERROR: Package contains private '.env' file(s)!" >&2
    echo "${ENV_LEAKS}" >&2
    rm -f "${OUTPUT_ZIP}"
    exit 1
fi

# 3. Verify that .env.example is included
if ! echo "${ZIP_CONTENTS}" | grep -q "\.env\.example"; then
    echo "ERROR: '.env.example' files were not included in archive!" >&2
    rm -f "${OUTPUT_ZIP}"
    exit 1
fi

# 4. Verify model.joblib is included if present in repo
if [ -f "${REPO_ROOT}/ml-service/model.joblib" ]; then
    if ! echo "${ZIP_CONTENTS}" | grep -q "model\.joblib"; then
        echo "ERROR: 'model.joblib' is present in repo but missing from archive!" >&2
        rm -f "${OUTPUT_ZIP}"
        exit 1
    fi
fi

echo "==> Verification passed successfully:"
echo "    - No 'node_modules' directories present"
echo "    - No private '.env' files present"
echo "    - Template '.env.example' files included"
if [ -f "${REPO_ROOT}/ml-service/model.joblib" ]; then
    echo "    - ML model artifact ('model.joblib') included"
fi

echo
echo "==> Submission archive details:"
ls -lh "${OUTPUT_ZIP}"

popd >/dev/null
