#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# 1. Exit with a clear message if not Linux
if [ "$(uname -s)" != "Linux" ]; then
    echo "Error: AegisDPI requires a Linux environment (Ubuntu 22.04+ or WSL2 Ubuntu)." >&2
    echo "Current operating system reported: $(uname -s)" >&2
    exit 1
fi

echo "=========================================================="
echo "               AegisDPI Environment Setup                 "
echo "=========================================================="

# 2. Check and install dependencies via apt (idempotent)
PKGS=(
    g++
    cmake
    libpcap-dev
    libhiredis-dev
    redis-server
    nftables
    iproute2
    python3-venv
    openssl
    nodejs
    npm
    zip
    unzip
)

MISSING_PKGS=()
for pkg in "${PKGS[@]}"; do
    if ! dpkg -s "${pkg}" >/dev/null 2>&1; then
        MISSING_PKGS+=("${pkg}")
    fi
done

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    echo "==> Installing missing system packages: ${MISSING_PKGS[*]}..."
    sudo apt-get update -y
    sudo apt-get install -y "${MISSING_PKGS[@]}"
else
    echo "==> All required system packages are already installed."
fi

# 3. Check Node.js >= 18
echo "==> Checking Node.js version..."
if ! command -v node >/dev/null 2>&1; then
    echo "Error: Node.js is not installed." >&2
    echo "Please install Node.js >= 18:" >&2
    echo "  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -" >&2
    echo "  sudo apt-get install -y nodejs" >&2
    exit 1
fi

NODE_MAJOR=$(node -v | sed -E 's/^v([0-9]+)\..*/\1/')
if [ "${NODE_MAJOR}" -lt 18 ]; then
    echo "Error: Node.js >= 18 is required (installed version is $(node -v))." >&2
    echo "Please upgrade Node.js on Ubuntu/WSL2:" >&2
    echo "  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -" >&2
    echo "  sudo apt-get install -y nodejs" >&2
    exit 1
fi
echo "Node.js $(node -v) meets requirements (>= 18)."

# 4. Disable / stop / mask system redis-server (aegis.sh runs its own Redis)
echo "==> Managing system redis-server service..."
if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
    sudo systemctl stop redis-server 2>/dev/null || true
    sudo systemctl disable redis-server 2>/dev/null || true
    sudo systemctl mask redis-server 2>/dev/null || true
    echo "System redis-server service stopped and masked in systemd."
else
    sudo service redis-server stop 2>/dev/null || true
    echo "systemd not running or absent; ensured system redis-server is stopped."
fi

# 5. Build engine (cmake configure + build) and run ctest
echo "==> Configuring and building C++ DPI engine..."
mkdir -p "${REPO_ROOT}/engine/build"
pushd "${REPO_ROOT}/engine/build" >/dev/null
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j"$(nproc 2>/dev/null || echo 2)"
echo "==> Running engine unit tests (ctest)..."
ctest --output-on-failure
popd >/dev/null

# 6. Setup middleware, frontend, and ml-service
echo "==> Installing middleware dependencies (npm ci)..."
pushd "${REPO_ROOT}/middleware" >/dev/null
npm ci
popd >/dev/null

echo "==> Installing frontend dependencies and building production bundle..."
pushd "${REPO_ROOT}/frontend" >/dev/null
npm ci
npm run build
popd >/dev/null

echo "==> Setting up ml-service virtualenv and dependencies..."
pushd "${REPO_ROOT}/ml-service" >/dev/null
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
./venv/bin/pip install --upgrade pip >/dev/null 2>&1 || true
./venv/bin/pip install -r requirements.txt
if [ ! -f "model.joblib" ]; then
    echo "model.joblib missing: training anomaly detection model..."
    ./venv/bin/python train.py
else
    echo "model.joblib found: skipping model training."
fi
popd >/dev/null

# 7. Create middleware/.env and ml-service/.env from .env.example ONLY if they do not exist
MW_ENV="${REPO_ROOT}/middleware/.env"
ML_ENV="${REPO_ROOT}/ml-service/.env"

if [ -f "${MW_ENV}" ] && [ -f "${ML_ENV}" ]; then
    echo "==> Keeping existing middleware/.env and ml-service/.env (not overwriting)."
else
    echo "==> Initializing configuration files from .env.example..."

    # Redis password: check existing or generate new
    REDIS_PW=""
    if [ -f "${MW_ENV}" ]; then
        REDIS_PW=$(grep -E '^REDIS_URL=' "${MW_ENV}" | sed -E 's/.*redis:\/\/:([^@]+)@.*/\1/' || true)
    elif [ -f "${ML_ENV}" ]; then
        REDIS_PW=$(grep -E '^REDIS_URL=' "${ML_ENV}" | sed -E 's/.*redis:\/\/:([^@]+)@.*/\1/' || true)
    fi
    if [ -z "${REDIS_PW}" ]; then
        REDIS_PW=$(openssl rand -hex 16)
    fi

    JWT_SECRET=$(openssl rand -hex 32)
    ML_SERVICE_PASS=$(openssl rand -hex 16)
    ML_SERVICE_HASH=$(node "${REPO_ROOT}/middleware/scripts/hash-password.js" "${ML_SERVICE_PASS}")

    echo
    echo "--- Configure Admin Credentials ---"
    read -r -p "Enter admin username [admin]: " ADMIN_INPUT
    ADMIN_USER="${ADMIN_INPUT:-admin}"

    while true; do
        read -s -r -p "Enter admin password (min 10 characters): " PW1
        echo
        read -s -r -p "Confirm admin password: " PW2
        echo
        if [ "${#PW1}" -lt 10 ]; then
            echo "Password must be at least 10 characters long. Please try again." >&2
            continue
        fi
        if [ "${PW1}" != "${PW2}" ]; then
            echo "Passwords do not match. Please try again." >&2
            continue
        fi
        ADMIN_PASS="${PW1}"
        break
    done

    ADMIN_HASH=$(node "${REPO_ROOT}/middleware/scripts/hash-password.js" "${ADMIN_PASS}")

    echo
    echo "--- Configure Telegram Alerts (Optional) ---"
    read -r -p "Enter Telegram Bot Token (leave blank to disable): " TG_TOKEN
    read -r -p "Enter Telegram Chat ID (leave blank to disable): " TG_CHAT

    if [ ! -f "${MW_ENV}" ]; then
        echo "Creating ${MW_ENV}..."
        cat <<EOF > "${MW_ENV}"
# Redis connection URL with password authentication
REDIS_URL=redis://:${REDIS_PW}@127.0.0.1:6379

# JWT secret key for signing tokens (8-hour session lifetime)
JWT_SECRET=${JWT_SECRET}

# Human admin account credentials (bcrypt hash generated with scripts/hash-password.js)
ADMIN_USERNAME=${ADMIN_USER}
ADMIN_PASSWORD_HASH=${ADMIN_HASH}

# ML Service service account credentials
ML_SERVICE_USERNAME=ml-service
ML_SERVICE_PASSWORD_HASH=${ML_SERVICE_HASH}

# HTTP and WebSocket port and host
PORT=4000
HOST=127.0.0.1

# DPI Engine management options
ENGINE_CONTROL_ENABLED=true
ENGINE_BIN=${REPO_ROOT}/engine/build/dpi_engine
EOF
        chmod 600 "${MW_ENV}"
        echo "Created ${MW_ENV} (mode 600)."
    else
        echo "Kept existing ${MW_ENV}."
    fi

    if [ ! -f "${ML_ENV}" ]; then
        echo "Creating ${ML_ENV}..."
        cat <<EOF > "${ML_ENV}"
# Redis connection URL
REDIS_URL=redis://:${REDIS_PW}@127.0.0.1:6379

# Middleware API base URL
MIDDLEWARE_URL=http://localhost:4000

# ML service account credentials for automated blocklist enforcement (/api/rules)
ML_SERVICE_USERNAME=ml-service
ML_SERVICE_PASSWORD=${ML_SERVICE_PASS}

# Comma-separated list of IPv4 addresses ignored from anomaly scoring
ML_IGNORE_IPS=10.10.0.1,172.21.38.198

# Telegram notification bot integration (optional)
TELEGRAM_BOT_TOKEN=${TG_TOKEN}
TELEGRAM_CHAT_ID=${TG_CHAT}
EOF
        chmod 600 "${ML_ENV}"
        echo "Created ${ML_ENV} (mode 600)."
    else
        echo "Kept existing ${ML_ENV}."
    fi
fi

# 8. Install restricted sudoers rule for the engine binary (validated with visudo -cf)
echo "==> Configuring restricted sudoers rule for engine binary..."
CURRENT_USER="$(id -un)"
ENGINE_BIN="${REPO_ROOT}/engine/build/dpi_engine"
SUDOERS_FILE="/etc/sudoers.d/aegis-engine"
RULE="${CURRENT_USER} ALL=(root) NOPASSWD: ${ENGINE_BIN}"

NEED_INSTALL=1
if [ -f "${SUDOERS_FILE}" ]; then
    if sudo -n grep -Fxq "${RULE}" "${SUDOERS_FILE}" 2>/dev/null; then
        echo "Sudoers rule in ${SUDOERS_FILE} is already present and matches."
        NEED_INSTALL=0
    fi
fi

if [ ${NEED_INSTALL} -eq 1 ]; then
    TMP_SUDO=$(mktemp)
    echo "${RULE}" > "${TMP_SUDO}"
    echo "Validating rule with visudo -cf..."
    if visudo -cf "${TMP_SUDO}" >/dev/null; then
        sudo cp "${TMP_SUDO}" "${SUDOERS_FILE}"
        sudo chmod 0440 "${SUDOERS_FILE}"
        echo "Installed restricted sudoers rule to ${SUDOERS_FILE}."
    else
        echo "Error: visudo -cf validation failed for generated sudoers rule." >&2
        rm -f "${TMP_SUDO}"
        exit 1
    fi
    rm -f "${TMP_SUDO}"
fi

echo "=========================================================="
echo "Setup complete. Run ./scripts/aegis.sh start and open http://localhost:4000"
echo "=========================================================="
