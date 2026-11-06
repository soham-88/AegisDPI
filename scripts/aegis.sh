#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
LOGS_DIR="${REPO_ROOT}/logs"
RUN_DIR="${REPO_ROOT}/run"

mkdir -p "${LOGS_DIR}" "${RUN_DIR}"

# Extract Redis password from middleware/.env (REDIS_URL=redis://:<pw>@...)
REDIS_PW=""
if [ -f "${REPO_ROOT}/middleware/.env" ]; then
    REDIS_PW=$(grep -E '^REDIS_URL=' "${REPO_ROOT}/middleware/.env" | sed -E 's/.*redis:\/\/:([^@]+)@.*/\1/' || true)
fi
if [ -z "${REDIS_PW}" ]; then
    echo "ERROR: Could not read REDIS_URL from middleware/.env. Run scripts/setup.sh first." >&2
    exit 1
fi

is_port_open() {
    local port="$1"
    (exec 3<>/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1 && exec 3>&-
}

wait_for_port() {
    local svc="$1"
    local port="$2"
    local timeout=20
    local start_time
    start_time=$(date +%s)
    while true; do
        if is_port_open "${port}"; then
            echo "${svc}: OK"
            return 0
        fi
        local now
        now=$(date +%s)
        if [ $((now - start_time)) -ge ${timeout} ]; then
            echo "${svc}: FAILED"
            return 1
        fi
        sleep 0.5
    done
}

start_ml() {
    if is_port_open 8000; then
        echo "ML: port 8000 already open, skipping start"
    else
        local uvicorn_bin="${REPO_ROOT}/ml-service/venv/bin/uvicorn"
        if [ ! -x "${uvicorn_bin}" ]; then
            uvicorn_bin="uvicorn"
        fi
        pushd "${REPO_ROOT}/ml-service" > /dev/null
        nohup "${uvicorn_bin}" main:app --host 127.0.0.1 --port 8000 >> "${LOGS_DIR}/ml.log" 2>&1 &
        echo $! > "${RUN_DIR}/ml.pid"
        popd > /dev/null
    fi
}

stop_ml() {
    if [ -f "${RUN_DIR}/ml.pid" ]; then
        local ml_pid
        ml_pid=$(cat "${RUN_DIR}/ml.pid" 2>/dev/null || true)
        if [ -n "${ml_pid}" ] && kill -0 "${ml_pid}" 2>/dev/null; then
            kill -TERM "${ml_pid}" 2>/dev/null || true
            for _ in $(seq 1 10); do
                if ! kill -0 "${ml_pid}" 2>/dev/null; then break; fi
                sleep 0.5
            done
        fi
        rm -f "${RUN_DIR}/ml.pid"
    fi
    # Fallback if ML was started outside script
    if is_port_open 8000; then
        pkill -TERM -f "uvicorn main:app" 2>/dev/null || true
        for _ in $(seq 1 8); do
            if ! is_port_open 8000; then break; fi
            sleep 0.5
        done
    fi
}

restart_ml() {
    echo "Stopping ML service..."
    stop_ml
    echo "Starting ML service..."
    start_ml
    wait_for_port "ML" 8000
}

start_services() {
    # 1. Redis (6379)
    if is_port_open 6379; then
        echo "Redis: port 6379 already open, skipping start"
    else
        redis-server --requirepass "${REDIS_PW}" --bind 127.0.0.1 --daemonize yes --dir "${REPO_ROOT}"
    fi

    # 2. ML Service (8000)
    start_ml

    # 3. Middleware (4000)
    if is_port_open 4000; then
        echo "Middleware: port 4000 already open, skipping start"
    else
        pushd "${REPO_ROOT}/middleware" > /dev/null
        NODE_ENV=production nohup node server.js >> "${LOGS_DIR}/middleware.log" 2>&1 &
        echo $! > "${RUN_DIR}/middleware.pid"
        popd > /dev/null
    fi

    # Wait until 6379, 4000 and 8000 answer (20 s timeout each)
    local all_ok=0
    wait_for_port "Redis" 6379 || all_ok=1
    wait_for_port "Middleware" 4000 || all_ok=1
    wait_for_port "ML" 8000 || all_ok=1

    if [ ${all_ok} -eq 0 ]; then
        echo "Open http://localhost:4000"
    else
        echo "One or more services failed to start within 20s"
        return 1
    fi
}

stop_services() {
    # 1. Stop Middleware via PID file
    if [ -f "${RUN_DIR}/middleware.pid" ]; then
        local mw_pid
        mw_pid=$(cat "${RUN_DIR}/middleware.pid" 2>/dev/null || true)
        if [ -n "${mw_pid}" ] && kill -0 "${mw_pid}" 2>/dev/null; then
            kill -TERM "${mw_pid}" 2>/dev/null || true
            for _ in $(seq 1 14); do
                if ! kill -0 "${mw_pid}" 2>/dev/null; then break; fi
                sleep 0.5
            done
        fi
        rm -f "${RUN_DIR}/middleware.pid"
    fi
    # Fallback if middleware was started outside script
    if is_port_open 4000; then
        pkill -TERM -f "node server.js" 2>/dev/null || true
        for _ in $(seq 1 12); do
            if ! is_port_open 4000; then break; fi
            sleep 0.5
        done
    fi

    # 2. Stop ML
    stop_ml

    # 3. Stop Redis
    redis-cli -a "${REDIS_PW}" --no-auth-warning shutdown 2>/dev/null || redis-cli shutdown 2>/dev/null || true
    for _ in $(seq 1 8); do
        if ! is_port_open 6379; then break; fi
        sleep 0.5
    done

    # 4. Confirm no dpi_engine process remains
    if pgrep -f "dpi_engine" >/dev/null 2>&1; then
        echo "dpi_engine process: STILL RUNNING"
    else
        echo "dpi_engine process: none"
    fi

    # 5. Confirm no nft table inet aegis remains
    local nft_check
    nft_check=$(sudo -n nft list table inet aegis 2>&1 || true)
    if echo "${nft_check}" | grep -qi "table inet aegis"; then
        echo "nft table inet aegis: STILL PRESENT"
    else
        echo "nft table inet aegis: none"
    fi
}

status_services() {
    if is_port_open 6379; then
        echo "Redis: OK"
    else
        echo "Redis: DOWN"
    fi

    if is_port_open 4000; then
        echo "Middleware: OK"
    else
        echo "Middleware: DOWN"
    fi

    if is_port_open 8000; then
        echo "ML: OK"
    else
        echo "ML: DOWN"
    fi

    if pgrep -f "dpi_engine" >/dev/null 2>&1; then
        echo "Engine: running"
    else
        echo "Engine: stopped"
    fi
}

logs_service() {
    local svc="${1:-}"
    if [ -z "${svc}" ]; then
        echo "Usage: $0 logs <svc>"
        exit 1
    fi

    case "${svc}" in
        middleware|node)
            local logfile="${LOGS_DIR}/middleware.log"
            touch "${logfile}"
            tail -f "${logfile}"
            ;;
        ml|ml-service|uvicorn)
            local logfile="${LOGS_DIR}/ml.log"
            touch "${logfile}"
            tail -f "${logfile}"
            ;;
        redis)
            local logfile="${LOGS_DIR}/redis.log"
            if [ -f "${logfile}" ]; then
                tail -f "${logfile}"
            else
                echo "Redis log at ${logfile} does not exist (Redis is daemonized to syslog / working directory)"
            fi
            ;;
        *)
            local logfile="${LOGS_DIR}/${svc}.log"
            if [ -f "${logfile}" ]; then
                tail -f "${logfile}"
            else
                echo "Unknown service log: ${svc}. Expected: middleware | ml | redis"
                exit 1
            fi
            ;;
    esac
}

case "${1:-}" in
    start)
        start_services
        ;;
    stop)
        stop_services
        ;;
    status)
        status_services
        ;;
    restart-ml)
        restart_ml
        ;;
    logs)
        shift
        logs_service "${1:-}"
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart-ml|logs <svc>}"
        exit 1
        ;;
esac
