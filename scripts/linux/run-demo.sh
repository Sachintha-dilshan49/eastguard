#!/usr/bin/env bash
# Starts the EastGuard end-to-end demo: every component as its own JVM process, in spec §9.2 order.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
LOGS="${ROOT}/logs"
JOURNAL="${ROOT}/journal/demo-control.journal"

RESET=false
RUN_FINAL=false
READY_SECONDS=60
FINAL_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        -Reset|--reset)
            RESET=true
            shift
            ;;
        -RunFinal|--run-final)
            RUN_FINAL=true
            shift
            ;;
        -ReadySeconds|--ready-seconds)
            READY_SECONDS="$2"
            shift 2
            ;;
        -FinalArgs|--final-args)
            shift
            while [[ $# -gt 0 && ! "$1" =~ ^- ]]; do
                FINAL_ARGS+=("$1")
                shift
            done
            ;;
        *)
            FINAL_ARGS+=("$1")
            shift
            ;;
    esac
done

command -v java >/dev/null 2>&1 || { echo "java not found on PATH: install JDK 21+" >&2; exit 1; }

JAVA_VER=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | awk -F '.' '{print $1}')
if [ -n "${JAVA_VER}" ] && [ "${JAVA_VER}" -lt 21 ]; then
    echo "JDK 21 or newer required, found: ${JAVA_VER}" >&2
    exit 1
fi

assert_prerequisites() {
    for f in out/eastguard/demos/Launch.class out/eastguard/demos/DemoFinal.class out/eastguard/demos/HealthProbe.class; do
        if [ ! -f "${ROOT}/${f}" ]; then
            echo "${f} not found: build first (./scripts/linux/sources.sh && javac --release 21 -d out \"@sources.txt\")" >&2
            exit 1
        fi
    done

    local missing=()
    for f in truststore.p12 control.p12 detector.p12 tokensvc.p12 gateway-app-02.p12 \
             gateway-app-03.p12 console.p12 workload-web-01.p12 workload-api-01.p12 lease-signer.p12 \
             control-signer.p12 lease-k1.cer control-k1.cer control-credentials.properties \
             api/admin.secret api/operator.secret api/viewer.secret api/tokensvc.secret \
             api/detector.secret api/gw-app-02.secret api/gw-app-03.secret \
             telemetry/gw-app-02.key telemetry/gw-app-03.key telemetry/tokensvc.key; do
        if [ ! -f "${ROOT}/keys/${f}" ]; then
            missing+=("keys/${f}")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo "missing keys: ${missing[*]}" >&2
        echo "Run ./scripts/linux/gen-certs.sh and ./scripts/linux/gen-credentials.sh first." >&2
        exit 1
    fi
}

write_logging_config() {
    cat << 'EOF' > "${LOGS}/logging.properties"
handlers=java.util.logging.ConsoleHandler
.level=INFO
java.util.logging.ConsoleHandler.level=INFO
java.util.logging.ConsoleHandler.formatter=java.util.logging.SimpleFormatter
java.util.logging.SimpleFormatter.format=%1$tH:%1$tM:%1$tS.%1$tL %4$-7s %3$s - %5$s%6$s%n
EOF
}

declare -a STARTED_NAMES=()
declare -a STARTED_PIDS=()

stop_all() {
    if [ ${#STARTED_NAMES[@]} -eq 0 ]; then return; fi
    echo ""
    echo "stopping the demo components (reverse start order)..."
    for (( i=${#STARTED_NAMES[@]}-1; i>=0; i-- )); do
        local name="${STARTED_NAMES[i]}"
        local pid="${STARTED_PIDS[i]}"
        touch "${LOGS}/${name}.stop"
        local stopped=false
        for _ in {1..20}; do
            if ! kill -0 "$pid" 2>/dev/null; then
                stopped=true
                break
            fi
            sleep 0.5
        done
        if [ "$stopped" = false ]; then
            kill -9 "$pid" 2>/dev/null || true
            echo "  $name did not stop within 10 s: killed"
        else
            echo "  $name stopped"
        fi
        rm -f "${LOGS}/${name}.stop"
    done
    STARTED_NAMES=()
    STARTED_PIDS=()
}

trap stop_all EXIT INT TERM

wait_ready() {
    local name="$1"
    local pid="$2"
    local check_type="$3"
    local check_val="$4"
    local deadline=$((SECONDS + READY_SECONDS))

    while [ $SECONDS -lt $deadline ]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            echo "---- last lines of logs/${name}.log:" >&2
            tail -n 15 "${LOGS}/${name}.log" >&2 || true
            echo "$name exited prematurely" >&2
            return 1
        fi
        case "$check_type" in
            health)
                if java -cp out eastguard.demos.HealthProbe "$check_val" >/dev/null 2>&1; then
                    return 0
                fi
                ;;
            out)
                if grep -q -F "$check_val" "${LOGS}/${name}.out.log" 2>/dev/null; then
                    return 0
                fi
                ;;
            log)
                if grep -q -F "$check_val" "${LOGS}/${name}.log" 2>/dev/null; then
                    return 0
                fi
                ;;
        esac
        sleep 0.2
    done
    echo "$name not ready after ${READY_SECONDS}s" >&2
    return 1
}

start_component() {
    local name="$1"
    local cls="$2"
    local check_type="$3"
    local check_val="$4"
    local shows="$5"
    shift 5
    local args=("$@")

    rm -f "${LOGS}/${name}.stop" "${LOGS}/${name}.out.log" "${LOGS}/${name}.log"

    java -cp out -Djava.util.logging.config.file="${LOGS}/logging.properties" \
        eastguard.demos.Launch --stop-file "${LOGS}/${name}.stop" --watch-pid $$ \
        "$cls" "${args[@]}" > "${LOGS}/${name}.out.log" 2> "${LOGS}/${name}.log" &
    local pid=$!

    STARTED_NAMES+=("$name")
    STARTED_PIDS+=("$pid")

    local t0=$SECONDS
    wait_ready "$name" "$pid" "$check_type" "$check_val"
    local elapsed=$((SECONDS - t0))
    printf "  %-15s pid %-6s ready in %2d s   %s\n" "$name" "$pid" "$elapsed" "$shows"
}

cd "${ROOT}"

if [ "${RESET}" = true ] || [ ! -f "${JOURNAL}" ]; then
    "${SCRIPT_DIR}/reset-demo.sh"
fi

assert_prerequisites
mkdir -p "${LOGS}"
write_logging_config

CONFIG_DIR="config"
if ! ip link show lo 2>/dev/null | grep -q "MULTICAST"; then
    echo "  note: interface lo does not have MULTICAST flag; falling back to polling mode (spec §9.1)"
    CONFIG_DIR="${LOGS}/config"
    mkdir -p "${CONFIG_DIR}"
    for cfg in config/demo-*.properties.example config/token.properties.example config/gateway-app-*.properties.example; do
        sed '/^multicast\./d' "${cfg}" > "${CONFIG_DIR}/$(basename "${cfg}")"
    done
fi

echo "starting the EastGuard demo from ${ROOT} (logs in logs/)"

start_component "control" "eastguard.control.ControlPlaneImpl" "health" "https://127.0.0.1:9443/health/ready" \
    "RMI 127.0.0.1:1099/1100, audit https://127.0.0.1:9443" --config "${CONFIG_DIR}/demo-control.properties.example"

DETECTOR_START=$SECONDS
start_component "detector" "eastguard.detector.ThreatDetector" "log" "threat detector started" \
    "UDP 127.0.0.1:5514" --config "${CONFIG_DIR}/demo-detector.properties.example"

start_component "tokensvc" "eastguard.tokensvc.TokenServer" "log" "installed enforcement revision" \
    "mTLS 127.0.0.1:8443" --config "${CONFIG_DIR}/token.properties.example"

start_component "backend-7002" "eastguard.demos.EchoBackend" "out" "echo backend listening" \
    "private backend of app-02" 127.0.0.1:7002

start_component "gateway-app-02" "eastguard.gateway.NioGateway" "log" "installed enforcement revision" \
    "mTLS 127.0.0.1:9002, decoy 127.0.0.1:9003" --config "${CONFIG_DIR}/gateway-app-02.properties.example"

start_component "backend-7003" "eastguard.demos.EchoBackend" "out" "echo backend listening" \
    "private backend of app-03" 127.0.0.1:7003

start_component "gateway-app-03" "eastguard.gateway.NioGateway" "log" "installed enforcement revision" \
    "mTLS 127.0.0.1:9004" --config "${CONFIG_DIR}/gateway-app-03.properties.example"

# Wait out acceptanceMillis for detector restart guard
GUARD_SEC=30
DETECTOR_ELAPSED=$((SECONDS - DETECTOR_START))
LEFT=$((GUARD_SEC - DETECTOR_ELAPSED))
if [ $LEFT -gt 0 ]; then
    echo "  waiting ${LEFT} s for the detector's restart guard (30000 ms) to end"
    sleep $LEFT
fi

echo ""
echo "demo is ready."

if [ "${RUN_FINAL}" = true ]; then
    java -cp out eastguard.demos.DemoFinal "${FINAL_ARGS[@]}" | tee "${LOGS}/demofinal.out.log"
else
    echo "  final demo:  java -cp out eastguard.demos.DemoFinal       (in a second terminal, project root)"
    echo "  dashboard:   java -cp out eastguard.dashboard.DashboardApp --config config/dashboard.properties.example"
    echo "Press Ctrl+C to stop every component."
    while true; do
        for (( i=0; i<${#STARTED_PIDS[@]}; i++ )); do
            if ! kill -0 "${STARTED_PIDS[i]}" 2>/dev/null; then
                echo "${STARTED_NAMES[i]} exited unexpectedly" >&2
                exit 1
            fi
        done
        sleep 1
    done
fi
