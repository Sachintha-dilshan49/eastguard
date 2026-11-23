#!/usr/bin/env bash
# Resets the EastGuard end-to-end demo: deletes the demo journal and logs, then bootstraps a fresh journal.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
JOURNAL="${ROOT}/journal/demo-control.journal"
LOGS="${ROOT}/logs"

KEEP_LOGS=false
for arg in "$@"; do
    case "${arg}" in
        -KeepLogs|--keep-logs)
            KEEP_LOGS=true
            ;;
    esac
done

command -v java >/dev/null 2>&1 || { echo "java not found on PATH: install JDK 21+" >&2; exit 1; }

if [ ! -f "${ROOT}/out/eastguard/control/ControlPlaneImpl.class" ]; then
    echo "out/ has no build: run ./scripts/linux/sources.sh and javac --release 21 -d out \"@sources.txt\" first" >&2
    exit 1
fi

for f in keys/lease-k1.cer keys/control-k1.cer keys/control-credentials.properties; do
    if [ ! -f "${ROOT}/${f}" ]; then
        echo "${f} not found: run ./scripts/linux/gen-certs.sh and ./scripts/linux/gen-credentials.sh first" >&2
        exit 1
    fi
done

if [ -f "${JOURNAL}" ]; then
    rm -f "${JOURNAL}"
    echo "deleted journal/demo-control.journal"
fi

if [ "${KEEP_LOGS}" = false ] && [ -d "${LOGS}" ]; then
    rm -rf "${LOGS}"/*
    echo "cleared logs/"
fi

mkdir -p "${ROOT}/journal" "${LOGS}"

cd "${ROOT}"
java -cp out eastguard.control.ControlPlaneImpl bootstrap \
    --config config/demo-control.properties.example \
    --state config/demo-bootstrap.properties.example \
    --actor admin --reason 'demo reset: deny-by-default policy for app-02 and app-03'

echo "demo reset complete"

