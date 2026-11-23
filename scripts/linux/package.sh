#!/usr/bin/env bash
# Packages production JARs into dist/ (excluding demo and test code)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

if [ ! -d "out/eastguard" ]; then
    echo "No build found in out/. Building first..."
    ./scripts/linux/sources.sh
    javac --release 21 -d out "@sources.txt"
fi

mkdir -p dist

# 1. Operator UI Dashboard (Executable JAR)
jar --create --file dist/eastguard-dashboard.jar --main-class eastguard.dashboard.DashboardApp \
    -C out eastguard/dashboard \
    -C out eastguard/control \
    -C out eastguard/common \
    -C out eastguard/handlers

# 2. Backend Daemons (Gateway, Control Plane, Token Service, Threat Detector, Bus)
jar --create --file dist/eastguard-server.jar \
    -C out eastguard/gateway \
    -C out eastguard/control \
    -C out eastguard/tokensvc \
    -C out eastguard/detector \
    -C out eastguard/bus \
    -C out eastguard/common \
    -C out eastguard/client \
    -C out eastguard/handlers

# 3. Workload Client SDK Library
jar --create --file dist/eastguard-client.jar \
    -C out eastguard/client \
    -C out eastguard/common

echo "Production packages created in dist/:"
ls -lh dist/*.jar
