#!/usr/bin/env bash
# Regenerates sources.txt (the javac argument file) from every .java file under src/ and test/.
# Run from the project root: ./scripts/sources.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

find src test -type f -name "*.java" | LC_ALL=C sort > sources.txt
COUNT=$(wc -l < sources.txt)
echo "sources.txt: $COUNT files"

