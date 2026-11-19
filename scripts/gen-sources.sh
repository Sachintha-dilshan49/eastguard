#!/bin/sh
# Regenerates sources.txt (the javac argument file) from every .java file under src/ and test/.
# Run from anywhere:  sh scripts/gen-sources.sh
# Paths use forward slashes and are sorted bytewise so output matches scripts/gen-sources.ps1.
set -eu
cd "$(dirname "$0")/.."
for dir in src test; do
    [ -d "$dir" ] && find "$dir" -type f -name '*.java'
done | LC_ALL=C sort > sources.txt
echo "sources.txt: $(wc -l < sources.txt | tr -d ' ') files"
