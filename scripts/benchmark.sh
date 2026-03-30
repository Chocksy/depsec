#!/bin/bash
# depsec benchmark — test detection against real malware datasets
#
# Usage:
#   ./scripts/benchmark.sh /path/to/malware/dataset
#
# Expects the Datadog malicious-software-packages-dataset structure:
#   samples/npm/malicious_intent/package_name/version/zipfile.zip
#   samples/pypi/malicious_intent/package_name/version/zipfile.zip

set -euo pipefail

DATASET_DIR="${1:?Usage: benchmark.sh /path/to/dataset}"
DEPSEC_BIN="${2:-$(dirname "$0")/../target/release/depsec}"
RESULTS_DIR="${3:-/tmp/depsec-benchmark-results}"

mkdir -p "$RESULTS_DIR"

echo "depsec benchmark"
echo "================"
echo "Dataset: $DATASET_DIR"
echo "Binary:  $DEPSEC_BIN"
echo "Results: $RESULTS_DIR"
echo ""

# Check if depsec is built
if [ ! -f "$DEPSEC_BIN" ]; then
    echo "Building depsec (release)..."
    cd "$(dirname "$0")/.."
    cargo build --release 2>/dev/null
    DEPSEC_BIN="$(pwd)/target/release/depsec"
    cd -
fi

total=0
detected=0
missed=0
errors=0

# Process npm samples
process_sample() {
    local zip_file="$1"
    local ecosystem="$2"
    local pkg_name="$3"
    local extract_dir="/tmp/depsec-bench-extract"

    rm -rf "$extract_dir"
    mkdir -p "$extract_dir/node_modules/$pkg_name"

    # Extract (password: infected)
    unzip -o -P infected "$zip_file" -d "$extract_dir/node_modules/$pkg_name" >/dev/null 2>&1 || return 1

    # Create a minimal package.json for depsec
    echo "{\"name\":\"bench-victim\",\"version\":\"1.0.0\"}" > "$extract_dir/package.json"

    # Init git for secrets check
    cd "$extract_dir"
    git init -q 2>/dev/null
    git add -A 2>/dev/null
    git commit -m "init" -q 2>/dev/null
    cd - >/dev/null

    # Run depsec scan
    local output
    output=$("$DEPSEC_BIN" scan "$extract_dir" --persona auditor --format json 2>/dev/null) || true

    # Check if any findings were produced
    local finding_count
    finding_count=$(echo "$output" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    total = sum(len(r['findings']) for r in data['results'])
    print(total)
except:
    print(0)
" 2>/dev/null)

    # Cleanup
    rm -rf "$extract_dir"

    echo "$finding_count"
}

echo "Processing npm malicious_intent samples..."
if [ -d "$DATASET_DIR/samples/npm/malicious_intent" ]; then
    for pkg_dir in "$DATASET_DIR/samples/npm/malicious_intent"/*/; do
        pkg_name=$(basename "$pkg_dir")

        # Get first version's zip
        zip_file=$(find "$pkg_dir" -name "*.zip" -type f 2>/dev/null | head -1)
        if [ -z "$zip_file" ]; then
            continue
        fi

        total=$((total + 1))

        findings=$(process_sample "$zip_file" "npm" "$pkg_name" 2>/dev/null)

        if [ "$findings" -gt 0 ] 2>/dev/null; then
            detected=$((detected + 1))
            echo "  ✓ $pkg_name — $findings findings"
        else
            missed=$((missed + 1))
            echo "  ✗ $pkg_name — MISSED"
            echo "$pkg_name" >> "$RESULTS_DIR/missed.txt"
        fi

        # Progress every 50
        if [ $((total % 50)) -eq 0 ]; then
            echo "  ... processed $total packages so far ($detected detected, $missed missed)"
        fi
    done
fi

echo ""
echo "Processing pypi malicious_intent samples..."
if [ -d "$DATASET_DIR/samples/pypi/malicious_intent" ]; then
    for pkg_dir in "$DATASET_DIR/samples/pypi/malicious_intent"/*/; do
        pkg_name=$(basename "$pkg_dir")

        zip_file=$(find "$pkg_dir" -name "*.zip" -type f 2>/dev/null | head -1)
        if [ -z "$zip_file" ]; then
            continue
        fi

        total=$((total + 1))

        # For PyPI, extract to .venv/site-packages
        extract_dir="/tmp/depsec-bench-extract"
        rm -rf "$extract_dir"
        mkdir -p "$extract_dir/.venv/lib/python3.11/site-packages/$pkg_name"
        unzip -o -P infected "$zip_file" -d "$extract_dir/.venv/lib/python3.11/site-packages/$pkg_name" >/dev/null 2>&1 || continue
        echo "{}" > "$extract_dir/package.json"
        cd "$extract_dir" && git init -q 2>/dev/null && git add -A 2>/dev/null && git commit -m "init" -q 2>/dev/null && cd - >/dev/null

        output=$("$DEPSEC_BIN" scan "$extract_dir" --persona auditor --format json 2>/dev/null) || true
        findings=$(echo "$output" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    total = sum(len(r['findings']) for r in data['results'])
    print(total)
except:
    print(0)
" 2>/dev/null)

        rm -rf "$extract_dir"

        if [ "$findings" -gt 0 ] 2>/dev/null; then
            detected=$((detected + 1))
        else
            missed=$((missed + 1))
            echo "  ✗ $pkg_name — MISSED"
            echo "$pkg_name" >> "$RESULTS_DIR/missed.txt"
        fi

        if [ $((total % 50)) -eq 0 ]; then
            echo "  ... processed $total packages ($detected detected, $missed missed)"
        fi
    done
fi

# Summary
echo ""
echo "=============================="
echo "BENCHMARK RESULTS"
echo "=============================="
echo "Total packages tested: $total"
echo "Detected (≥1 finding): $detected"
echo "Missed (0 findings):   $missed"
echo "Errors:                $errors"
if [ $total -gt 0 ]; then
    rate=$((detected * 100 / total))
    echo "Detection rate:        ${rate}%"
fi
echo ""
echo "Missed packages saved to: $RESULTS_DIR/missed.txt"

# Save results JSON
cat > "$RESULTS_DIR/results.json" << EOF
{
    "tool": "depsec",
    "version": "$($DEPSEC_BIN --version 2>/dev/null | head -1)",
    "dataset": "$DATASET_DIR",
    "total": $total,
    "detected": $detected,
    "missed": $missed,
    "detection_rate": ${rate:-0}
}
EOF

echo "Results JSON saved to: $RESULTS_DIR/results.json"
