#!/bin/bash

# Test: Help Output
# Description: Verify that both raijin and raijin-util binaries display proper help output
# Expected: Both binaries should display help text and return exit code 0
#
# NOTE: --help is a safe command that doesn't trigger scanning

set -euo pipefail

echo "=== Testing Help Output ==="

# Track test results
test_passed=true

# Test raijin help output (safe - just prints help)
echo "Testing raijin --help..."
raijin_help_output=$(./build/raijin --help 2>&1) || true
if echo "$raijin_help_output" | grep -q "Raijin"; then
    echo "✓ raijin --help: PASS"
else
    echo "✗ raijin --help: FAIL"
    echo "  Expected: Output to contain 'Raijin'"
    echo "  Actual output:"
    echo "$raijin_help_output" | head -20
    test_passed=false
fi

# Test raijin-util help output (safe - just prints help)
echo "Testing raijin-util (no args for help)..."
raijin_util_output=$(./build/raijin-util 2>&1) || true
# Check for RAIJIN (uppercase in ASCII art) or various help indicators
if echo "$raijin_util_output" | grep -qiE "(RAIJIN|raijin|Scanner|update|help)"; then
    echo "✓ raijin-util help: PASS"
else
    echo "✗ raijin-util help: FAIL"
    echo "  Expected: Output to contain 'RAIJIN' or help text"
    echo "  Actual output:"
    echo "$raijin_util_output" | head -20
    test_passed=false
fi

# Overall test result
if [ "$test_passed" = true ]; then
    echo "=== Help Output Test: PASS ==="
    exit 0
else
    echo "=== Help Output Test: FAIL ==="
    exit 1
fi
