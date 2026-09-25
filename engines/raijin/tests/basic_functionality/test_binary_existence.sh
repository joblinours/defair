#!/bin/bash

# Test: Binary Existence
# Description: Verify that both raijin and raijin-util binaries exist and are executable
# Expected: Both binaries should exist in build/ directory and be executable

set -euo pipefail

echo "=== Testing Binary Existence ==="

# Track test results
test_passed=true

# Test raijin binary existence
echo "Testing raijin binary..."
if [ -f "./build/raijin" ] && [ -x "./build/raijin" ]; then
    echo "✓ raijin binary: PASS (exists and executable)"
else
    echo "✗ raijin binary: FAIL (missing or not executable)"
    echo "  Expected: ./build/raijin to exist and be executable"
    if [ -f "./build/raijin" ]; then
        echo "  Actual: File exists but is not executable"
        ls -la ./build/raijin
    else
        echo "  Actual: File does not exist"
        echo "  Contents of ./build/:"
        ls -la ./build/ 2>&1 || echo "  Directory does not exist"
    fi
    test_passed=false
fi

# Test raijin-util binary existence
echo "Testing raijin-util binary..."
if [ -f "./build/raijin-util" ] && [ -x "./build/raijin-util" ]; then
    echo "✓ raijin-util binary: PASS (exists and executable)"
else
    echo "✗ raijin-util binary: FAIL (missing or not executable)"
    echo "  Expected: ./build/raijin-util to exist and be executable"
    if [ -f "./build/raijin-util" ]; then
        echo "  Actual: File exists but is not executable"
        ls -la ./build/raijin-util
    else
        echo "  Actual: File does not exist"
    fi
    test_passed=false
fi

# Overall test result
if [ "$test_passed" = true ]; then
    echo "=== Binary Existence Test: PASS ==="
    exit 0
else
    echo "=== Binary Existence Test: FAIL ==="
    exit 1
fi
