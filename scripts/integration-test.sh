#!/bin/bash
# Integration test script for agent-protocols
# Runs all protocol examples and verifies they complete successfully.
#
# Usage:
#   ./scripts/integration-test.sh          # Run all examples
#   ./scripts/integration-test.sh --quick  # Run only core protocol examples
#
# Exit codes:
#   0 - All examples passed
#   1 - One or more examples failed

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Change to repo root
cd "$(dirname "$0")/.."

PASSED=0
FAILED=0
SKIPPED=0

# Function to run an example and check for success
run_example() {
    local name="$1"
    local path="$2"
    local expected_output="$3"
    local timeout_seconds="${4:-30}"

    printf "%-50s " "$name..."

    # Check if the example directory exists
    if [ ! -d "$path" ]; then
        echo -e "${YELLOW}SKIP${NC} (directory not found)"
        ((SKIPPED++))
        return 0
    fi

    # Run the example with timeout
    output=$(timeout "$timeout_seconds" go run "./$path" 2>&1) || {
        exit_code=$?
        if [ $exit_code -eq 124 ]; then
            echo -e "${RED}FAIL${NC} (timeout after ${timeout_seconds}s)"
        else
            echo -e "${RED}FAIL${NC} (exit code $exit_code)"
        fi
        echo "Output:"
        echo "$output" | head -20
        ((FAILED++))
        return 1
    }

    # Check for expected output pattern
    if echo "$output" | grep -q "$expected_output"; then
        echo -e "${GREEN}PASS${NC}"
        ((PASSED++))
        return 0
    else
        echo -e "${RED}FAIL${NC} (expected output not found)"
        echo "Expected: $expected_output"
        echo "Output:"
        echo "$output" | head -20
        ((FAILED++))
        return 1
    fi
}

echo "========================================"
echo "Agent Protocols Integration Tests"
echo "========================================"
echo ""

# Parse arguments
QUICK_MODE=false
if [ "$1" == "--quick" ]; then
    QUICK_MODE=true
    echo "Running in quick mode (core protocols only)"
    echo ""
fi

echo "--- Core Protocol Examples ---"
echo ""

# AAuth examples
run_example "aauth/simple (identity-only flow)" \
    "aauth/examples/simple" \
    "Identity-only flow completed successfully"

run_example "aauth/resource-managed (resource token flow)" \
    "aauth/examples/resource-managed" \
    "Resource-managed flow completed"

run_example "aauth/delegation (human delegation flow)" \
    "aauth/examples/delegation" \
    "Delegation flow completed"

# ID-JAG examples
run_example "idjag/simple (token exchange flow)" \
    "idjag/examples/simple" \
    "Demo completed successfully"

run_example "idjag/delegation (assertion delegation)" \
    "idjag/examples/delegation" \
    "Demo completed successfully"

# AIMS examples
run_example "aims/simple (workload identity flow)" \
    "aims/examples/simple" \
    "Demo completed successfully"

run_example "aims/mtls (mutual TLS flow)" \
    "aims/examples/mtls" \
    "Demo completed successfully"

if [ "$QUICK_MODE" = false ]; then
    echo ""
    echo "--- Multi-Protocol Demo ---"
    echo ""

    run_example "demos/multi-protocol" \
        "demos/multi-protocol" \
        "Demo Completed Successfully" \
        60  # Longer timeout for multi-protocol demo

    echo ""
    echo "--- Adapter Examples ---"
    echo ""

    # Note: Adapter examples may require external services
    # They are marked as optional and will be skipped if dependencies are missing

    # Zitadel adapter examples (require Zitadel server)
    if [ -d "adapters/zitadel/examples" ]; then
        echo "(Zitadel examples require external Zitadel server - skipping)"
        ((SKIPPED+=3))
    fi

    # SharkAuth adapter examples (require SharkAuth server)
    if [ -d "adapters/sharkauth/examples" ]; then
        echo "(SharkAuth examples require external SharkAuth server - skipping)"
        ((SKIPPED+=1))
    fi

    # Ory adapter examples (require Ory Hydra server)
    if [ -d "adapters/ory/examples" ]; then
        echo "(Ory examples require external Ory Hydra server - skipping)"
        ((SKIPPED+=1))
    fi
fi

echo ""
echo "========================================"
echo "Results"
echo "========================================"
echo -e "Passed:  ${GREEN}$PASSED${NC}"
echo -e "Failed:  ${RED}$FAILED${NC}"
echo -e "Skipped: ${YELLOW}$SKIPPED${NC}"
echo ""

if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Integration tests FAILED${NC}"
    exit 1
else
    echo -e "${GREEN}All integration tests PASSED${NC}"
    exit 0
fi
