#!/bin/bash
# Phase-based implementation check and automated test loop for Coding Agent CLI.
# Run from repository root: ./scripts/test-phases.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

FAILED_PHASES=()
FAILED_SUBTASKS=()

run_build() {
    local desc="$1"
    shift
    echo -e "${YELLOW}Build: ${desc}${NC}"
    if go build "$@"; then
        echo -e "${GREEN}  OK${NC}"
        return 0
    else
        echo -e "${RED}  FAILED${NC}"
        return 1
    fi
}

run_test() {
    local label="$1"
    shift
    if go test -v -count=1 "$@"; then
        echo -e "${GREEN}  ${label}: PASS${NC}"
        return 0
    else
        echo -e "${RED}  ${label}: FAIL${NC}"
        return 1
    fi
}

echo "=========================================="
echo "Coding Agent CLI - Phase implementation check and tests"
echo "=========================================="

# Step 1: Global implementation check
echo ""
echo -e "${YELLOW}Step 1: Global build (implementation check)${NC}"
if ! run_build "go build ./..." ./...; then
    echo -e "${RED}Implementation check failed. Fix build before running phase tests.${NC}"
    exit 1
fi

# Step 2: Phase loop with subtasks (do not exit on first failure; record and continue)
echo ""
echo -e "${YELLOW}Step 2: Phase loop (build + test per phase)${NC}"

# Phase 1: Foundation
echo ""
echo "--- Phase 1: Foundation ---"
run_build "Phase 1 packages" ./cmd/... ./internal/storage/... || FAILED_PHASES+=("1")
run_test "cmd" ./cmd/... || FAILED_SUBTASKS+=("Phase1:cmd")
run_test "internal/storage" ./internal/storage/... || FAILED_SUBTASKS+=("Phase1:storage")

# Phase 2: Scanner integration
echo ""
echo "--- Phase 2: Scanner integration ---"
run_build "Phase 2 packages" ./internal/scanner/... ./plugins/bandit/... ./plugins/semgrep/... || FAILED_PHASES+=("2")
run_test "internal/scanner" ./internal/scanner/... || FAILED_SUBTASKS+=("Phase2:scanner")
run_test "plugins/bandit" ./plugins/bandit/... || FAILED_SUBTASKS+=("Phase2:bandit")
run_test "plugins/semgrep" ./plugins/semgrep/... || FAILED_SUBTASKS+=("Phase2:semgrep")

# Phase 3: Normalization
echo ""
echo "--- Phase 3: Normalization ---"
run_build "Phase 3 packages" ./internal/cwe/... ./internal/sarif/... || FAILED_PHASES+=("3")
run_test "internal/cwe" ./internal/cwe/... || FAILED_SUBTASKS+=("Phase3:cwe")
run_test "internal/sarif" ./internal/sarif/... || FAILED_SUBTASKS+=("Phase3:sarif")

# Phase 4: LLM
echo ""
echo "--- Phase 4: LLM ---"
run_build "Phase 4 packages" ./internal/llm/... || FAILED_PHASES+=("4")
run_test "internal/llm" ./internal/llm/... || FAILED_SUBTASKS+=("Phase4:llm")

# Phase 5: Policy engine
echo ""
echo "--- Phase 5: Policy engine ---"
run_build "Phase 5 packages" ./internal/policy/... || FAILED_PHASES+=("5")
run_test "internal/policy" ./internal/policy/... || FAILED_SUBTASKS+=("Phase5:policy")

# Phase 6: CLI and reporting
echo ""
echo "--- Phase 6: CLI and reporting ---"
run_build "Phase 6 packages" ./cmd/... ./internal/importer/... ./internal/exporter/... || FAILED_PHASES+=("6")
run_test "cmd" ./cmd/... || FAILED_SUBTASKS+=("Phase6:cmd")
run_test "internal/importer" ./internal/importer/... || FAILED_SUBTASKS+=("Phase6:importer")
run_test "internal/exporter" ./internal/exporter/... || FAILED_SUBTASKS+=("Phase6:exporter")

# Phase 7: Integration tests
echo ""
echo "--- Phase 7: Testing and docs (integration tests) ---"
run_test "tests/integration" -tags=integration ./tests/integration/... || FAILED_SUBTASKS+=("Phase7:integration")

# Summary
echo ""
echo "=========================================="
echo "Summary"
echo "=========================================="
if [ ${#FAILED_PHASES[@]} -eq 0 ] && [ ${#FAILED_SUBTASKS[@]} -eq 0 ]; then
    echo -e "${GREEN}All phases and subtasks PASSED.${NC}"
    exit 0
fi
if [ ${#FAILED_PHASES[@]} -gt 0 ]; then
    echo -e "${RED}Failed phase builds: ${FAILED_PHASES[*]}${NC}"
fi
if [ ${#FAILED_SUBTASKS[@]} -gt 0 ]; then
    echo -e "${RED}Failed subtasks: ${FAILED_SUBTASKS[*]}${NC}"
fi
exit 1
