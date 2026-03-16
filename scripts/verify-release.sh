#!/bin/bash
# Release verification script

set -e

VERSION="1.0.0"
DIST_DIR="dist"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Verifying Release Artifacts v${VERSION}"
echo "========================================"

FAILED_CHECKS=()

# Function to run verification check
verify_check() {
    local check_name="$1"
    local check_command="$2"
    
    echo -n "Checking ${check_name}... "
    
    if eval "$check_command" > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}✗${NC}"
        FAILED_CHECKS+=("$check_name")
        return 1
    fi
}

# Verify dist directory exists
if [ ! -d "${DIST_DIR}" ]; then
    echo -e "${RED}Error: ${DIST_DIR} directory not found${NC}"
    exit 1
fi

# Get current platform binary
CURRENT_OS=$(go env GOOS)
CURRENT_ARCH=$(go env GOARCH)
CURRENT_BINARY="${DIST_DIR}/coding-agent-cli-${VERSION}-${CURRENT_OS}-${CURRENT_ARCH}"

if [ "$CURRENT_OS" = "windows" ]; then
    CURRENT_BINARY="${CURRENT_BINARY}.exe"
fi

echo ""
echo "Verifying binary for current platform: ${CURRENT_OS}/${CURRENT_ARCH}"
echo ""

# Check 1: Binary exists
verify_check "Binary exists" "[ -f '${CURRENT_BINARY}' ]"

# Check 2: Binary is executable
verify_check "Binary is executable" "[ -x '${CURRENT_BINARY}' ]"

# Check 3: Version information
verify_check "Version information" "'${CURRENT_BINARY}' --version | grep -q '${VERSION}'"

# Check 4: Help command
verify_check "Help command" "'${CURRENT_BINARY}' --help"

# Check 5: Checksum file exists
verify_check "Checksum file exists" "[ -f '${CURRENT_BINARY}.sha256' ]"

# Check 6: Checksum matches
if [ -f "${CURRENT_BINARY}.sha256" ]; then
    EXPECTED_CHECKSUM=$(cat "${CURRENT_BINARY}.sha256")
    if [ "$CURRENT_OS" = "darwin" ]; then
        ACTUAL_CHECKSUM=$(shasum -a 256 "${CURRENT_BINARY}" | awk '{print $1}')
    else
        ACTUAL_CHECKSUM=$(sha256sum "${CURRENT_BINARY}" | awk '{print $1}')
    fi
    verify_check "Checksum matches" "[ '${EXPECTED_CHECKSUM}' = '${ACTUAL_CHECKSUM}' ]"
fi

# Check 7: Archive exists
if [ "$CURRENT_OS" = "windows" ]; then
    ARCHIVE="${DIST_DIR}/coding-agent-cli-${VERSION}-${CURRENT_OS}-${CURRENT_ARCH}.zip"
else
    ARCHIVE="${DIST_DIR}/coding-agent-cli-${VERSION}-${CURRENT_OS}-${CURRENT_ARCH}.tar.gz"
fi
verify_check "Archive exists" "[ -f '${ARCHIVE}' ]"

# Check 8: Archive can be extracted
if [ -f "${ARCHIVE}" ]; then
    TEMP_DIR=$(mktemp -d)
    if [ "$CURRENT_OS" = "windows" ]; then
        verify_check "Archive extraction" "unzip -q '${ARCHIVE}' -d '${TEMP_DIR}'"
    else
        verify_check "Archive extraction" "tar -xzf '${ARCHIVE}' -C '${TEMP_DIR}'"
    fi
    rm -rf "${TEMP_DIR}"
fi

# Check 9: README and LICENSE in archive
echo -n "Checking archive contents... "
TEMP_DIR=$(mktemp -d)
if [ "$CURRENT_OS" = "windows" ]; then
    unzip -q "${ARCHIVE}" -d "${TEMP_DIR}" 2>/dev/null || true
else
    tar -xzf "${ARCHIVE}" -C "${TEMP_DIR}" 2>/dev/null || true
fi

if [ -f "${TEMP_DIR}/README.md" ] && [ -f "${TEMP_DIR}/LICENSE" ]; then
    echo -e "${GREEN}✓${NC}"
else
    echo -e "${RED}✗${NC}"
    FAILED_CHECKS+=("Archive contents")
fi
rm -rf "${TEMP_DIR}"

# Check 10: Basic scan test (if testdata exists)
if [ -d "testdata/vulnerable-code" ]; then
    echo -n "Checking basic scan operation... "
    TEMP_OUTPUT=$(mktemp)
    if "${CURRENT_BINARY}" scan testdata/vulnerable-code --offline --output "${TEMP_OUTPUT}" --format json > /dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
    else
        echo -e "${RED}✗${NC}"
        FAILED_CHECKS+=("Basic scan operation")
    fi
    rm -f "${TEMP_OUTPUT}"
fi

# Summary
echo ""
echo "========================================"
echo "Verification Summary"
echo "========================================"
echo ""

if [ ${#FAILED_CHECKS[@]} -eq 0 ]; then
    echo -e "${GREEN}All verification checks passed!${NC}"
    echo ""
    echo "Release artifacts are ready for distribution."
    exit 0
else
    echo -e "${RED}Failed checks (${#FAILED_CHECKS[@]}):${NC}"
    for check in "${FAILED_CHECKS[@]}"; do
        echo "  ✗ $check"
    done
    echo ""
    echo -e "${RED}Release verification failed!${NC}"
    echo "Please fix the issues before releasing."
    exit 1
fi
