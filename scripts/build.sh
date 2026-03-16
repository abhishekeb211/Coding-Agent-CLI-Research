#!/bin/bash
# Multi-platform build script for Coding Agent CLI

set -e

VERSION="1.0.0"
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
DIST_DIR="dist"

# Platform configurations
PLATFORMS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
    "windows/amd64"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "Building Coding Agent CLI v${VERSION}"
echo "========================================"

# Create dist directory
mkdir -p "${DIST_DIR}"

# Track build results
SUCCESSFUL_BUILDS=()
FAILED_BUILDS=()

# Build for each platform
for platform in "${PLATFORMS[@]}"; do
    GOOS=${platform%/*}
    GOARCH=${platform#*/}
    
    output="coding-agent-cli-${VERSION}-${GOOS}-${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
        output="${output}.exe"
    fi
    
    echo ""
    echo -e "${YELLOW}Building for ${GOOS}/${GOARCH}...${NC}"
    
    # Build binary
    if GOOS=$GOOS GOARCH=$GOARCH go build \
        -ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME}" \
        -o "${DIST_DIR}/${output}" \
        . ; then
        
        echo -e "${GREEN}✓ Build successful${NC}"
        SUCCESSFUL_BUILDS+=("${GOOS}/${GOARCH}")
        
        # Generate SHA256 checksum
        if [ "$GOOS" = "darwin" ]; then
            shasum -a 256 "${DIST_DIR}/${output}" | awk '{print $1}' > "${DIST_DIR}/${output}.sha256"
        else
            sha256sum "${DIST_DIR}/${output}" | awk '{print $1}' > "${DIST_DIR}/${output}.sha256"
        fi
        echo -e "${GREEN}✓ Checksum generated${NC}"
        
        # Create archive
        if [ "$GOOS" = "windows" ]; then
            # Create zip for Windows
            (cd "${DIST_DIR}" && zip -q "${output%.exe}.zip" "${output}" ../README.md ../LICENSE)
            echo -e "${GREEN}✓ Archive created: ${output%.exe}.zip${NC}"
        else
            # Create tar.gz for Unix
            tar czf "${DIST_DIR}/${output}.tar.gz" \
                -C "${DIST_DIR}" "${output}" \
                -C .. README.md LICENSE
            echo -e "${GREEN}✓ Archive created: ${output}.tar.gz${NC}"
        fi
        
        # Verify binary
        if [ "$GOOS" = "$(go env GOOS)" ] && [ "$GOARCH" = "$(go env GOARCH)" ]; then
            if "${DIST_DIR}/${output}" --version > /dev/null 2>&1; then
                echo -e "${GREEN}✓ Binary verification passed${NC}"
            else
                echo -e "${RED}✗ Binary verification failed${NC}"
                FAILED_BUILDS+=("${GOOS}/${GOARCH} (verification)")
            fi
        fi
        
    else
        echo -e "${RED}✗ Build failed${NC}"
        FAILED_BUILDS+=("${GOOS}/${GOARCH}")
    fi
done

# Print summary
echo ""
echo "========================================"
echo "Build Summary"
echo "========================================"
echo ""

if [ ${#SUCCESSFUL_BUILDS[@]} -gt 0 ]; then
    echo -e "${GREEN}Successful builds (${#SUCCESSFUL_BUILDS[@]}):${NC}"
    for build in "${SUCCESSFUL_BUILDS[@]}"; do
        echo "  ✓ $build"
    done
fi

if [ ${#FAILED_BUILDS[@]} -gt 0 ]; then
    echo ""
    echo -e "${RED}Failed builds (${#FAILED_BUILDS[@]}):${NC}"
    for build in "${FAILED_BUILDS[@]}"; do
        echo "  ✗ $build"
    done
    echo ""
    exit 1
fi

echo ""
echo -e "${GREEN}All builds completed successfully!${NC}"
echo "Artifacts available in: ${DIST_DIR}/"
echo ""

# List generated files
echo "Generated files:"
ls -lh "${DIST_DIR}/" | grep -v "^total" | awk '{print "  " $9 " (" $5 ")"}'

exit 0
