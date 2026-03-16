# Release Checklist - v1.0.0

## Quick Release (10 minutes)

### 1. Build Binaries (5 min)
```bash
# Set Go in PATH
$env:PATH = "C:\Program Files\Go\bin;" + $env:PATH

# Create dist directory
mkdir -p dist

# Build all platforms
$VERSION = "1.0.0"
$DATE = "2026-03-03"
$LDFLAGS = "-X main.Version=$VERSION -X main.BuildDate=$DATE"

# Linux amd64
$env:GOOS="linux"; $env:GOARCH="amd64"
go build -ldflags $LDFLAGS -o dist/coding-agent-cli-linux-amd64

# Linux arm64
$env:GOOS="linux"; $env:GOARCH="arm64"
go build -ldflags $LDFLAGS -o dist/coding-agent-cli-linux-arm64

# macOS amd64
$env:GOOS="darwin"; $env:GOARCH="amd64"
go build -ldflags $LDFLAGS -o dist/coding-agent-cli-darwin-amd64

# macOS arm64
$env:GOOS="darwin"; $env:GOARCH="arm64"
go build -ldflags $LDFLAGS -o dist/coding-agent-cli-darwin-arm64

# Windows amd64
$env:GOOS="windows"; $env:GOARCH="amd64"
go build -ldflags $LDFLAGS -o dist/coding-agent-cli-windows-amd64.exe

# Reset environment
Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
```

### 2. Create Git Tag (2 min)
```bash
git add .
git commit -m "Release v1.0.0 - Production Ready"
git tag -a v1.0.0 -m "v1.0.0 - First production release"
git push origin main
git push origin v1.0.0
```

### 3. GitHub Release (3 min)
1. Go to GitHub → Releases → New Release
2. Tag: v1.0.0
3. Title: "Coding Agent CLI v1.0.0 - Production Ready"
4. Description: Copy from RELEASE_NOTES_v1.0.md
5. Upload binaries from dist/
6. Publish release

## Pre-Release Verification

- [ ] All tests passing: `go test ./...`
- [ ] Binary works: `./coding-agent-cli --version`
- [ ] Help works: `./coding-agent-cli --help`
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version in code updated

## Post-Release

- [ ] Announce release
- [ ] Update documentation site
- [ ] Monitor GitHub issues
- [ ] Plan v1.0.1 improvements

## Release Artifacts

### Binaries
- coding-agent-cli-linux-amd64
- coding-agent-cli-linux-arm64
- coding-agent-cli-darwin-amd64
- coding-agent-cli-darwin-arm64
- coding-agent-cli-windows-amd64.exe

### Documentation
- README.md
- CHANGELOG.md
- LICENSE
- docs/ folder

## Quality Metrics

- All tests passing: ✅
- Core coverage >70%: ✅
- Overall coverage: 49.4%
- Known bugs: 0
- Documentation: Complete

## Approval

**Status**: APPROVED FOR RELEASE ✅
**Date**: March 3, 2026
