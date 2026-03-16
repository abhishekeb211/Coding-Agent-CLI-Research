# Installation Guide

## System Requirements

- **Operating System**: Linux, macOS, or Windows
- **Go**: Version 1.21 or higher (for building from source)
- **Scanner Dependencies**:
  - Python 3.8+ (for Bandit and Semgrep)
  - Bandit: `pip install bandit`
  - Semgrep: `pip install semgrep`
  - gosec: `go install github.com/securego/gosec/v2/cmd/gosec@latest` (optional, for Go code)
  - ESLint: `npm install -g eslint eslint-plugin-security` (optional, for JavaScript/TypeScript)

## Installation Methods

### Option 1: Download Pre-built Binary

Download the latest release for your platform from the [releases page](https://github.com/coding-agent/cli/releases):

**Linux (amd64)**:
```bash
wget https://github.com/coding-agent/cli/releases/download/v1.0.0/coding-agent-cli-1.0.0-linux-amd64.tar.gz
tar -xzf coding-agent-cli-1.0.0-linux-amd64.tar.gz
sudo mv coding-agent-cli /usr/local/bin/
```

**macOS (amd64)**:
```bash
curl -LO https://github.com/coding-agent/cli/releases/download/v1.0.0/coding-agent-cli-1.0.0-darwin-amd64.tar.gz
tar -xzf coding-agent-cli-1.0.0-darwin-amd64.tar.gz
sudo mv coding-agent-cli /usr/local/bin/
```

**Windows (amd64)**:
Download the `.zip` file and extract `coding-agent-cli.exe` to a directory in your PATH.

### Option 2: Build from Source

```bash
git clone https://github.com/coding-agent/cli.git
cd cli
go build -o coding-agent-cli .
sudo mv coding-agent-cli /usr/local/bin/
```

### Option 3: Install with Go

```bash
go install github.com/coding-agent/cli@latest
```

## Installing Scanner Dependencies

### Bandit (Python Security Scanner)

```bash
pip install bandit
```

Verify installation:
```bash
bandit --version
```

### Semgrep (Multi-language Security Scanner)

```bash
pip install semgrep
```

Verify installation:
```bash
semgrep --version
```

### gosec (Go Security Scanner) - Optional

For scanning Go code:

```bash
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

Verify installation:
```bash
gosec --version
```

### ESLint with Security Plugin (JavaScript/TypeScript) - Optional

For scanning JavaScript and TypeScript code:

```bash
npm install -g eslint eslint-plugin-security
```

Verify installation:
```bash
eslint --version
```

Create `.eslintrc.json` in your project:
```json
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended"]
}
```

## Verify Installation

Check that the CLI is installed correctly:

```bash
coding-agent-cli --version
```

You should see output like:
```
coding-agent-cli version 1.0.0
```

## Next Steps

- Read the [Quickstart Guide](02-quickstart.md) to run your first scan
- Configure the tool using the [Configuration Guide](03-configuration.md)
