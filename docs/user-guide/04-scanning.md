# Scanning Guide

## Basic Scanning

Scan a directory:
```bash
coding-agent-cli scan /path/to/code
```

Scan current directory:
```bash
coding-agent-cli scan .
```

## Scanner Selection

Use specific scanners:
```bash
coding-agent-cli scan /path --scanners bandit
coding-agent-cli scan /path --scanners semgrep
coding-agent-cli scan /path --scanners bandit,semgrep
```

## Output Formats

### JSON Output
```bash
coding-agent-cli scan /path --format json --output results.json
```

### SARIF Output (for CI/CD)
```bash
coding-agent-cli scan /path --format sarif --output results.sarif
```

### Markdown Report
```bash
coding-agent-cli scan /path --format markdown --output report.md
```

### HTML Report
```bash
coding-agent-cli scan /path --format html --output report.html
```

## Offline Mode

Scan without LLM remediation:
```bash
coding-agent-cli scan /path --offline
```

## Policy Enforcement

Scan with policy enforcement:
```bash
coding-agent-cli scan /path --policy policy.yaml
```

## Common Scenarios

### CI/CD Integration
```bash
coding-agent-cli scan . --format sarif --output results.sarif --offline --policy ci-policy.yaml
```

### Development Workflow
```bash
coding-agent-cli scan . --scanners bandit,semgrep --format markdown --output report.md
```

### Security Audit
```bash
coding-agent-cli scan /project --policy security-audit.yaml --format html --output audit-report.html
```
