# Quickstart Guide

Get started with Coding Agent CLI in 5 minutes.

## Step 0: Start the Web Dashboard (Optional)

For a visual interface, start the web dashboard:

```bash
coding-agent-cli serve
```

Then open your browser to: `http://localhost:8080`

The dashboard provides:
- Visual finding browser
- Interactive analytics and charts
- Scan history
- Security score tracking

Continue with the CLI steps below, or use the web interface!

## Step 1: Run Your First Scan

Scan a directory for security vulnerabilities:

```bash
coding-agent-cli scan /path/to/your/code
```

Example output:
```
Starting security scan...
Target: /path/to/your/code
Scanners: bandit, semgrep

Running bandit...
Running semgrep...

Scan complete!
Total findings: 15
  Critical: 2
  High: 5
  Medium: 6
  Low: 2

Results saved to: scan-results.json
```

## Step 2: View Findings

List all findings from the last scan:

```bash
coding-agent-cli findings list
```

Show details for a specific finding:

```bash
coding-agent-cli findings show <finding-id>
```

## Step 3: Generate a Report

Generate a report in your preferred format:

**JSON Report**:
```bash
coding-agent-cli report --format json --output report.json
```

**SARIF Report** (for CI/CD integration):
```bash
coding-agent-cli report --format sarif --output report.sarif
```

**HTML Report** (for viewing in browser):
```bash
coding-agent-cli report --format html --output report.html
```

**Markdown Report**:
```bash
coding-agent-cli report --format markdown --output report.md
```

## Step 4: Apply Security Policies

Create a simple policy file `policy.yaml`:

```yaml
policies:
  - id: block-sql-injection
    name: Block SQL Injection
    description: Deny SQL injection vulnerabilities
    enabled: true
    action: deny
    severity: high
    cwe:
      - CWE-89
```

Run scan with policy enforcement:

```bash
coding-agent-cli scan /path/to/code --policy policy.yaml
```

## Common Scan Options

**Scan with specific scanners**:
```bash
coding-agent-cli scan /path/to/code --scanners bandit,semgrep
```

**Scan in offline mode** (no LLM remediation):
```bash
coding-agent-cli scan /path/to/code --offline
```

**Scan with custom output**:
```bash
coding-agent-cli scan /path/to/code --output my-results.json --format json
```

## Next Steps

- Explore the [Web Dashboard](10-web-dashboard.md) for visual analysis
- Learn about [Configuration Options](03-configuration.md)
- Explore [Scanning Options](04-scanning.md)
- Try [New Scanners](12-scanners.md) (gosec, eslint)
- Create [Custom Policies](06-policies.md)
- Set up [Real LLM Integration](08-llm-integration.md) (OpenAI, Anthropic, Ollama)
- Configure [CI/CD Integration](13-cicd-integration.md)
- Set up [Webhooks](14-webhooks.md) for notifications
