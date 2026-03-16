# Report Generation

## Generate Reports

Generate a report from the last scan:
```bash
coding-agent-cli report --format json --output report.json
```

## Report Formats

### JSON Report
```bash
coding-agent-cli report --format json --output report.json
```

Contains:
- Scan metadata
- All findings with details
- Policy decisions
- Statistics

### SARIF Report
```bash
coding-agent-cli report --format sarif --output report.sarif
```

SARIF 2.1.0 compliant format for:
- GitHub Code Scanning
- Azure DevOps
- GitLab Security Dashboard

### Markdown Report
```bash
coding-agent-cli report --format markdown --output report.md
```

Human-readable report with:
- Executive summary
- Findings by severity
- Remediation guidance

### HTML Report
```bash
coding-agent-cli report --format html --output report.html
```

Interactive HTML report with:
- Sortable tables
- Filtering options
- Charts and graphs

### CSV Export
```bash
coding-agent-cli report --format csv --output report.csv
```

Spreadsheet-compatible format for:
- Data analysis
- Tracking over time
- Custom reporting

## Report Customization

Filter report by severity:
```bash
coding-agent-cli report --severity high,critical --format html
```

Include only policy violations:
```bash
coding-agent-cli report --violations-only --format json
```
