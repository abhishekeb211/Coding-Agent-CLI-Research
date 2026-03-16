# Managing Findings

## List Findings

List all findings from the last scan:
```bash
coding-agent-cli findings list
```

Filter by severity:
```bash
coding-agent-cli findings list --severity high
coding-agent-cli findings list --severity critical,high
```

Filter by CWE:
```bash
coding-agent-cli findings list --cwe CWE-89
```

## Show Finding Details

Show detailed information for a specific finding:
```bash
coding-agent-cli findings show <finding-id>
```

Output includes:
- CWE ID and description
- Severity and confidence
- File path and line number
- Code snippet
- Remediation guidance (if LLM enabled)

## Export Findings

Export findings to different formats:
```bash
coding-agent-cli findings export --format json --output findings.json
coding-agent-cli findings export --format csv --output findings.csv
```

## Finding Lifecycle

1. **Discovery**: Scanners detect vulnerabilities
2. **Normalization**: Findings mapped to CWE categories
3. **Storage**: Findings stored in database
4. **Enrichment**: LLM generates remediation guidance (optional)
5. **Policy Evaluation**: Policies applied to findings
6. **Reporting**: Findings exported in various formats
