# Web Dashboard

## Overview

The web dashboard provides a browser-based interface for viewing scan results, analyzing trends, and managing security findings. It offers an intuitive alternative to the CLI for teams who prefer visual interfaces.

## Starting the Web Server

Start the embedded web server:

```bash
coding-agent-cli serve
```

By default, the dashboard is available at: `http://localhost:8080`

### Server Options

**Custom port**:
```bash
coding-agent-cli serve --port 3000
```

**Custom host**:
```bash
coding-agent-cli serve --host 0.0.0.0 --port 8080
```

**With TLS** (optional):
```bash
coding-agent-cli serve --tls --cert server.crt --key server.key
```

## Dashboard Features

### Home Page

The home page displays:
- **Scan Summary**: Total findings by severity (critical, high, medium, low)
- **Recent Scans**: List of recent scan runs with timestamps
- **Severity Breakdown**: Visual chart showing finding distribution
- **Top CWE Categories**: Most common vulnerability types

### Findings List

Browse all findings with:
- **Sorting**: By severity, date, file, CWE
- **Filtering**: By severity level, scanner, file path, CWE category
- **Pagination**: Navigate through large result sets
- **Search**: Find specific findings by keyword

### Finding Details

Click any finding to view:
- Complete vulnerability information
- File location and line numbers
- Code snippet with context
- CWE category and description
- AI-powered remediation guidance
- Related findings

### Analytics Dashboard

View security trends over time:
- **Trend Charts**: Finding counts by severity over time
- **New vs. Resolved**: Track remediation progress
- **Mean Time to Remediation (MTTR)**: Average time to fix issues
- **Security Score**: Overall security posture metric
- **Hotspot Files**: Files with the most findings
- **Scanner Effectiveness**: Findings per scanner

### Scan History

Review past scans:
- List of all scan runs
- Scan duration and timestamp
- Finding counts per scan
- Compare scans side-by-side

## Theme Support

Toggle between light and dark themes using the theme switcher in the navigation bar. Your preference is saved automatically.

## Progressive Web App (PWA)

The dashboard works offline after the initial load:
- Install as a desktop app (Chrome, Edge)
- Access cached data without internet
- Sync when connection is restored

**To install**:
1. Visit the dashboard in Chrome/Edge
2. Click the install icon in the address bar
3. Follow the prompts

## Keyboard Shortcuts

- `Ctrl/Cmd + K`: Open search
- `Ctrl/Cmd + /`: Show keyboard shortcuts
- `Esc`: Close modals/dialogs
- Arrow keys: Navigate lists

## Performance Tips

For large codebases with thousands of findings:
- Use filters to narrow results
- Enable pagination (default: 50 items per page)
- Use the search function for specific findings
- Consider incremental scanning (see [Scanning Guide](04-scanning.md))

## Security Considerations

The web dashboard:
- Runs locally on your machine
- Does not send data to external servers
- Supports optional authentication (see [Authentication](#authentication))
- Can be secured with TLS for network access

### Authentication

Enable authentication for multi-user environments:

```yaml
# config.yaml
web:
  auth:
    enabled: true
    type: basic  # or jwt
    users:
      - username: admin
        password_hash: <bcrypt-hash>
        role: admin
```

Generate password hash:
```bash
coding-agent-cli auth hash-password
```

## Troubleshooting

**Port already in use**:
```bash
# Use a different port
coding-agent-cli serve --port 8081
```

**Dashboard not loading**:
- Check that the server is running
- Verify firewall settings
- Try accessing `http://127.0.0.1:8080` instead of `localhost`

**Slow performance**:
- Clear browser cache
- Reduce the number of displayed findings using filters
- Consider database optimization (see [Performance Guide](11-performance.md))

## Next Steps

- Learn about the [REST API](11-rest-api.md) for programmatic access
- Explore [Analytics](12-analytics.md) features
- Set up [CI/CD Integration](13-cicd-integration.md)
