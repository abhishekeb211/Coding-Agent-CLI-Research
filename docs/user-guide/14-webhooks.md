# Webhooks

## Overview

Webhooks allow you to receive real-time notifications when security scans complete or critical findings are discovered. Send notifications to Slack, Discord, Microsoft Teams, or custom endpoints.

## Configuration

### Basic Webhook

Configure webhooks in `config.yaml`:

```yaml
webhooks:
  - id: slack-notifications
    url: https://hooks.slack.com/services/YOUR/WEBHOOK/URL
    events:
      - scan_complete
      - critical_finding
    enabled: true
```

### Multiple Webhooks

Configure multiple webhook endpoints:

```yaml
webhooks:
  - id: slack-security
    url: https://hooks.slack.com/services/YOUR/WEBHOOK/URL
    events:
      - scan_complete
      - critical_finding
      - policy_violation
    enabled: true
  
  - id: discord-alerts
    url: https://discord.com/api/webhooks/YOUR/WEBHOOK
    events:
      - critical_finding
    enabled: true
  
  - id: custom-endpoint
    url: https://api.example.com/security-alerts
    events:
      - scan_complete
    secret: your-webhook-secret
    enabled: true
```

## Event Types

### scan_complete

Triggered when a scan finishes:

```json
{
  "event": "scan_complete",
  "timestamp": "2026-03-03T10:00:00Z",
  "scan_id": "abc123",
  "path": "/path/to/code",
  "duration_seconds": 300,
  "summary": {
    "total_findings": 42,
    "critical": 2,
    "high": 8,
    "medium": 20,
    "low": 12
  },
  "scanners": ["bandit", "semgrep", "gosec"],
  "url": "http://localhost:8080/scans/abc123"
}
```

### critical_finding

Triggered when a critical severity finding is discovered:

```json
{
  "event": "critical_finding",
  "timestamp": "2026-03-03T10:00:00Z",
  "scan_id": "abc123",
  "finding": {
    "id": "finding-456",
    "severity": "critical",
    "cwe": "CWE-89",
    "title": "SQL Injection",
    "file": "app/database.py",
    "line": 42,
    "scanner": "bandit"
  },
  "url": "http://localhost:8080/findings/finding-456"
}
```

### policy_violation

Triggered when a policy is violated:

```json
{
  "event": "policy_violation",
  "timestamp": "2026-03-03T10:00:00Z",
  "scan_id": "abc123",
  "policy": {
    "id": "block-sql-injection",
    "name": "Block SQL Injection",
    "action": "deny"
  },
  "finding": {
    "id": "finding-456",
    "severity": "critical",
    "cwe": "CWE-89",
    "title": "SQL Injection"
  },
  "url": "http://localhost:8080/findings/finding-456"
}
```

### high_finding

Triggered when a high severity finding is discovered:

```json
{
  "event": "high_finding",
  "timestamp": "2026-03-03T10:00:00Z",
  "scan_id": "abc123",
  "finding": {
    "id": "finding-789",
    "severity": "high",
    "cwe": "CWE-79",
    "title": "Cross-Site Scripting (XSS)",
    "file": "app/views.py",
    "line": 123
  }
}
```

## Popular Integrations

### Slack

1. **Create Slack Webhook**:
   - Go to https://api.slack.com/apps
   - Create a new app
   - Enable Incoming Webhooks
   - Add webhook to workspace
   - Copy webhook URL

2. **Configure**:
```yaml
webhooks:
  - id: slack-security
    url: https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXX
    events:
      - scan_complete
      - critical_finding
    enabled: true
```

Slack will receive formatted messages:

```
🔒 Security Scan Complete

Path: /path/to/code
Duration: 5m 0s

Findings:
🔴 Critical: 2
🟠 High: 8
🟡 Medium: 20
🟢 Low: 12

View Results: http://localhost:8080/scans/abc123
```

### Discord

1. **Create Discord Webhook**:
   - Go to Server Settings → Integrations
   - Create Webhook
   - Copy webhook URL

2. **Configure**:
```yaml
webhooks:
  - id: discord-alerts
    url: https://discord.com/api/webhooks/123456789/abcdefghijklmnop
    events:
      - critical_finding
    enabled: true
```

### Microsoft Teams

1. **Create Teams Webhook**:
   - Go to channel → Connectors
   - Configure Incoming Webhook
   - Copy webhook URL

2. **Configure**:
```yaml
webhooks:
  - id: teams-security
    url: https://outlook.office.com/webhook/YOUR-WEBHOOK-URL
    events:
      - scan_complete
      - critical_finding
    enabled: true
```

### Custom Endpoint

For custom integrations:

```yaml
webhooks:
  - id: custom-api
    url: https://api.example.com/security-alerts
    events:
      - scan_complete
      - critical_finding
      - policy_violation
    secret: your-webhook-secret
    headers:
      X-API-Key: your-api-key
      Content-Type: application/json
    enabled: true
```

## Webhook Security

### HMAC Signatures

Verify webhook authenticity using HMAC signatures:

```yaml
webhooks:
  - id: secure-webhook
    url: https://api.example.com/webhooks
    secret: your-secret-key
    enabled: true
```

The webhook payload includes a signature header:
```
X-Webhook-Signature: sha256=abc123...
```

Verify in your endpoint:

```python
import hmac
import hashlib

def verify_webhook(payload, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

### Custom Headers

Add authentication headers:

```yaml
webhooks:
  - id: authenticated-webhook
    url: https://api.example.com/webhooks
    headers:
      Authorization: Bearer your-token
      X-API-Key: your-api-key
    enabled: true
```

## Retry Logic

Webhooks automatically retry on failure:

```yaml
webhooks:
  - id: reliable-webhook
    url: https://api.example.com/webhooks
    retry:
      max_attempts: 3
      initial_delay: 1s
      max_delay: 30s
      exponential_backoff: true
    enabled: true
```

Retry behavior:
- Attempt 1: Immediate
- Attempt 2: After 1 second
- Attempt 3: After 2 seconds
- Attempt 4: After 4 seconds (up to max_delay)

## Webhook Management

### CLI Commands

**List webhooks**:
```bash
coding-agent-cli webhook list
```

**Add webhook**:
```bash
coding-agent-cli webhook add \
  --id slack-alerts \
  --url https://hooks.slack.com/services/YOUR/WEBHOOK \
  --events scan_complete,critical_finding
```

**Test webhook**:
```bash
coding-agent-cli webhook test slack-alerts
```

**Delete webhook**:
```bash
coding-agent-cli webhook delete slack-alerts
```

**View delivery log**:
```bash
coding-agent-cli webhook deliveries --webhook-id slack-alerts
```

### API Endpoints

**Create webhook**:
```http
POST /api/v1/webhooks
Content-Type: application/json

{
  "id": "slack-alerts",
  "url": "https://hooks.slack.com/services/YOUR/WEBHOOK",
  "events": ["scan_complete", "critical_finding"],
  "enabled": true
}
```

**List webhooks**:
```http
GET /api/v1/webhooks
```

**Test webhook**:
```http
POST /api/v1/webhooks/{id}/test
```

**Delete webhook**:
```http
DELETE /api/v1/webhooks/{id}
```

**View deliveries**:
```http
GET /api/v1/webhooks/{id}/deliveries
```

## Filtering Events

Filter events by severity or scanner:

```yaml
webhooks:
  - id: critical-only
    url: https://hooks.slack.com/services/YOUR/WEBHOOK
    events:
      - critical_finding
    filters:
      severity:
        - critical
    enabled: true
  
  - id: bandit-findings
    url: https://api.example.com/bandit-alerts
    events:
      - scan_complete
    filters:
      scanners:
        - bandit
    enabled: true
```

## Webhook Templates

Customize webhook payload format:

```yaml
webhooks:
  - id: custom-format
    url: https://api.example.com/webhooks
    events:
      - scan_complete
    template: |
      {
        "service": "coding-agent-cli",
        "alert_type": "{{ .Event }}",
        "timestamp": "{{ .Timestamp }}",
        "details": {
          "scan_id": "{{ .ScanID }}",
          "findings": {{ .Summary.TotalFindings }},
          "critical": {{ .Summary.Critical }}
        }
      }
    enabled: true
```

## Troubleshooting

### Webhook Not Firing

Check webhook configuration:
```bash
coding-agent-cli webhook list
```

Verify webhook is enabled:
```yaml
webhooks:
  - id: my-webhook
    enabled: true  # Must be true
```

### Delivery Failures

View delivery log:
```bash
coding-agent-cli webhook deliveries --webhook-id my-webhook --failed
```

Common issues:
- Invalid URL
- Network connectivity
- Endpoint timeout
- Authentication failure

### Testing Webhooks

Test webhook manually:
```bash
coding-agent-cli webhook test my-webhook
```

This sends a test payload to verify connectivity.

### Debugging

Enable verbose logging:
```yaml
logging:
  level: debug
  webhooks: true
```

View webhook logs:
```bash
coding-agent-cli logs --component webhooks
```

## Best Practices

1. **Use HMAC signatures**: Verify webhook authenticity
2. **Set retry limits**: Prevent infinite retry loops
3. **Filter events**: Only receive relevant notifications
4. **Test webhooks**: Verify configuration before production
5. **Monitor deliveries**: Check delivery logs regularly
6. **Secure secrets**: Store webhook secrets securely
7. **Rate limit**: Avoid overwhelming endpoints

## Examples

### Slack Notification with Rich Formatting

```yaml
webhooks:
  - id: slack-rich
    url: https://hooks.slack.com/services/YOUR/WEBHOOK
    events:
      - scan_complete
    template: |
      {
        "blocks": [
          {
            "type": "header",
            "text": {
              "type": "plain_text",
              "text": "🔒 Security Scan Complete"
            }
          },
          {
            "type": "section",
            "fields": [
              {"type": "mrkdwn", "text": "*Path:*\n{{ .Path }}"},
              {"type": "mrkdwn", "text": "*Duration:*\n{{ .Duration }}"}
            ]
          },
          {
            "type": "section",
            "fields": [
              {"type": "mrkdwn", "text": "*Critical:*\n{{ .Summary.Critical }}"},
              {"type": "mrkdwn", "text": "*High:*\n{{ .Summary.High }}"},
              {"type": "mrkdwn", "text": "*Medium:*\n{{ .Summary.Medium }}"},
              {"type": "mrkdwn", "text": "*Low:*\n{{ .Summary.Low }}"}
            ]
          }
        ]
      }
```

### PagerDuty Integration

```yaml
webhooks:
  - id: pagerduty
    url: https://events.pagerduty.com/v2/enqueue
    events:
      - critical_finding
    headers:
      Content-Type: application/json
    template: |
      {
        "routing_key": "YOUR_INTEGRATION_KEY",
        "event_action": "trigger",
        "payload": {
          "summary": "Critical security finding: {{ .Finding.Title }}",
          "severity": "critical",
          "source": "coding-agent-cli",
          "custom_details": {
            "file": "{{ .Finding.File }}",
            "line": {{ .Finding.Line }},
            "cwe": "{{ .Finding.CWE }}"
          }
        }
      }
```

## Next Steps

- Configure [CI/CD Integration](13-cicd-integration.md)
- Set up [Policies](06-policies.md) for webhook triggers
- Learn about [REST API](11-rest-api.md) for custom integrations
