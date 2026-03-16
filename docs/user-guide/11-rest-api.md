# REST API

## Overview

The REST API provides programmatic access to all Coding Agent CLI functionality, enabling integration with automation workflows, custom tools, and third-party systems.

## API Server

The API is served by the same web server as the dashboard:

```bash
coding-agent-cli serve --port 8080
```

API base URL: `http://localhost:8080/api/v1`

## Authentication

### API Tokens

Generate an API token:

```bash
coding-agent-cli auth create-token --name "CI Pipeline"
```

Use the token in requests:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8080/api/v1/scans
```

### Basic Authentication

If basic auth is enabled:

```bash
curl -u username:password http://localhost:8080/api/v1/scans
```

## API Endpoints

### Scans

#### Trigger a New Scan

```http
POST /api/v1/scans
Content-Type: application/json

{
  "path": "/path/to/code",
  "scanners": ["bandit", "semgrep", "gosec"],
  "policies": ["./policies/security.yaml"]
}
```

Response:
```json
{
  "scan_id": "abc123",
  "status": "running",
  "started": "2026-03-03T10:00:00Z"
}
```

#### List Scans

```http
GET /api/v1/scans?limit=50&offset=0
```

Response:
```json
{
  "scans": [
    {
      "id": "abc123",
      "path": "/path/to/code",
      "status": "completed",
      "started": "2026-03-03T10:00:00Z",
      "completed": "2026-03-03T10:05:00Z",
      "findings_count": 42
    }
  ],
  "total": 100,
  "page": 1,
  "page_size": 50
}
```

#### Get Scan Details

```http
GET /api/v1/scans/{id}
```

Response:
```json
{
  "id": "abc123",
  "path": "/path/to/code",
  "status": "completed",
  "started": "2026-03-03T10:00:00Z",
  "completed": "2026-03-03T10:05:00Z",
  "duration_seconds": 300,
  "scanners": ["bandit", "semgrep"],
  "findings": {
    "critical": 2,
    "high": 8,
    "medium": 20,
    "low": 12
  }
}
```

### Findings

#### List Findings

```http
GET /api/v1/findings?severity=critical,high&limit=50&offset=0
```

Query parameters:
- `severity`: Filter by severity (critical, high, medium, low)
- `cwe`: Filter by CWE ID (e.g., CWE-89)
- `scanner`: Filter by scanner (bandit, semgrep, gosec, eslint)
- `file`: Filter by file path
- `limit`: Results per page (default: 50)
- `offset`: Pagination offset (default: 0)
- `sort`: Sort field (severity, date, file)
- `order`: Sort order (asc, desc)

Response:
```json
{
  "findings": [
    {
      "id": "finding-123",
      "severity": "critical",
      "cwe": "CWE-89",
      "title": "SQL Injection",
      "file": "app/database.py",
      "line": 42,
      "scanner": "bandit",
      "created_at": "2026-03-03T10:00:00Z"
    }
  ],
  "total": 150,
  "page": 1,
  "page_size": 50
}
```

#### Get Finding Details

```http
GET /api/v1/findings/{id}
```

Response:
```json
{
  "id": "finding-123",
  "severity": "critical",
  "cwe": "CWE-89",
  "title": "SQL Injection",
  "description": "Possible SQL injection vector...",
  "file": "app/database.py",
  "line": 42,
  "column": 10,
  "code_snippet": "query = \"SELECT * FROM users WHERE id = \" + user_id",
  "scanner": "bandit",
  "remediation": "Use parameterized queries...",
  "created_at": "2026-03-03T10:00:00Z"
}
```

### Policies

#### Validate Policy

```http
POST /api/v1/policies/validate
Content-Type: application/json

{
  "policy": "policies:\n  - id: test\n    name: Test Policy\n    action: deny"
}
```

Response:
```json
{
  "valid": true,
  "errors": []
}
```

### Reports

#### Generate Report

```http
GET /api/v1/reports/{scan_id}?format=json
```

Query parameters:
- `format`: Report format (json, sarif, html, markdown, csv)

Response: Report in requested format

### Analytics

#### Get Trends

```http
GET /api/v1/analytics/trends?start=2026-01-01&end=2026-03-03
```

Response:
```json
{
  "dates": ["2026-01-01", "2026-01-08", "2026-01-15"],
  "critical": [5, 3, 2],
  "high": [12, 10, 8],
  "medium": [25, 22, 20],
  "low": [15, 14, 12]
}
```

#### Get MTTR

```http
GET /api/v1/analytics/mttr
```

Response:
```json
{
  "mean_time_to_remediation_hours": 48.5,
  "median_hours": 36.0,
  "p90_hours": 72.0
}
```

#### Get Security Score

```http
GET /api/v1/analytics/score
```

Response:
```json
{
  "score": 85.5,
  "grade": "B",
  "trend": "improving",
  "history": [
    {"date": "2026-01-01", "score": 75.0},
    {"date": "2026-02-01", "score": 80.0},
    {"date": "2026-03-01", "score": 85.5}
  ]
}
```

#### Get Hotspots

```http
GET /api/v1/analytics/hotspots?limit=10
```

Response:
```json
{
  "hotspots": [
    {
      "file": "app/auth.py",
      "findings_count": 15,
      "critical": 3,
      "high": 7,
      "medium": 5
    }
  ]
}
```

## Error Handling

All errors follow a consistent format:

```json
{
  "code": "INVALID_REQUEST",
  "message": "Invalid severity level",
  "details": {
    "field": "severity",
    "value": "invalid"
  }
}
```

### Error Codes

- `INVALID_REQUEST`: Malformed request or invalid parameters
- `NOT_FOUND`: Resource not found
- `UNAUTHORIZED`: Authentication required or invalid
- `FORBIDDEN`: Insufficient permissions
- `INTERNAL_ERROR`: Server error
- `SCANNER_FAILED`: Scanner execution failed
- `LLM_FAILED`: LLM provider error

### HTTP Status Codes

- `200 OK`: Success
- `201 Created`: Resource created
- `400 Bad Request`: Invalid input
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `429 Too Many Requests`: Rate limit exceeded
- `500 Internal Server Error`: Server error

## Rate Limiting

The API implements rate limiting to prevent abuse:

- **Default**: 100 requests per minute per IP
- **Authenticated**: 1000 requests per minute per token

Rate limit headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1709467200
```

## Pagination

List endpoints support pagination:

```http
GET /api/v1/findings?limit=50&offset=100
```

Response includes pagination metadata:
```json
{
  "findings": [...],
  "total": 500,
  "page": 3,
  "page_size": 50,
  "has_next": true,
  "has_prev": true
}
```

## OpenAPI Documentation

The API is fully documented using OpenAPI 3.0.3 specification.

### Interactive Swagger UI

Access interactive API documentation at:

```
http://localhost:8080/api/docs
```

The Swagger UI provides:
- Complete API reference with all endpoints
- Interactive request/response examples
- Try-it-out functionality to test endpoints directly
- Schema definitions for all data models
- Filtering and search capabilities

### OpenAPI Specification

Download the OpenAPI specification in YAML or JSON format:

**YAML Format:**
```bash
curl http://localhost:8080/api/v1/openapi.yaml > openapi.yaml
```

**JSON Format:**
```bash
curl http://localhost:8080/api/v1/openapi.json > openapi.json
```

### Using the OpenAPI Spec

The OpenAPI specification can be used to:

1. **Import into API clients** (Postman, Insomnia, etc.)
2. **Generate client libraries** in various programming languages
3. **Validate API requests** and responses
4. **Generate documentation** in different formats

See the [API Quick Start Guide](../developer-guide/api-quick-start.md) for detailed examples.

### Generate Client Libraries

Use OpenAPI Generator to create client libraries:

```bash
# Install OpenAPI Generator
npm install -g @openapitools/openapi-generator-cli

# Generate Python client
openapi-generator-cli generate \
  -i http://localhost:8080/api/v1/openapi.yaml \
  -g python \
  -o ./clients/python

# Generate TypeScript client
openapi-generator-cli generate \
  -i http://localhost:8080/api/v1/openapi.yaml \
  -g typescript-axios \
  -o ./clients/typescript

# Generate Go client
openapi-generator-cli generate \
  -i http://localhost:8080/api/v1/openapi.yaml \
  -g go \
  -o ./clients/go
```

## Examples

### Python Client

```python
import requests

class CodingAgentClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.headers = {"Authorization": f"Bearer {token}"}
    
    def trigger_scan(self, path, scanners):
        response = requests.post(
            f"{self.base_url}/api/v1/scans",
            json={"path": path, "scanners": scanners},
            headers=self.headers
        )
        return response.json()
    
    def get_findings(self, severity=None):
        params = {"severity": severity} if severity else {}
        response = requests.get(
            f"{self.base_url}/api/v1/findings",
            params=params,
            headers=self.headers
        )
        return response.json()

# Usage
client = CodingAgentClient("http://localhost:8080", "your-token")
scan = client.trigger_scan("/path/to/code", ["bandit", "semgrep"])
findings = client.get_findings(severity="critical,high")
```

### JavaScript Client

```javascript
class CodingAgentClient {
  constructor(baseUrl, token) {
    this.baseUrl = baseUrl;
    this.token = token;
  }

  async triggerScan(path, scanners) {
    const response = await fetch(`${this.baseUrl}/api/v1/scans`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.token}`
      },
      body: JSON.stringify({ path, scanners })
    });
    return response.json();
  }

  async getFindings(severity) {
    const params = severity ? `?severity=${severity}` : '';
    const response = await fetch(
      `${this.baseUrl}/api/v1/findings${params}`,
      {
        headers: { 'Authorization': `Bearer ${this.token}` }
      }
    );
    return response.json();
  }
}

// Usage
const client = new CodingAgentClient('http://localhost:8080', 'your-token');
const scan = await client.triggerScan('/path/to/code', ['bandit', 'semgrep']);
const findings = await client.getFindings('critical,high');
```

## Next Steps

- Explore the [Web Dashboard](10-web-dashboard.md)
- Set up [Webhooks](14-webhooks.md) for notifications
- Learn about [CI/CD Integration](13-cicd-integration.md)
