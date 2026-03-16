# REST API Reference

## Overview

Complete REST API reference for the Coding Agent CLI v1.2 API.

**Base URL**: `http://localhost:8080/api/v1`

**API Version**: v1

## Interactive Documentation

The API provides interactive documentation using Swagger UI:

- **Swagger UI**: [http://localhost:8080/api/docs](http://localhost:8080/api/docs)
- **OpenAPI Spec (YAML)**: [http://localhost:8080/api/v1/openapi.yaml](http://localhost:8080/api/v1/openapi.yaml)
- **OpenAPI Spec (JSON)**: [http://localhost:8080/api/v1/openapi.json](http://localhost:8080/api/v1/openapi.json)

The Swagger UI provides:
- Interactive API exploration
- Request/response examples
- Try-it-out functionality for testing endpoints
- Complete schema documentation
- Filtering and search capabilities

## OpenAPI Specification

The API is fully documented using OpenAPI 3.0.3 specification. You can:

1. **View in Browser**: Navigate to `/api/docs` for interactive Swagger UI
2. **Download Spec**: Download YAML or JSON format from the endpoints above
3. **Import to Tools**: Import the OpenAPI spec into tools like Postman, Insomnia, or API testing frameworks
4. **Generate Clients**: Use OpenAPI generators to create client libraries in various languages

## Authentication

### API Tokens

```http
Authorization: Bearer <token>
```

### Basic Authentication

```http
Authorization: Basic <base64(username:password)>
```

## Scans API

### POST /api/v1/scans

Trigger a new security scan.

**Request Body**:
```json
{
  "path": "/path/to/code",
  "scanners": ["bandit", "semgrep", "gosec"],
  "policies": ["./policies/security.yaml"],
  "llm_enabled": true
}
```

**Response** (201):
```json
{
  "scan_id": "abc123",
  "status": "running",
  "started": "2026-03-03T10:00:00Z"
}
```

### GET /api/v1/scans

List all scans.

**Query Parameters**:
- `limit`: Results per page (default: 50)
- `offset`: Pagination offset (default: 0)
- `status`: Filter by status
- `sort`: Sort field
- `order`: Sort order (asc/desc)

**Response** (200):
```json
{
  "scans": [...],
  "total": 100,
  "page": 1,
  "page_size": 50
}
```

### GET /api/v1/scans/{id}

Get scan details.

**Response** (200):
```json
{
  "id": "abc123",
  "path": "/path/to/code",
  "status": "completed",
  "findings": {
    "critical": 2,
    "high": 8,
    "medium": 20,
    "low": 12
  }
}
```

## Findings API

### GET /api/v1/findings

List findings with filtering.

**Query Parameters**:
- `severity`: Filter by severity
- `cwe`: Filter by CWE ID
- `scanner`: Filter by scanner
- `file`: Filter by file path
- `limit`: Results per page
- `offset`: Pagination offset

**Response** (200):
```json
{
  "findings": [...],
  "total": 150,
  "page": 1,
  "page_size": 50
}
```

### GET /api/v1/findings/{id}

Get finding details.

**Response** (200):
```json
{
  "id": "finding-123",
  "severity": "critical",
  "cwe": "CWE-89",
  "title": "SQL Injection",
  "remediation": "Use parameterized queries..."
}
```

## Analytics API

### GET /api/v1/analytics/trends

Get finding trends over time.

**Query Parameters**:
- `start`: Start date (ISO 8601)
- `end`: End date (ISO 8601)
- `interval`: Time interval (day/week/month)

**Response** (200):
```json
{
  "dates": ["2026-01-01", "2026-01-08"],
  "critical": [5, 3],
  "high": [12, 10],
  "medium": [25, 22],
  "low": [15, 14]
}
```

### GET /api/v1/analytics/mttr

Get mean time to remediation.

**Response** (200):
```json
{
  "mean_time_to_remediation_hours": 48.5,
  "median_hours": 36.0,
  "p90_hours": 72.0
}
```

### GET /api/v1/analytics/score

Get security score.

**Response** (200):
```json
{
  "score": 85.5,
  "grade": "B",
  "trend": "improving"
}
```

### GET /api/v1/analytics/hotspots

Get files with most findings.

**Response** (200):
```json
{
  "hotspots": [
    {
      "file": "app/auth.py",
      "findings_count": 15,
      "critical": 3
    }
  ]
}
```

## Webhooks API

### POST /api/v1/webhooks

Create a webhook.

**Request Body**:
```json
{
  "id": "slack-alerts",
  "url": "https://hooks.slack.com/...",
  "events": ["scan_complete", "critical_finding"],
  "enabled": true
}
```

**Response** (201):
```json
{
  "id": "slack-alerts",
  "created_at": "2026-03-03T10:00:00Z"
}
```

### GET /api/v1/webhooks

List all webhooks.

### POST /api/v1/webhooks/{id}/test

Test a webhook.

### DELETE /api/v1/webhooks/{id}

Delete a webhook.

## Error Responses

All error responses follow a consistent format:

```json
{
  "code": "ERROR_CODE",
  "message": "Human-readable error message",
  "details": {
    "field": "additional_context"
  }
}
```

### Error Codes

- `INVALID_REQUEST` (400) - Invalid request parameters or body
- `UNAUTHORIZED` (401) - Authentication required or failed
- `FORBIDDEN` (403) - Insufficient permissions
- `NOT_FOUND` (404) - Resource not found
- `RATE_LIMIT_EXCEEDED` (429) - Too many requests
- `INTERNAL_ERROR` (500) - Internal server error
- `SCANNER_FAILED` (500) - Scanner execution failed
- `LLM_FAILED` (500) - LLM provider error

## Rate Limiting

- Unauthenticated: 100 req/min
- Authenticated: 1000 req/min

Headers:
```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 995
X-RateLimit-Reset: 1709467200
```

## Pagination

List endpoints support pagination using query parameters:

- `page`: Page number (1-indexed, default: 1)
- `page_size`: Items per page (default: 50, max: 100)

Response includes pagination metadata:
```json
{
  "items": [...],
  "total": 150,
  "page": 1,
  "page_size": 50
}
```

## Filtering and Sorting

Many endpoints support filtering via query parameters. See the OpenAPI specification or Swagger UI for endpoint-specific filter options.

Common filters:
- `severity`: Filter by severity level (critical, high, medium, low)
- `cwe_id`: Filter by CWE identifier
- `run_id`: Filter by scan run ID
- `file_path`: Filter by file path (partial match)

## Complete API Reference

For the complete, up-to-date API reference with all endpoints, request/response schemas, and examples, please visit:

**[Interactive API Documentation (Swagger UI)](http://localhost:8080/api/docs)**

The Swagger UI provides comprehensive documentation including:
- All available endpoints with descriptions
- Request body schemas and examples
- Response schemas for all status codes
- Query parameter documentation
- Try-it-out functionality for testing
- Model schemas with field descriptions

You can also download the OpenAPI specification in YAML or JSON format for use with API clients and code generators.
