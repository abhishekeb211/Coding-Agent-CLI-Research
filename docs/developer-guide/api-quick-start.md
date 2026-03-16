# API Quick Start Guide

This guide will help you get started with the Coding Agent CLI REST API.

## Starting the API Server

Start the API server using the CLI:

```bash
coding-agent-cli serve --port 8080
```

The server will start on `http://localhost:8080` by default.

## Accessing the Documentation

### Interactive Swagger UI

Open your browser and navigate to:

```
http://localhost:8080/api/docs
```

The Swagger UI provides:
- Complete API documentation
- Interactive request/response examples
- Try-it-out functionality to test endpoints directly
- Schema definitions for all data models

### OpenAPI Specification

Download the OpenAPI specification:

**YAML Format:**
```bash
curl http://localhost:8080/api/v1/openapi.yaml -o openapi.yaml
```

**JSON Format:**
```bash
curl http://localhost:8080/api/v1/openapi.json -o openapi.json
```

## Basic API Usage

### Health Check

Verify the API is running:

```bash
curl http://localhost:8080/health
```

Response:
```json
{
  "status": "ok",
  "version": "1.2.0"
}
```

### Trigger a Scan

Start a new security scan:

```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/path/to/your/code",
    "scanners": ["bandit", "semgrep"],
    "policies": ["./policies/security.yaml"]
  }'
```

Response:
```json
{
  "scan_id": "abc123def456",
  "status": "running",
  "started": "2026-03-03T10:00:00Z"
}
```

### List All Scans

Retrieve a list of all scans:

```bash
curl "http://localhost:8080/api/v1/scans?page=1&page_size=50"
```

Response:
```json
{
  "scans": [
    {
      "scan_id": "abc123",
      "target_path": "/path/to/code",
      "status": "completed",
      "start_time": "2026-03-03T10:00:00Z",
      "end_time": "2026-03-03T10:05:00Z",
      "duration": 300,
      "total_findings": 42
    }
  ],
  "total": 150,
  "page": 1,
  "page_size": 50
}
```

### Get Scan Details

Retrieve detailed information about a specific scan:

```bash
curl http://localhost:8080/api/v1/scans/abc123def456
```

### List Findings

List all security findings with optional filtering:

```bash
# All findings
curl http://localhost:8080/api/v1/findings

# Filter by severity
curl "http://localhost:8080/api/v1/findings?severity=critical"

# Filter by CWE
curl "http://localhost:8080/api/v1/findings?cwe_id=CWE-89"

# Filter by file path
curl "http://localhost:8080/api/v1/findings?file_path=auth.py"

# Combine filters with pagination
curl "http://localhost:8080/api/v1/findings?severity=high&page=1&page_size=20"
```

Response:
```json
{
  "findings": [
    {
      "id": "finding-001",
      "finding_id": "bandit-B201",
      "cwe_id": "CWE-89",
      "cwe_description": "SQL Injection",
      "severity": "critical",
      "confidence": "high",
      "code_fingerprint": "abc123",
      "file_path": "app/auth.py",
      "line_number": 42,
      "description": "Possible SQL injection vulnerability"
    }
  ],
  "total": 150,
  "page": 1,
  "page_size": 50
}
```

### Get Finding Details

Retrieve detailed information about a specific finding:

```bash
curl http://localhost:8080/api/v1/findings/finding-001
```

## Using with API Clients

### Postman

1. Open Postman
2. Click "Import"
3. Select "Link" tab
4. Enter: `http://localhost:8080/api/v1/openapi.yaml`
5. Click "Continue" and then "Import"

All API endpoints will be imported as a collection.

### Insomnia

1. Open Insomnia
2. Click "Create" → "Import From" → "URL"
3. Enter: `http://localhost:8080/api/v1/openapi.yaml`
4. Click "Fetch and Import"

### cURL Scripts

Create a bash script for common operations:

```bash
#!/bin/bash
# api-client.sh

API_BASE="http://localhost:8080/api/v1"

# Function to trigger a scan
scan() {
  local path=$1
  curl -X POST "$API_BASE/scans" \
    -H "Content-Type: application/json" \
    -d "{\"path\": \"$path\", \"scanners\": [\"bandit\", \"semgrep\"]}"
}

# Function to list findings
findings() {
  local severity=${1:-""}
  if [ -n "$severity" ]; then
    curl "$API_BASE/findings?severity=$severity"
  else
    curl "$API_BASE/findings"
  fi
}

# Function to get scan details
scan_details() {
  local scan_id=$1
  curl "$API_BASE/scans/$scan_id"
}

# Usage
case "$1" in
  scan)
    scan "$2"
    ;;
  findings)
    findings "$2"
    ;;
  details)
    scan_details "$2"
    ;;
  *)
    echo "Usage: $0 {scan|findings|details} [args]"
    exit 1
    ;;
esac
```

Usage:
```bash
chmod +x api-client.sh
./api-client.sh scan /path/to/code
./api-client.sh findings critical
./api-client.sh details abc123def456
```

## Generating Client Libraries

Use OpenAPI Generator to create client libraries:

### Python Client

```bash
# Install OpenAPI Generator
npm install -g @openapitools/openapi-generator-cli

# Generate Python client
openapi-generator-cli generate \
  -i http://localhost:8080/api/v1/openapi.yaml \
  -g python \
  -o ./clients/python \
  --additional-properties=packageName=coding_agent_client

# Install and use
cd clients/python
pip install .

# Use in Python
from coding_agent_client import ApiClient, Configuration, ScansApi

config = Configuration(host="http://localhost:8080/api/v1")
client = ApiClient(config)
scans_api = ScansApi(client)

# Trigger a scan
response = scans_api.create_scan({
    "path": "/path/to/code",
    "scanners": ["bandit", "semgrep"]
})
print(f"Scan ID: {response.scan_id}")
```

### JavaScript/TypeScript Client

```bash
# Generate TypeScript client
openapi-generator-cli generate \
  -i http://localhost:8080/api/v1/openapi.yaml \
  -g typescript-axios \
  -o ./clients/typescript

# Install and use
cd clients/typescript
npm install

# Use in TypeScript/JavaScript
import { Configuration, ScansApi } from './clients/typescript';

const config = new Configuration({
  basePath: 'http://localhost:8080/api/v1'
});

const scansApi = new ScansApi(config);

// Trigger a scan
const response = await scansApi.createScan({
  path: '/path/to/code',
  scanners: ['bandit', 'semgrep']
});

console.log(`Scan ID: ${response.data.scan_id}`);
```

### Go Client

```bash
# Generate Go client
openapi-generator-cli generate \
  -i http://localhost:8080/api/v1/openapi.yaml \
  -g go \
  -o ./clients/go \
  --additional-properties=packageName=codingagent

# Use in Go
package main

import (
    "context"
    "fmt"
    codingagent "path/to/clients/go"
)

func main() {
    cfg := codingagent.NewConfiguration()
    cfg.Servers = codingagent.ServerConfigurations{
        {URL: "http://localhost:8080/api/v1"},
    }
    
    client := codingagent.NewAPIClient(cfg)
    
    // Trigger a scan
    req := codingagent.ScanRequest{
        Path: "/path/to/code",
        Scanners: []string{"bandit", "semgrep"},
    }
    
    resp, _, err := client.ScansApi.CreateScan(context.Background()).
        ScanRequest(req).Execute()
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Scan ID: %s\n", resp.ScanId)
}
```

## Error Handling

All API errors follow a consistent format:

```json
{
  "code": "ERROR_CODE",
  "message": "Human-readable error message",
  "details": {
    "field": "additional_context"
  }
}
```

Common error codes:
- `INVALID_REQUEST` (400) - Invalid request parameters
- `NOT_FOUND` (404) - Resource not found
- `INTERNAL_ERROR` (500) - Internal server error

Example error handling in bash:

```bash
response=$(curl -s -w "\n%{http_code}" http://localhost:8080/api/v1/scans/invalid-id)
http_code=$(echo "$response" | tail -n1)
body=$(echo "$response" | head -n-1)

if [ "$http_code" -ne 200 ]; then
  echo "Error: HTTP $http_code"
  echo "$body" | jq '.message'
  exit 1
fi
```

## Rate Limiting

The API implements rate limiting:
- Unauthenticated: 100 requests/minute
- Authenticated: 1000 requests/minute

Rate limit information is included in response headers:

```bash
curl -I http://localhost:8080/api/v1/scans

# Headers:
# X-RateLimit-Limit: 100
# X-RateLimit-Remaining: 95
# X-RateLimit-Reset: 1709467200
```

## Pagination

List endpoints support pagination:

```bash
# First page (default)
curl "http://localhost:8080/api/v1/findings?page=1&page_size=50"

# Second page
curl "http://localhost:8080/api/v1/findings?page=2&page_size=50"

# Custom page size (max 100)
curl "http://localhost:8080/api/v1/findings?page=1&page_size=100"
```

Response includes pagination metadata:
```json
{
  "findings": [...],
  "total": 500,
  "page": 1,
  "page_size": 50
}
```

## Next Steps

- Explore the [complete API reference](./rest-api-reference.md)
- View [interactive Swagger UI](http://localhost:8080/api/docs)
- Learn about [authentication and security](./api-authentication.md)
- See [advanced API usage examples](./api-examples.md)

## Support

For issues or questions:
- Check the [Swagger UI](http://localhost:8080/api/docs) for endpoint details
- Review the [OpenAPI specification](http://localhost:8080/api/v1/openapi.yaml)
- Consult the [developer guide](./README.md)
