# API Documentation

This directory contains the OpenAPI specification for the Coding Agent CLI REST API.

## Files

- `openapi.yaml` - OpenAPI 3.0.3 specification in YAML format

## Viewing the Documentation

### Interactive Swagger UI

When the API server is running, you can view interactive documentation at:

```
http://localhost:8080/api/docs
```

The Swagger UI provides:
- Interactive API exploration
- Try-it-out functionality for testing endpoints
- Complete request/response schemas
- Examples for all endpoints
- Filtering and search capabilities

### Accessing the OpenAPI Spec

The OpenAPI specification is available in two formats:

**YAML Format:**
```
http://localhost:8080/api/v1/openapi.yaml
```

**JSON Format:**
```
http://localhost:8080/api/v1/openapi.json
```

## Using the OpenAPI Spec

### Import into API Clients

You can import the OpenAPI spec into various API clients:

**Postman:**
1. Open Postman
2. Click "Import"
3. Enter the URL: `http://localhost:8080/api/v1/openapi.yaml`
4. Click "Import"

**Insomnia:**
1. Open Insomnia
2. Click "Create" → "Import From" → "URL"
3. Enter the URL: `http://localhost:8080/api/v1/openapi.yaml`
4. Click "Fetch and Import"

### Generate Client Libraries

You can use OpenAPI Generator to create client libraries in various languages:

```bash
# Install OpenAPI Generator
npm install -g @openapitools/openapi-generator-cli

# Generate Python client
openapi-generator-cli generate \
  -i http://localhost:8080/api/v1/openapi.yaml \
  -g python \
  -o ./clients/python

# Generate Go client
openapi-generator-cli generate \
  -i http://localhost:8080/api/v1/openapi.yaml \
  -g go \
  -o ./clients/go

# Generate TypeScript/JavaScript client
openapi-generator-cli generate \
  -i http://localhost:8080/api/v1/openapi.yaml \
  -g typescript-axios \
  -o ./clients/typescript
```

### Validate API Requests

You can use the OpenAPI spec to validate API requests and responses:

```bash
# Install openapi-cli
npm install -g @redocly/cli

# Validate the spec
redocly lint http://localhost:8080/api/v1/openapi.yaml

# Bundle the spec (resolve all $ref)
redocly bundle http://localhost:8080/api/v1/openapi.yaml \
  -o openapi-bundled.yaml
```

## API Overview

The Coding Agent CLI REST API provides programmatic access to:

### Scans
- `POST /api/v1/scans` - Trigger new security scan
- `GET /api/v1/scans` - List all scans
- `GET /api/v1/scans/{id}` - Get scan details

### Findings
- `GET /api/v1/findings` - List findings with filtering
- `GET /api/v1/findings/{id}` - Get finding details
- `POST /api/v1/findings/import` - Import findings from external tools

### Policies
- `POST /api/v1/policies/validate` - Validate policy configuration

### Reports
- `GET /api/v1/reports/{id}` - Generate reports in various formats

### Analytics
- `GET /api/v1/analytics/trends` - Get finding trends over time

### Health
- `GET /health` - Health check endpoint

## Authentication

The API supports multiple authentication methods:

- **API Tokens**: `Authorization: Bearer <token>`
- **Basic Auth**: `Authorization: Basic <base64(username:password)>`

Note: Authentication is optional by default but can be enabled in the server configuration.

## Rate Limiting

- Unauthenticated requests: 100 requests/minute
- Authenticated requests: 1000 requests/minute

Rate limit information is included in response headers:
- `X-RateLimit-Limit` - Maximum requests per window
- `X-RateLimit-Remaining` - Remaining requests in current window
- `X-RateLimit-Reset` - Unix timestamp when limit resets

## Error Handling

All errors follow a consistent format:

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
- `SCANNER_FAILED` (500) - Scanner execution failed

## Examples

### Trigger a Scan

```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/path/to/code",
    "scanners": ["bandit", "semgrep"],
    "policies": ["./policies/security.yaml"]
  }'
```

### List Findings

```bash
curl "http://localhost:8080/api/v1/findings?severity=critical&page=1&page_size=50"
```

### Get Scan Details

```bash
curl http://localhost:8080/api/v1/scans/abc123def456
```

## Development

### Updating the OpenAPI Spec

When making changes to the API:

1. Update `openapi.yaml` with new endpoints, schemas, or examples
2. Validate the spec:
   ```bash
   redocly lint api/openapi.yaml
   ```
3. Test the changes by viewing in Swagger UI
4. Update any related documentation

### Embedding the Spec

The OpenAPI spec is embedded in the Go binary using `go:embed`. When you build the application, the spec is automatically included and served by the API server.

## Additional Resources

- [OpenAPI Specification](https://spec.openapis.org/oas/v3.0.3)
- [Swagger UI Documentation](https://swagger.io/tools/swagger-ui/)
- [OpenAPI Generator](https://openapi-generator.tech/)
- [Redocly CLI](https://redocly.com/docs/cli/)
