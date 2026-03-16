# API Package

This package implements the REST API server for the Coding Agent CLI v1.2.

## Architecture

The API server is built using:
- **Router**: chi v5 - lightweight, idiomatic HTTP router
- **Middleware**: Logging, recovery, timeout, rate limiting, CORS
- **API Versioning**: All endpoints under `/api/v1`

## Components

### Server (`server.go`)
Main server implementation with:
- HTTP server lifecycle management
- Middleware setup
- Route configuration
- Graceful shutdown

### Middleware (`middleware.go`)
- **Request Logger**: Structured logging of all HTTP requests
- **Rate Limiter**: Token bucket rate limiting per IP address
- **Recovery**: Panic recovery with error logging
- **Timeout**: Request timeout enforcement
- **CORS**: Cross-Origin Resource Sharing support

### Handlers (`handlers.go`)
API endpoint handlers:
- `POST /api/v1/scans` - Create new scan
- `GET /api/v1/scans` - List scans
- `GET /api/v1/scans/{id}` - Get scan details
- `GET /api/v1/findings` - List findings
- `GET /api/v1/findings/{id}` - Get finding details
- `POST /api/v1/policies/validate` - Validate policy
- `GET /api/v1/reports/{id}` - Generate report
- `GET /api/v1/analytics/trends` - Get analytics trends

### Types (`types.go`)
Request/response types and helper functions:
- Standard error codes
- Request/response models
- JSON encoding/decoding helpers

## Usage

### Starting the Server

```bash
# Start with defaults (localhost:8080)
coding-agent-cli serve

# Custom host and port
coding-agent-cli serve --host 0.0.0.0 --port 3000
```

### Configuration

```go
config := &api.Config{
    Host:            "localhost",
    Port:            8080,
    ReadTimeout:     30 * time.Second,
    WriteTimeout:    30 * time.Second,
    ShutdownTimeout: 10 * time.Second,
    RateLimit:       100, // requests per minute
    EnableCORS:      true,
    CORSOrigins:     []string{"http://localhost:*"},
}

server, err := api.NewServer(db, orchestrator, config)
```

### Making Requests

```bash
# Health check
curl http://localhost:8080/health

# Create scan (not yet implemented)
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"path": "./src", "scanners": ["bandit", "semgrep"]}'

# List findings (not yet implemented)
curl http://localhost:8080/api/v1/findings?page=1&page_size=20
```

## Error Handling

All errors follow a standard format:

```json
{
  "code": "ERROR_CODE",
  "message": "Human-readable error message",
  "details": {
    "field": "additional context"
  }
}
```

Error codes:
- `INVALID_REQUEST` - Invalid request parameters
- `NOT_FOUND` - Resource not found
- `UNAUTHORIZED` - Authentication required
- `INTERNAL_ERROR` - Server error
- `SCANNER_FAILED` - Scanner execution failed
- `LLM_FAILED` - LLM provider failed

## Rate Limiting

The API implements token bucket rate limiting:
- Default: 100 requests per minute per IP
- Configurable via `Config.RateLimit`
- Returns `429 Too Many Requests` when exceeded
- Tokens refill every minute

## CORS Support

CORS is enabled by default for local development:
- Allowed origins: `http://localhost:*`
- Allowed methods: GET, POST, PUT, DELETE, OPTIONS
- Allowed headers: Accept, Authorization, Content-Type, X-Request-ID
- Credentials: Enabled

## Testing

Run tests:
```bash
go test ./internal/api/...
```

Run with coverage:
```bash
go test -cover ./internal/api/...
```

## Implementation Status

### Phase 1 (Task 2.1) - ✅ Complete
- [x] Server infrastructure with chi router
- [x] Middleware (logging, recovery, timeout, rate limiting)
- [x] API versioning (/api/v1)
- [x] CORS support
- [x] Health check endpoint
- [x] Basic tests

### Phase 1 (Task 2.2) - 🚧 Pending
- [ ] Implement scan endpoints
- [ ] Implement findings endpoints
- [ ] Implement policy validation
- [ ] Implement report generation
- [ ] Add pagination and filtering
- [ ] Add comprehensive tests

### Phase 3 - 🚧 Pending
- [ ] Analytics endpoints
- [ ] Web dashboard integration

## Dependencies

- `github.com/go-chi/chi/v5` - HTTP router
- `github.com/go-chi/cors` - CORS middleware
- `github.com/rs/zerolog` - Structured logging

## Future Enhancements

- Authentication/authorization (Phase 5, Task 5.3)
- OpenAPI/Swagger documentation (Task 5.4.2)
- WebSocket support for real-time updates
- GraphQL API (alternative to REST)
- API metrics and monitoring
