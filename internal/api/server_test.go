package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coding-agent/cli/internal/scanner"
	"github.com/coding-agent/cli/internal/storage"
)

func TestNewServer(t *testing.T) {
	// Create temporary database
	db, err := storage.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create orchestrator
	orchestrator := scanner.NewOrchestrator(scanner.Config{})

	// Test with default config
	server, err := NewServer(db, orchestrator, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	if server == nil {
		t.Fatal("Expected server to be non-nil")
	}

	if server.router == nil {
		t.Fatal("Expected router to be non-nil")
	}

	// Test with custom config
	config := &Config{
		Host:        "0.0.0.0",
		Port:        9000,
		EnableCORS:  false,
		RateLimit:   50,
	}

	server, err = NewServer(db, orchestrator, config)
	if err != nil {
		t.Fatalf("Failed to create server with custom config: %v", err)
	}

	if server.config.Port != 9000 {
		t.Errorf("Expected port 9000, got %d", server.config.Port)
	}
}

func TestHealthEndpoint(t *testing.T) {
	// Create temporary database
	db, err := storage.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create orchestrator
	orchestrator := scanner.NewOrchestrator(scanner.Config{})

	// Create server
	server, err := NewServer(db, orchestrator, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	// Execute request
	server.router.ServeHTTP(w, req)

	// Check response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}
}

func TestAPIVersioning(t *testing.T) {
	// Create temporary database
	db, err := storage.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create orchestrator
	orchestrator := scanner.NewOrchestrator(scanner.Config{})

	// Create server
	server, err := NewServer(db, orchestrator, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Test API v1 endpoints exist
	endpoints := []string{
		"/api/v1/scans",
		"/api/v1/findings",
		"/api/v1/policies/validate",
	}

	for _, endpoint := range endpoints {
		req := httptest.NewRequest(http.MethodGet, endpoint, nil)
		w := httptest.NewRecorder()

		server.router.ServeHTTP(w, req)

		// Should not return 404 (endpoint exists, even if not implemented)
		if w.Code == http.StatusNotFound {
			t.Errorf("Endpoint %s returned 404, expected endpoint to exist", endpoint)
		}
	}
}

func TestCORSHeaders(t *testing.T) {
	// Create temporary database
	db, err := storage.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create orchestrator
	orchestrator := scanner.NewOrchestrator(scanner.Config{})

	// Create server with CORS enabled
	config := &Config{
		EnableCORS:  true,
		CORSOrigins: []string{"http://localhost:3000"},
	}

	server, err := NewServer(db, orchestrator, config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create OPTIONS request (preflight)
	req := httptest.NewRequest(http.MethodOptions, "/api/v1/scans", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")

	w := httptest.NewRecorder()
	server.router.ServeHTTP(w, req)

	// Check CORS headers
	allowOrigin := w.Header().Get("Access-Control-Allow-Origin")
	if allowOrigin != "http://localhost:3000" {
		t.Errorf("Expected Access-Control-Allow-Origin header, got %s", allowOrigin)
	}
}

func TestRequestIDMiddleware(t *testing.T) {
	// Create temporary database
	db, err := storage.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create orchestrator
	orchestrator := scanner.NewOrchestrator(scanner.Config{})

	// Create server
	server, err := NewServer(db, orchestrator, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	// Execute request
	server.router.ServeHTTP(w, req)

	// Check for X-Request-ID header in response
	requestID := w.Header().Get("X-Request-ID")
	if requestID == "" {
		t.Error("Expected X-Request-ID header to be set")
	}
}

func TestOpenAPIEndpoints(t *testing.T) {
	// Create temporary database
	db, err := storage.NewDatabase(":memory:")
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer db.Close()

	// Create orchestrator
	orchestrator := scanner.NewOrchestrator(scanner.Config{})

	// Create server
	server, err := NewServer(db, orchestrator, nil)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	tests := []struct {
		name        string
		endpoint    string
		contentType string
	}{
		{
			name:        "OpenAPI YAML",
			endpoint:    "/api/v1/openapi.yaml",
			contentType: "application/x-yaml",
		},
		{
			name:        "OpenAPI JSON",
			endpoint:    "/api/v1/openapi.json",
			contentType: "application/json",
		},
		{
			name:        "Swagger UI",
			endpoint:    "/api/docs",
			contentType: "text/html",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.endpoint, nil)
			w := httptest.NewRecorder()

			server.router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			contentType := w.Header().Get("Content-Type")
			if contentType != tt.contentType && !contains(contentType, tt.contentType) {
				t.Errorf("Expected Content-Type %s, got %s", tt.contentType, contentType)
			}

			if w.Body.Len() == 0 {
				t.Error("Expected non-empty response body")
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}
