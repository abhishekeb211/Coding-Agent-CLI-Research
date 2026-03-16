package api

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/coding-agent/cli/internal/analytics"
	"github.com/coding-agent/cli/internal/scanner"
	"github.com/coding-agent/cli/internal/storage"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/rs/zerolog/log"
)

// Server represents the API server
type Server struct {
	router       *chi.Mux
	db           *storage.Database
	orchestrator *scanner.Orchestrator
	analytics    *analytics.Engine
	config       *Config
	httpServer   *http.Server
}

// Config holds server configuration
type Config struct {
	Host            string
	Port            int
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
	RateLimit       int // requests per minute
	EnableCORS      bool
	CORSOrigins     []string
}

// DefaultConfig returns default server configuration
func DefaultConfig() *Config {
	return &Config{
		Host:            "localhost",
		Port:            8080,
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		ShutdownTimeout: 10 * time.Second,
		RateLimit:       100,
		EnableCORS:      true,
		CORSOrigins:     []string{"http://localhost:*"},
	}
}

// NewServer creates a new API server
func NewServer(db *storage.Database, orchestrator *scanner.Orchestrator, config *Config) (*Server, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Create analytics engine
	analyticsEngine := analytics.NewEngine(db.DB())

	s := &Server{
		router:       chi.NewRouter(),
		db:           db,
		orchestrator: orchestrator,
		analytics:    analyticsEngine,
		config:       config,
	}

	// Setup middleware
	s.setupMiddleware()

	// Setup routes
	s.setupRoutes()

	return s, nil
}

// setupMiddleware configures middleware stack
func (s *Server) setupMiddleware() {
	// Request ID for tracing
	s.router.Use(middleware.RequestID)

	// Real IP detection
	s.router.Use(middleware.RealIP)

	// Structured logging
	s.router.Use(requestLogger)

	// Panic recovery
	s.router.Use(middleware.Recoverer)

	// Request timeout
	s.router.Use(middleware.Timeout(60 * time.Second))

	// Rate limiting
	s.router.Use(rateLimiter(s.config.RateLimit))

	// CORS support
	if s.config.EnableCORS {
		s.router.Use(cors.Handler(cors.Options{
			AllowedOrigins:   s.config.CORSOrigins,
			AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
			ExposedHeaders:   []string{"X-Request-ID"},
			AllowCredentials: true,
			MaxAge:           300,
		}))
	}
}

// setupRoutes configures API routes
func (s *Server) setupRoutes() {
	// Health check endpoint
	s.router.Get("/health", s.handleHealth)

	// API documentation
	s.router.Get("/api/v1/openapi.yaml", s.handleOpenAPISpec)
	s.router.Get("/api/v1/openapi.json", s.handleOpenAPISpecJSON)
	s.router.Get("/api/docs", s.handleSwaggerUI)

	// API v1 routes
	s.router.Route("/api/v1", func(r chi.Router) {
		// Scans
		r.Post("/scans", s.handleCreateScan)
		r.Get("/scans", s.handleListScans)
		r.Get("/scans/{id}", s.handleGetScan)

		// Findings
		r.Get("/findings", s.handleListFindings)
		r.Get("/findings/{id}", s.handleGetFinding)
		r.Post("/findings/import", s.handleImportFindings)

		// Policies
		r.Post("/policies/validate", s.handleValidatePolicy)

		// Reports
		r.Get("/reports/{id}", s.handleGenerateReport)

		// Analytics
		r.Get("/analytics/trends", s.handleGetTrends)
		r.Get("/analytics/mttr", s.handleGetMTTR)
		r.Get("/analytics/score", s.handleGetSecurityScore)
		r.Get("/analytics/hotspots", s.handleGetHotspots)
	})
}

// Start starts the HTTP server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  s.config.ReadTimeout,
		WriteTimeout: s.config.WriteTimeout,
	}

	log.Info().
		Str("addr", addr).
		Msg("Starting API server")

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("failed to start server: %w", err)
	}

	return nil
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	log.Info().Msg("Shutting down API server")

	shutdownCtx, cancel := context.WithTimeout(ctx, s.config.ShutdownTimeout)
	defer cancel()

	if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	return nil
}

// GetRouter returns the chi router (useful for testing)
func (s *Server) GetRouter() *chi.Mux {
	return s.router
}

// Query executes a query that returns rows
func (s *Server) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return s.db.Query(query, args...)
}

// QueryRow executes a query that returns at most one row
func (s *Server) QueryRow(query string, args ...interface{}) *sql.Row {
	return s.db.QueryRow(query, args...)
}
