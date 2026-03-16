package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/coding-agent/cli/internal/api"
	"github.com/coding-agent/cli/internal/scanner"
	"github.com/coding-agent/cli/internal/storage"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	serveHost string
	servePort int
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the API server and web dashboard",
	Long: `Start the HTTP API server and web dashboard.

The server provides:
- REST API at /api/v1/*
- Web dashboard at /
- Health check at /health

Example:
  coding-agent-cli serve
  coding-agent-cli serve --port 8080
  coding-agent-cli serve --host 0.0.0.0 --port 3000`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringVar(&serveHost, "host", "localhost", "Host to bind to")
	serveCmd.Flags().IntVar(&servePort, "port", 8080, "Port to listen on")
}

func runServe(cmd *cobra.Command, args []string) error {
	// Initialize database
	dbPath := getDBPath()
	db, err := storage.NewDatabase(dbPath)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	// Initialize scanner orchestrator
	orchestrator := scanner.NewOrchestrator(scanner.Config{
		TargetPath:  ".",
		OfflineMode: false,
		Verbose:     verbose,
	})

	// Create API server
	config := &api.Config{
		Host:        serveHost,
		Port:        servePort,
		EnableCORS:  true,
		CORSOrigins: []string{"http://localhost:*", "http://127.0.0.1:*"},
	}

	server, err := api.NewServer(db, orchestrator, config)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil {
			errChan <- err
		}
	}()

	log.Info().
		Str("host", serveHost).
		Int("port", servePort).
		Msgf("Server started at http://%s:%d", serveHost, servePort)
	log.Info().Msgf("API available at http://%s:%d/api/v1", serveHost, servePort)
	log.Info().Msgf("Health check at http://%s:%d/health", serveHost, servePort)

	// Wait for shutdown signal or error
	select {
	case <-sigChan:
		log.Info().Msg("Shutdown signal received")
	case err := <-errChan:
		return fmt.Errorf("server error: %w", err)
	}

	// Graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	log.Info().Msg("Server stopped")
	return nil
}
