package main

import (
	"os"

	"github.com/coding-agent/cli/cmd"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Version information (set via ldflags during build)
var (
	Version   = "1.0.0"
	BuildDate = "2026-03-03"
	GitCommit = "dev"
)

func main() {
	// Set version in cmd package
	cmd.Version = Version
	cmd.BuildDate = BuildDate
	cmd.GitCommit = GitCommit

	// Configure zerolog
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// Execute root command
	if err := cmd.Execute(); err != nil {
		log.Fatal().Err(err).Msg("Failed to execute command")
	}
}
