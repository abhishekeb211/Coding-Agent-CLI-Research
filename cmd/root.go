package cmd

import (
	"fmt"
	"path/filepath"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	verbose bool
	
	// Version information (set from main.go)
	Version   = "dev"
	BuildDate = "unknown"
	GitCommit = "unknown"
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "coding-agent-cli",
	Short: "Offline-first AI-augmented security scanning framework",
	Long: `Coding Agent CLI is an offline-first security scanning framework that integrates
local SAST tools with AI-augmented remediation guidance and policy-as-code governance.

Features:
  - Offline-first architecture with cryptographic verification
  - Local LLM integration for remediation guidance
  - Policy-as-code enforcement
  - Unified finding normalization across multiple tools`,
	Version: "1.0.0",
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	// Update version from variables
	rootCmd.Version = Version
	SetVersionTemplate()
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	// Global flags
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
}

// SetVersionTemplate updates the version template with current version info
func SetVersionTemplate() {
	rootCmd.SetVersionTemplate(fmt.Sprintf(`Coding Agent CLI
Version:    %s
Build Date: %s
Git Commit: %s
`, Version, BuildDate, GitCommit))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag
		viper.SetConfigFile(cfgFile)
	} else {
		// Search for config in current directory
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName("config")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in
	if err := viper.ReadInConfig(); err == nil {
		if verbose {
			log.Info().Str("config", viper.ConfigFileUsed()).Msg("Using config file")
		}
	} else {
		if verbose {
			log.Warn().Err(err).Msg("No config file found, using defaults")
		}
	}
}

// getDBPath returns the database path from config or default
func getDBPath() string {
	dbPath := viper.GetString("database.path")
	if dbPath == "" {
		dbPath = ".coding-agent/database.db"
	}
	if !filepath.IsAbs(dbPath) {
		if abs, err := filepath.Abs(dbPath); err == nil {
			dbPath = abs
		}
	}
	return dbPath
}

// GetConfigString retrieves a string configuration value
func GetConfigString(key string) string {
	return viper.GetString(key)
}

// GetConfigBool retrieves a boolean configuration value
func GetConfigBool(key string) bool {
	return viper.GetBool(key)
}

// GetConfigInt retrieves an integer configuration value
func GetConfigInt(key string) int {
	return viper.GetInt(key)
}

// GetConfigStringSlice retrieves a string slice configuration value
func GetConfigStringSlice(key string) []string {
	return viper.GetStringSlice(key)
}

// PrintVersion prints the version information
func PrintVersion() {
	fmt.Printf("Coding Agent CLI v%s\n", Version)
	fmt.Printf("Build Date: %s\n", BuildDate)
	fmt.Printf("Git Commit: %s\n", GitCommit)
	fmt.Println("Offline-first AI-augmented security scanning framework")
}
