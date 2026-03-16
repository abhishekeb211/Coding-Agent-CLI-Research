// +build integration,configworkflow

package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/coding-agent/cli/internal/scanner"
)

func TestConfigurationFileLoading(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	configContent := `
scanners:
  - bandit
  - semgrep
database: ./findings.db
output_format: json
llm:
  provider: openai
  api_key: test-key
  cache_enabled: true
policy:
  enabled: true
  policy_file: ./policy.yaml
`
	configPath := ctx.CreateTestConfig(t, configContent)

	// Load configuration
	config, err := scanner.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify configuration values
	if len(config.Scanners) != 2 {
		t.Errorf("Expected 2 scanners, got %d", len(config.Scanners))
	}

	if config.OutputFormat != "json" {
		t.Errorf("Expected output format 'json', got '%s'", config.OutputFormat)
	}

	if config.LLM.Provider != "openai" {
		t.Errorf("Expected LLM provider 'openai', got '%s'", config.LLM.Provider)
	}

	if !config.LLM.CacheEnabled {
		t.Error("Expected LLM cache to be enabled")
	}

	if !config.Policy.Enabled {
		t.Error("Expected policy to be enabled")
	}
}

func TestCommandLineFlagOverrides(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create base config
	configContent := `
scanners:
  - bandit
output_format: json
`
	configPath := ctx.CreateTestConfig(t, configContent)

	// Load config
	config, err := scanner.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Simulate command-line flag overrides
	config.OutputFormat = "sarif" // Override from CLI
	config.Scanners = append(config.Scanners, "semgrep")

	// Verify overrides took effect
	if config.OutputFormat != "sarif" {
		t.Errorf("Expected output format override to 'sarif', got '%s'", config.OutputFormat)
	}

	if len(config.Scanners) != 2 {
		t.Errorf("Expected 2 scanners after override, got %d", len(config.Scanners))
	}
}

func TestEnvironmentVariableConfiguration(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Set environment variables
	os.Setenv("CODING_AGENT_OUTPUT_FORMAT", "markdown")
	os.Setenv("CODING_AGENT_LLM_PROVIDER", "anthropic")
	os.Setenv("CODING_AGENT_LLM_API_KEY", "env-api-key")
	defer func() {
		os.Unsetenv("CODING_AGENT_OUTPUT_FORMAT")
		os.Unsetenv("CODING_AGENT_LLM_PROVIDER")
		os.Unsetenv("CODING_AGENT_LLM_API_KEY")
	}()

	// Load config with environment variables
	config := scanner.LoadConfigWithEnv()

	// Verify environment variables were applied
	if config.OutputFormat != "markdown" {
		t.Errorf("Expected output format from env 'markdown', got '%s'", config.OutputFormat)
	}

	if config.LLM.Provider != "anthropic" {
		t.Errorf("Expected LLM provider from env 'anthropic', got '%s'", config.LLM.Provider)
	}

	if config.LLM.APIKey != "env-api-key" {
		t.Errorf("Expected API key from env, got '%s'", config.LLM.APIKey)
	}
}

func TestConfigurationValidation(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	testCases := []struct {
		name        string
		config      string
		shouldError bool
		errorMsg    string
	}{
		{
			name: "Valid config",
			config: `
scanners:
  - bandit
output_format: json
`,
			shouldError: false,
		},
		{
			name: "Missing scanners",
			config: `
output_format: json
`,
			shouldError: true,
			errorMsg:    "scanners",
		},
		{
			name: "Invalid output format",
			config: `
scanners:
  - bandit
output_format: invalid
`,
			shouldError: true,
			errorMsg:    "output format",
		},
		{
			name: "Invalid scanner name",
			config: `
scanners:
  - unknown-scanner
output_format: json
`,
			shouldError: true,
			errorMsg:    "scanner",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := ctx.CreateTestFile(t, tc.name+".yaml", tc.config)

			config, err := scanner.LoadConfig(configPath)

			if tc.shouldError {
				if err == nil {
					t.Error("Expected validation error, got nil")
				} else if tc.errorMsg != "" && !contains(err.Error(), tc.errorMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tc.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if config == nil {
					t.Error("Expected valid config, got nil")
				}
			}
		})
	}
}

func TestConfigurationPrecedence(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create config file
	configContent := `
output_format: json
scanners:
  - bandit
`
	configPath := ctx.CreateTestConfig(t, configContent)

	// Set environment variable
	os.Setenv("CODING_AGENT_OUTPUT_FORMAT", "sarif")
	defer os.Unsetenv("CODING_AGENT_OUTPUT_FORMAT")

	// Load config (file + env)
	config, err := scanner.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Apply environment overrides
	config.ApplyEnvOverrides()

	// Environment should override file
	if config.OutputFormat != "sarif" {
		t.Errorf("Expected env to override file, got '%s'", config.OutputFormat)
	}

	// Now apply CLI flag override
	config.OutputFormat = "html"

	// CLI should override everything
	if config.OutputFormat != "html" {
		t.Errorf("Expected CLI to override all, got '%s'", config.OutputFormat)
	}
}

func TestConfigWithRelativePaths(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	configContent := `
database: ./data/findings.db
policy:
  policy_file: ./policies/security.yaml
llm:
  cache_path: ./cache/llm.db
`
	configPath := ctx.CreateTestConfig(t, configContent)

	config, err := scanner.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify paths are resolved relative to config file
	configDir := filepath.Dir(configPath)

	expectedDB := filepath.Join(configDir, "data", "findings.db")
	if config.Database != expectedDB {
		t.Errorf("Expected database path '%s', got '%s'", expectedDB, config.Database)
	}

	expectedPolicy := filepath.Join(configDir, "policies", "security.yaml")
	if config.Policy.PolicyFile != expectedPolicy {
		t.Errorf("Expected policy path '%s', got '%s'", expectedPolicy, config.Policy.PolicyFile)
	}
}

func TestConfigWithAbsolutePaths(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	absDBPath := filepath.Join(ctx.TempDir, "absolute", "findings.db")
	absPolicyPath := filepath.Join(ctx.TempDir, "absolute", "policy.yaml")

	configContent := `
database: ` + absDBPath + `
policy:
  policy_file: ` + absPolicyPath + `
`
	configPath := ctx.CreateTestConfig(t, configContent)

	config, err := scanner.LoadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Absolute paths should remain unchanged
	if config.Database != absDBPath {
		t.Errorf("Expected absolute database path '%s', got '%s'", absDBPath, config.Database)
	}

	if config.Policy.PolicyFile != absPolicyPath {
		t.Errorf("Expected absolute policy path '%s', got '%s'", absPolicyPath, config.Policy.PolicyFile)
	}
}

func TestDefaultConfiguration(t *testing.T) {
	// Load default config without file
	config := scanner.NewDefaultConfig()

	// Verify defaults
	if len(config.Scanners) == 0 {
		t.Error("Expected default scanners to be set")
	}

	if config.OutputFormat == "" {
		t.Error("Expected default output format to be set")
	}

	if config.Database == "" {
		t.Error("Expected default database path to be set")
	}

	// Verify sensible defaults
	if config.OutputFormat != "json" {
		t.Errorf("Expected default output format 'json', got '%s'", config.OutputFormat)
	}
}

func TestConfigMerging(t *testing.T) {
	ctx := SetupTest(t)
	defer ctx.Cleanup(t)

	// Create base config
	baseConfig := `
scanners:
  - bandit
output_format: json
`
	baseConfigPath := ctx.CreateTestFile(t, "base.yaml", baseConfig)

	// Create override config
	overrideConfig := `
scanners:
  - semgrep
llm:
  provider: openai
`
	overrideConfigPath := ctx.CreateTestFile(t, "override.yaml", overrideConfig)

	// Load and merge configs
	config1, err := scanner.LoadConfig(baseConfigPath)
	if err != nil {
		t.Fatalf("Failed to load base config: %v", err)
	}

	config2, err := scanner.LoadConfig(overrideConfigPath)
	if err != nil {
		t.Fatalf("Failed to load override config: %v", err)
	}

	merged := scanner.MergeConfigs(config1, config2)

	// Verify merge results
	if len(merged.Scanners) != 2 {
		t.Errorf("Expected merged scanners to have 2 items, got %d", len(merged.Scanners))
	}

	if merged.OutputFormat != "json" {
		t.Error("Expected base config value to be preserved")
	}

	if merged.LLM.Provider != "openai" {
		t.Error("Expected override config value to be applied")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && 
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || 
		 len(s) > len(substr)+1 && s[1:len(substr)+1] == substr))
}
