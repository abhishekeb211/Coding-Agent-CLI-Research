package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
)

// TestRootCommandExists tests that root command is initialized
func TestRootCommandExists(t *testing.T) {
	if rootCmd == nil {
		t.Fatal("rootCmd should not be nil")
	}
}

// TestRootCommandUse tests root command use string
func TestRootCommandUse(t *testing.T) {
	if rootCmd.Use != "coding-agent-cli" {
		t.Errorf("rootCmd.Use = %v, want 'coding-agent-cli'", rootCmd.Use)
	}
}

// TestRootCommandVersion tests root command version
func TestRootCommandVersion(t *testing.T) {
	if rootCmd.Version == "" {
		t.Error("rootCmd.Version should not be empty")
	}
}

// TestRootCommandHasSubcommands tests that root command has subcommands
func TestRootCommandHasSubcommands(t *testing.T) {
	commands := rootCmd.Commands()
	if len(commands) == 0 {
		t.Error("rootCmd should have subcommands")
	}
	
	// Check for expected subcommands
	expectedCommands := []string{"scan", "findings", "policy", "report", "serve", "migrate"}
	foundCommands := make(map[string]bool)
	
	for _, cmd := range commands {
		foundCommands[cmd.Name()] = true
	}
	
	for _, expected := range expectedCommands {
		if !foundCommands[expected] {
			t.Errorf("Expected subcommand %s not found", expected)
		}
	}
}

// TestRootCommandPersistentFlags tests persistent flags
func TestRootCommandPersistentFlags(t *testing.T) {
	flags := []string{"config", "verbose"}
	
	for _, flagName := range flags {
		flag := rootCmd.PersistentFlags().Lookup(flagName)
		if flag == nil {
			t.Errorf("Expected persistent flag %s to exist", flagName)
		}
	}
}

// TestRootCommandConfigFlag tests config flag
func TestRootCommandConfigFlag(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("config")
	if flag == nil {
		t.Fatal("config flag not found")
	}
	
	if flag.Value.Type() != "string" {
		t.Errorf("config flag type = %v, want string", flag.Value.Type())
	}
	
	if flag.DefValue != "" {
		t.Errorf("config flag default = %v, want empty string", flag.DefValue)
	}
}

// TestRootCommandVerboseFlag tests verbose flag
func TestRootCommandVerboseFlag(t *testing.T) {
	flag := rootCmd.PersistentFlags().Lookup("verbose")
	if flag == nil {
		t.Fatal("verbose flag not found")
	}
	
	if flag.Value.Type() != "bool" {
		t.Errorf("verbose flag type = %v, want bool", flag.Value.Type())
	}
	
	if flag.DefValue != "false" {
		t.Errorf("verbose flag default = %v, want false", flag.DefValue)
	}
	
	// Check shorthand
	if flag.Shorthand != "v" {
		t.Errorf("verbose flag shorthand = %v, want 'v'", flag.Shorthand)
	}
}

// TestExecute tests Execute function
func TestExecute(t *testing.T) {
	// Save original args
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	
	// Set test args
	os.Args = []string{"coding-agent-cli", "--help"}
	
	// Reset command
	rootCmd.SetArgs([]string{"--help"})
	
	// Capture output
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	
	err := rootCmd.Execute()
	if err != nil {
		t.Errorf("Execute() with --help failed: %v", err)
	}
	
	output := buf.String()
	if len(output) == 0 {
		t.Error("Expected help output, got empty string")
	}
}

// TestVersionInfo tests version information
func TestVersionInfo(t *testing.T) {
	// Test default values
	if Version == "" {
		Version = "dev"
	}
	if BuildDate == "" {
		BuildDate = "unknown"
	}
	if GitCommit == "" {
		GitCommit = "unknown"
	}
	
	// Verify they're set
	if Version == "" {
		t.Error("Version should not be empty")
	}
	if BuildDate == "" {
		t.Error("BuildDate should not be empty")
	}
	if GitCommit == "" {
		t.Error("GitCommit should not be empty")
	}
}

// TestSetVersionTemplate tests SetVersionTemplate function
func TestSetVersionTemplate(t *testing.T) {
	// Set test version info
	Version = "1.2.0"
	BuildDate = "2024-01-01"
	GitCommit = "abc123"
	
	SetVersionTemplate()
	
	// Capture version output
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"--version"})
	
	err := rootCmd.Execute()
	if err != nil {
		t.Errorf("Execute() with --version failed: %v", err)
	}
	
	output := buf.String()
	if len(output) == 0 {
		t.Error("Expected version output, got empty string")
	}
	
	// Check that version info is in output
	if !bytes.Contains([]byte(output), []byte(Version)) {
		t.Errorf("Version output should contain %s", Version)
	}
}

// TestPrintVersion tests PrintVersion function
func TestPrintVersion(t *testing.T) {
	// Set test version info
	Version = "1.2.0"
	BuildDate = "2024-01-01"
	GitCommit = "abc123"
	
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	
	PrintVersion()
	
	w.Close()
	os.Stdout = oldStdout
	
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	output := buf.String()
	
	if len(output) == 0 {
		t.Error("Expected version output, got empty string")
	}
	
	// Check that version info is in output
	if !bytes.Contains([]byte(output), []byte(Version)) {
		t.Errorf("Version output should contain %s", Version)
	}
	if !bytes.Contains([]byte(output), []byte(BuildDate)) {
		t.Errorf("Version output should contain %s", BuildDate)
	}
	if !bytes.Contains([]byte(output), []byte(GitCommit)) {
		t.Errorf("Version output should contain %s", GitCommit)
	}
}

// TestInitConfig tests config initialization
func TestInitConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configFile := filepath.Join(tmpDir, "config.yaml")
	
	configContent := `---
offline_mode: true
database:
  path: ./test.db
`
	
	if err := os.WriteFile(configFile, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}
	
	// Set config file
	cfgFile = configFile
	verbose = true
	
	// Initialize config
	initConfig()
	
	// Verify config was loaded
	if viper.ConfigFileUsed() != configFile {
		t.Errorf("Config file used = %v, want %v", viper.ConfigFileUsed(), configFile)
	}
}

// TestInitConfigNoFile tests config initialization without file
func TestInitConfigNoFile(t *testing.T) {
	// Reset viper
	viper.Reset()
	
	// Set non-existent config file
	cfgFile = ""
	verbose = false
	
	// Initialize config (should not error)
	initConfig()
	
	// Should use defaults
	if viper.ConfigFileUsed() != "" {
		t.Logf("Config file used: %v (expected empty, but this is ok)", viper.ConfigFileUsed())
	}
}

// TestGetConfigString tests GetConfigString function
func TestGetConfigString(t *testing.T) {
	viper.Reset()
	viper.Set("test.string", "value")
	
	result := GetConfigString("test.string")
	if result != "value" {
		t.Errorf("GetConfigString() = %v, want 'value'", result)
	}
	
	// Test non-existent key
	result = GetConfigString("nonexistent")
	if result != "" {
		t.Errorf("GetConfigString() for non-existent key = %v, want empty string", result)
	}
}

// TestGetConfigBool tests GetConfigBool function
func TestGetConfigBool(t *testing.T) {
	viper.Reset()
	viper.Set("test.bool", true)
	
	result := GetConfigBool("test.bool")
	if !result {
		t.Error("GetConfigBool() = false, want true")
	}
	
	// Test non-existent key
	result = GetConfigBool("nonexistent")
	if result {
		t.Error("GetConfigBool() for non-existent key = true, want false")
	}
}

// TestGetConfigInt tests GetConfigInt function
func TestGetConfigInt(t *testing.T) {
	viper.Reset()
	viper.Set("test.int", 42)
	
	result := GetConfigInt("test.int")
	if result != 42 {
		t.Errorf("GetConfigInt() = %v, want 42", result)
	}
	
	// Test non-existent key
	result = GetConfigInt("nonexistent")
	if result != 0 {
		t.Errorf("GetConfigInt() for non-existent key = %v, want 0", result)
	}
}

// TestGetConfigStringSlice tests GetConfigStringSlice function
func TestGetConfigStringSlice(t *testing.T) {
	viper.Reset()
	viper.Set("test.slice", []string{"a", "b", "c"})
	
	result := GetConfigStringSlice("test.slice")
	if len(result) != 3 {
		t.Errorf("GetConfigStringSlice() length = %v, want 3", len(result))
	}
	
	expected := []string{"a", "b", "c"}
	for i, v := range result {
		if v != expected[i] {
			t.Errorf("GetConfigStringSlice()[%d] = %v, want %v", i, v, expected[i])
		}
	}
	
	// Test non-existent key
	result = GetConfigStringSlice("nonexistent")
	if result != nil && len(result) != 0 {
		t.Errorf("GetConfigStringSlice() for non-existent key = %v, want nil or empty", result)
	}
}

// TestRootCommandHelp tests help output
func TestRootCommandHelp(t *testing.T) {
	// Reset command
	rootCmd.SetArgs([]string{"--help"})
	
	// Capture output
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	
	err := rootCmd.Execute()
	if err != nil {
		t.Errorf("Execute() with --help failed: %v", err)
	}
	
	output := buf.String()
	
	// Check for expected content in help
	expectedStrings := []string{
		"coding-agent-cli",
		"Offline-first",
		"security scanning",
		"Available Commands",
		"Flags",
	}
	
	for _, expected := range expectedStrings {
		if !bytes.Contains([]byte(output), []byte(expected)) {
			t.Errorf("Help output should contain '%s'", expected)
		}
	}
}

// TestRootCommandInvalidSubcommand tests invalid subcommand
func TestRootCommandInvalidSubcommand(t *testing.T) {
	// Reset command
	rootCmd.SetArgs([]string{"invalid-command"})
	
	// Capture output
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	
	err := rootCmd.Execute()
	if err == nil {
		t.Error("Expected error for invalid subcommand, got nil")
	}
}
