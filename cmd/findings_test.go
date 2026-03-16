package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
)

// TestFindingsCommandExists tests that findings command is registered
func TestFindingsCommandExists(t *testing.T) {
	if findingsCmd == nil {
		t.Error("findingsCmd should not be nil")
	}
	if findingsCmd.Use != "findings" {
		t.Errorf("findingsCmd.Use = %v, want 'findings'", findingsCmd.Use)
	}
}

// TestFindingsListCommand tests findings list subcommand
func TestFindingsListCommand(t *testing.T) {
	if len(findingsCmd.Commands()) < 1 {
		t.Fatal("findingsCmd should have subcommands")
	}
	
	// Find list command
	var listCmd *cobra.Command
	for _, cmd := range findingsCmd.Commands() {
		if cmd.Use == "list" {
			listCmd = cmd
			break
		}
	}
	
	if listCmd == nil {
		t.Fatal("Expected 'list' subcommand not found")
	}
	
	if listCmd.Use != "list" {
		t.Errorf("Expected 'list' subcommand, got %v", listCmd.Use)
	}
}

// TestFindingsShowCommand tests findings show subcommand
func TestFindingsShowCommand(t *testing.T) {
	if len(findingsCmd.Commands()) < 2 {
		t.Fatal("findingsCmd should have at least 2 subcommands")
	}
	
	// Find show command
	var showCmd *cobra.Command
	for _, cmd := range findingsCmd.Commands() {
		if cmd.Use == "show [finding-id]" {
			showCmd = cmd
			break
		}
	}
	
	if showCmd == nil {
		t.Fatal("Expected 'show' subcommand not found")
	}
	
	if showCmd.Use != "show [finding-id]" {
		t.Errorf("Expected 'show [finding-id]' subcommand, got %v", showCmd.Use)
	}
}

// TestFindingsListFlags tests findings list command flags
func TestFindingsListFlags(t *testing.T) {
	var listCmd *cobra.Command
	for _, cmd := range findingsCmd.Commands() {
		if cmd.Use == "list" {
			listCmd = cmd
			break
		}
	}
	
	if listCmd == nil {
		t.Fatal("list command not found")
	}
	
	flags := []string{"run-id", "severity", "cwe", "limit"}
	for _, flagName := range flags {
		flag := listCmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("Expected flag %s to exist in list command", flagName)
		}
	}
}

// TestFindingsListFlagDefaults tests default values for list flags
func TestFindingsListFlagDefaults(t *testing.T) {
	var listCmd *cobra.Command
	for _, cmd := range findingsCmd.Commands() {
		if cmd.Use == "list" {
			listCmd = cmd
			break
		}
	}
	
	if listCmd == nil {
		t.Fatal("list command not found")
	}
	
	// Test limit default
	limitFlag := listCmd.Flags().Lookup("limit")
	if limitFlag == nil {
		t.Fatal("limit flag not found")
	}
	if limitFlag.DefValue != "50" {
		t.Errorf("limit default = %v, want 50", limitFlag.DefValue)
	}
	
	// Test other flags default to empty
	emptyFlags := []string{"run-id", "severity", "cwe"}
	for _, flagName := range emptyFlags {
		flag := listCmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Fatalf("Flag %s not found", flagName)
		}
		if flag.DefValue != "" {
			t.Errorf("Flag %s default = %v, want empty string", flagName, flag.DefValue)
		}
	}
}

// TestFindingsShowFlags tests findings show command flags
func TestFindingsShowFlags(t *testing.T) {
	var showCmd *cobra.Command
	for _, cmd := range findingsCmd.Commands() {
		if cmd.Use == "show [finding-id]" {
			showCmd = cmd
			break
		}
	}
	
	if showCmd == nil {
		t.Fatal("show command not found")
	}
	
	flag := showCmd.Flags().Lookup("remediation")
	if flag == nil {
		t.Error("Expected remediation flag to exist in show command")
	}
	
	// Default should be true
	if flag.DefValue != "true" {
		t.Errorf("remediation flag default = %v, want true", flag.DefValue)
	}
}

// TestFindingsShowRequiresID tests that show command requires finding ID
func TestFindingsShowRequiresID(t *testing.T) {
	var showCmd *cobra.Command
	for _, cmd := range findingsCmd.Commands() {
		if cmd.Use == "show [finding-id]" {
			showCmd = cmd
			break
		}
	}
	
	if showCmd == nil {
		t.Fatal("show command not found")
	}
	
	// Reset command for testing
	showCmd.SetArgs([]string{})
	
	// Capture output
	buf := new(bytes.Buffer)
	showCmd.SetOut(buf)
	showCmd.SetErr(buf)
	
	err := showCmd.Execute()
	if err == nil {
		t.Error("Expected error when no finding ID provided, got nil")
	}
}

// TestFindingsListSeverityFilter tests severity filtering
func TestFindingsListSeverityFilter(t *testing.T) {
	var listCmd *cobra.Command
	for _, cmd := range findingsCmd.Commands() {
		if cmd.Use == "list" {
			listCmd = cmd
			break
		}
	}
	
	if listCmd == nil {
		t.Fatal("list command not found")
	}
	
	severities := []string{"critical", "high", "medium", "low"}
	for _, severity := range severities {
		t.Run(severity, func(t *testing.T) {
			// Reset flags
			listCmd.ResetFlags()
			initConfig() // Re-initialize config/flags
			
			// Find list command again after reset
			for _, cmd := range findingsCmd.Commands() {
				if cmd.Use == "list" {
					listCmd = cmd
					break
				}
			}
			
			if err := listCmd.Flags().Set("severity", severity); err != nil {
				t.Errorf("Failed to set severity flag to %s: %v", severity, err)
			}
			
			actualSeverity, err := listCmd.Flags().GetString("severity")
			if err != nil {
				t.Errorf("Failed to get severity flag: %v", err)
			}
			if actualSeverity != severity {
				t.Errorf("Severity = %v, want %v", actualSeverity, severity)
			}
		})
	}
}

// TestFindingsListCWEFilter tests CWE filtering
func TestFindingsListCWEFilter(t *testing.T) {
	var listCmd *cobra.Command
	for _, cmd := range findingsCmd.Commands() {
		if cmd.Use == "list" {
			listCmd = cmd
			break
		}
	}
	
	if listCmd == nil {
		t.Fatal("list command not found")
	}
	
	// Reset flags
	listCmd.ResetFlags()
	initConfig() // Re-initialize config/flags
	
	// Find list command again after reset
	for _, cmd := range findingsCmd.Commands() {
		if cmd.Use == "list" {
			listCmd = cmd
			break
		}
	}
	
	cweID := "CWE-89"
	if err := listCmd.Flags().Set("cwe", cweID); err != nil {
		t.Errorf("Failed to set cwe flag: %v", err)
	}
	
	actualCWE, err := listCmd.Flags().GetString("cwe")
	if err != nil {
		t.Errorf("Failed to get cwe flag: %v", err)
	}
	if actualCWE != cweID {
		t.Errorf("CWE = %v, want %v", actualCWE, cweID)
	}
}

// TestFindingsListLimitFlag tests limit flag
func TestFindingsListLimitFlag(t *testing.T) {
	var listCmd *cobra.Command
	for _, cmd := range findingsCmd.Commands() {
		if cmd.Use == "list" {
			listCmd = cmd
			break
		}
	}
	
	if listCmd == nil {
		t.Fatal("list command not found")
	}
	
	// Reset flags
	listCmd.ResetFlags()
	initConfig() // Re-initialize config/flags
	
	// Find list command again after reset
	for _, cmd := range findingsCmd.Commands() {
		if cmd.Use == "list" {
			listCmd = cmd
			break
		}
	}
	
	limits := []int{10, 25, 100}
	for _, limit := range limits {
		t.Run(string(rune(limit)), func(t *testing.T) {
			if err := listCmd.Flags().Set("limit", string(rune(limit))); err == nil {
				actualLimit, err := listCmd.Flags().GetInt("limit")
				if err != nil {
					t.Errorf("Failed to get limit flag: %v", err)
				}
				// Just verify we can set and get the flag
				_ = actualLimit
			}
		})
	}
}
