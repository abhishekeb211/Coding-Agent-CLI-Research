package cmd

import (
	"testing"
)

func TestServeCommand(t *testing.T) {
	// Test that serve command is registered
	cmd := rootCmd
	serveCmd := cmd.Commands()

	found := false
	for _, c := range serveCmd {
		if c.Name() == "serve" {
			found = true
			break
		}
	}

	if !found {
		t.Error("serve command not registered")
	}
}

func TestServeFlags(t *testing.T) {
	// Test that flags are defined
	flags := serveCmd.Flags()

	hostFlag := flags.Lookup("host")
	if hostFlag == nil {
		t.Error("host flag not defined")
	}

	portFlag := flags.Lookup("port")
	if portFlag == nil {
		t.Error("port flag not defined")
	}

	// Test default values
	if hostFlag.DefValue != "localhost" {
		t.Errorf("Expected default host 'localhost', got '%s'", hostFlag.DefValue)
	}

	if portFlag.DefValue != "8080" {
		t.Errorf("Expected default port '8080', got '%s'", portFlag.DefValue)
	}
}
