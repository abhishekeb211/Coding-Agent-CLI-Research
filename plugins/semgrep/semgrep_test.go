package semgrep

import (
	"context"
	"testing"
)

// TestName tests plugin name
func TestName(t *testing.T) {
	plugin := &Scanner{}
	if plugin.Name() != "semgrep" {
		t.Errorf("Name() = %v, want semgrep", plugin.Name())
	}
}

// TestIsAvailable tests availability check
func TestIsAvailable(t *testing.T) {
	plugin := &Scanner{}
	// Just ensure it doesn't panic
	_ = plugin.IsAvailable()
}

// TestScanWithInvalidPath tests error handling for invalid paths
func TestScanWithInvalidPath(t *testing.T) {
	plugin := &Scanner{}
	ctx := context.Background()

	_, err := plugin.Scan(ctx, "/non/existent/path")
	if err == nil {
		t.Error("Expected error for non-existent path")
	}
}
