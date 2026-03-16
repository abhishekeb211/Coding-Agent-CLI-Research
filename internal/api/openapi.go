package api

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

//go:embed openapi.yaml
var openapiSpec embed.FS

// readOpenAPISpec reads the OpenAPI specification in YAML format
func readOpenAPISpec() ([]byte, error) {
	// Try to read from embedded file first
	data, err := openapiSpec.ReadFile("openapi.yaml")
	if err == nil {
		return data, nil
	}

	// Fallback to reading from filesystem
	// This is useful during development
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get working directory: %w", err)
	}

	specPath := filepath.Join(cwd, "api", "openapi.yaml")
	data, err = os.ReadFile(specPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read OpenAPI spec: %w", err)
	}

	return data, nil
}

// readOpenAPISpecJSON reads the OpenAPI specification and converts it to JSON
func readOpenAPISpecJSON() ([]byte, error) {
	// Read YAML spec
	yamlData, err := readOpenAPISpec()
	if err != nil {
		return nil, err
	}

	// Parse YAML
	var spec interface{}
	if err := yaml.Unmarshal(yamlData, &spec); err != nil {
		return nil, fmt.Errorf("failed to parse OpenAPI YAML: %w", err)
	}

	// Convert to JSON
	jsonData, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to convert to JSON: %w", err)
	}

	return jsonData, nil
}
