# Plugin Development Guide

## Scanner Plugin Interface

All scanner plugins must implement the `Scanner` interface:

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, path string) ([]RawFinding, error)
    IsAvailable() bool
}
```

## Creating a New Scanner Plugin

### Step 1: Create Plugin Package

Create a new directory under `plugins/`:
```
plugins/
└── myscan/
    ├── myscan.go
    └── myscan_test.go
```

### Step 2: Implement the Interface

```go
package myscan

import (
    "context"
    "os/exec"
    "github.com/coding-agent/cli/internal/scanner"
)

type Plugin struct{}

func (p *Plugin) Name() string {
    return "myscan"
}

func (p *Plugin) IsAvailable() bool {
    _, err := exec.LookPath("myscan")
    return err == nil
}

func (p *Plugin) Scan(ctx context.Context, path string) ([]scanner.RawFinding, error) {
    // Run scanner
    cmd := exec.CommandContext(ctx, "myscan", "--json", path)
    output, err := cmd.CombinedOutput()
    if err != nil {
        return nil, err
    }

    // Parse output
    findings, err := p.parseOutput(output)
    if err != nil {
        return nil, err
    }

    return findings, nil
}

func (p *Plugin) parseOutput(output []byte) ([]scanner.RawFinding, error) {
    // Parse scanner-specific output format
    // Convert to RawFinding format
    return findings, nil
}
```

### Step 3: Register Plugin

Register the plugin in `internal/scanner/orchestrator.go`:

```go
func NewOrchestrator(config Config) *Orchestrator {
    orch := &Orchestrator{
        plugins: make(map[string]Scanner),
        config:  config,
    }

    // Register plugins
    orch.plugins["bandit"] = &bandit.Plugin{}
    orch.plugins["semgrep"] = &semgrep.Plugin{}
    orch.plugins["myscan"] = &myscan.Plugin{}  // Add your plugin

    return orch
}
```

### Step 4: Add CWE Mappings

Add rule-to-CWE mappings in `internal/cwe/mapper.go`:

```go
var RuleToCWEMap = map[string]string{
    // Existing mappings...
    
    // MyScanner rules
    "MYSCAN-001": "CWE-89",
    "MYSCAN-002": "CWE-79",
}
```

### Step 5: Write Tests

```go
package myscan

import (
    "context"
    "testing"
)

func TestName(t *testing.T) {
    plugin := &Plugin{}
    if plugin.Name() != "myscan" {
        t.Errorf("Name() = %v, want myscan", plugin.Name())
    }
}

func TestScan(t *testing.T) {
    plugin := &Plugin{}
    ctx := context.Background()
    
    findings, err := plugin.Scan(ctx, "./testdata")
    if err != nil {
        t.Fatalf("Scan() error = %v", err)
    }
    
    if len(findings) == 0 {
        t.Error("Expected findings but got none")
    }
}
```

## Best Practices

### Error Handling
- Return descriptive errors
- Handle scanner not found gracefully
- Validate input paths

### Performance
- Use context for cancellation
- Stream large outputs
- Implement timeouts

### Output Parsing
- Handle malformed output
- Validate JSON/XML schemas
- Provide fallback for unknown formats

### Testing
- Test with real scanner output
- Test error conditions
- Test with various code samples

## Example: Complete Plugin

See `plugins/bandit/bandit.go` and `plugins/semgrep/semgrep.go` for complete examples.
