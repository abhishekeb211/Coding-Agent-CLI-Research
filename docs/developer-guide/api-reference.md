# API Reference

## Scanner Package

### Orchestrator

```go
type Orchestrator struct {
    plugins map[string]Scanner
    config  Config
}

func NewOrchestrator(config Config) *Orchestrator
func (o *Orchestrator) Run(ctx context.Context, path string) (*ScanResult, error)
```

### Scanner Interface

```go
type Scanner interface {
    Name() string
    Scan(ctx context.Context, path string) ([]RawFinding, error)
    IsAvailable() bool
}
```

## Storage Package

### Database

```go
type Database struct {
    db *sql.DB
}

func NewDatabase(path string) (*Database, error)
func (d *Database) SaveRun(run *Run) error
func (d *Database) SaveRawFinding(finding *RawFinding) error
func (d *Database) SaveNormalizedFinding(finding *NormalizedFinding) error
func (d *Database) GetFindingsByRun(runID string) ([]NormalizedFinding, error)
func (d *Database) Close() error
```

## Policy Package

### Evaluator

```go
type Evaluator struct {
    policies *PolicySet
    waivers  *WaiverSet
}

func NewEvaluator(policies *PolicySet) *Evaluator
func (e *Evaluator) Evaluate(finding *Finding) *PolicyDecision
func (e *Evaluator) EvaluateAll(findings []*Finding) []*PolicyDecision
```

### Policy Loading

```go
func LoadPolicies(path string) (*PolicySet, error)
func LoadWaivers(path string) (*WaiverSet, error)
func SavePolicies(policySet *PolicySet, path string) error
```

## LLM Package

### Manager

```go
type Manager struct {
    provider LLMProvider
    config   Config
}

func NewManager(config Config) (*Manager, error)
func (m *Manager) GenerateRemediation(ctx context.Context, req RemediationRequest) (*RemediationResponse, error)
func (m *Manager) IsAvailable() bool
func (m *Manager) Close() error
```

### Cache

```go
type Cache struct {
    db      *sql.DB
    enabled bool
}

func NewCache(cacheDir string, enabled bool) (*Cache, error)
func (c *Cache) Get(req RemediationRequest) (*RemediationResponse, bool)
func (c *Cache) Set(req RemediationRequest, resp *RemediationResponse) error
func (c *Cache) Close() error
```

## SARIF Package

### Conversion

```go
func ConvertToSARIF(result *scanner.ScanResult) (*SARIF, error)
func (s *SARIF) ToJSON() ([]byte, error)
```

## CWE Package

### Mapping

```go
func MapRuleToCWE(ruleID, category string) string
func ExtractCWEFromMetadata(metadata map[string]interface{}) string
```
