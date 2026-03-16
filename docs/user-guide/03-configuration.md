# Configuration Guide

## Configuration File

Create a `config.yaml` file in your project root or `~/.coding-agent-cli/config.yaml`:

```yaml
# Scanner configuration
scanners:
  - bandit
  - semgrep

# Output configuration
output:
  format: json
  file: scan-results.json

# Database configuration
database:
  path: ~/.coding-agent-cli/findings.db

# LLM configuration (optional)
llm:
  enabled: true
  provider: mock  # or openai, anthropic
  model: gpt-4
  api_key: ${OPENAI_API_KEY}
  cache_enabled: true
  cache_dir: ~/.coding-agent-cli/llm-cache

# Policy configuration
policy:
  enabled: false
  file: policy.yaml

# Offline mode
offline: false
```

## Configuration Options

### Scanner Options

- `scanners`: List of scanners to use (bandit, semgrep)

### Output Options

- `output.format`: Output format (json, sarif, markdown, html, csv)
- `output.file`: Output file path

### Database Options

- `database.path`: Path to SQLite database for storing findings

### LLM Options

- `llm.enabled`: Enable AI-powered remediation guidance
- `llm.provider`: LLM provider (mock, openai, anthropic)
- `llm.model`: Model name
- `llm.api_key`: API key (use environment variable)
- `llm.cache_enabled`: Enable response caching
- `llm.cache_dir`: Cache directory path

### Policy Options

- `policy.enabled`: Enable policy enforcement
- `policy.file`: Path to policy file

## Environment Variables

Override configuration with environment variables:

```bash
export CODING_AGENT_SCANNERS="bandit,semgrep"
export CODING_AGENT_OUTPUT_FORMAT="sarif"
export CODING_AGENT_OFFLINE="true"
export OPENAI_API_KEY="your-api-key"
```

## Command-Line Flags

Command-line flags override both config file and environment variables:

```bash
coding-agent-cli scan /path --scanners bandit --format json --offline
```

## Configuration Priority

1. Command-line flags (highest priority)
2. Environment variables
3. Configuration file
4. Default values (lowest priority)
