# LLM Integration

## Overview

Coding Agent CLI integrates with Large Language Models to provide AI-powered remediation guidance for security vulnerabilities. Version 1.2 adds support for real LLM providers including OpenAI, Anthropic, and local models via Ollama.

## Supported Providers

- **OpenAI**: GPT-4, GPT-4 Turbo, GPT-3.5 Turbo
- **Anthropic**: Claude 3 Opus, Claude 3 Sonnet, Claude 3 Haiku
- **Ollama**: Local LLM inference (Llama 3, Mistral, CodeLlama, etc.)
- **Mock Provider**: Built-in mock for testing and offline use

## Configuration

### OpenAI Configuration

Configure OpenAI in `config.yaml`:

```yaml
llm:
  enabled: true
  provider: openai
  model: gpt-4-turbo  # or gpt-4, gpt-3.5-turbo
  api_key: ${OPENAI_API_KEY}
  cache_enabled: true
  max_tokens: 2048
  temperature: 0.3
```

Set API key:
```bash
export OPENAI_API_KEY="sk-..."
```

**Supported Models**:
- `gpt-4-turbo`: Latest GPT-4 Turbo (recommended)
- `gpt-4`: GPT-4 (higher quality, slower)
- `gpt-3.5-turbo`: GPT-3.5 Turbo (faster, lower cost)

### Anthropic Configuration

Configure Anthropic in `config.yaml`:

```yaml
llm:
  enabled: true
  provider: anthropic
  model: claude-3-sonnet-20240229  # or opus, haiku
  api_key: ${ANTHROPIC_API_KEY}
  cache_enabled: true
  max_tokens: 2048
```

Set API key:
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

**Supported Models**:
- `claude-3-opus-20240229`: Most capable (highest quality)
- `claude-3-sonnet-20240229`: Balanced performance (recommended)
- `claude-3-haiku-20240307`: Fastest and most affordable

### Ollama Configuration (Local LLMs)

Run LLMs locally with Ollama:

1. **Install Ollama**:
```bash
# macOS/Linux
curl -fsSL https://ollama.ai/install.sh | sh

# Windows
# Download from https://ollama.ai/download
```

2. **Pull a model**:
```bash
ollama pull llama3
# or: codellama, mistral, mixtral, etc.
```

3. **Configure**:
```yaml
llm:
  enabled: true
  provider: ollama
  model: llama3
  base_url: http://localhost:11434
  cache_enabled: true
```

**Recommended Models**:
- `llama3`: General purpose, good for security analysis
- `codellama`: Optimized for code understanding
- `mistral`: Fast and efficient
- `mixtral`: High quality, larger model

## Provider Fallback Chain

Configure multiple providers with automatic fallback:

```yaml
llm:
  enabled: true
  providers:
    - name: openai
      model: gpt-4-turbo
      api_key: ${OPENAI_API_KEY}
      priority: 1
    - name: anthropic
      model: claude-3-sonnet-20240229
      api_key: ${ANTHROPIC_API_KEY}
      priority: 2
    - name: ollama
      model: llama3
      priority: 3
    - name: mock
      priority: 4
```

If OpenAI fails, the system automatically tries Anthropic, then Ollama, then the mock provider.

## Cost Estimation

Before making API calls, the CLI estimates costs:

```bash
coding-agent-cli scan ./code --llm --estimate-cost
```

Output:
```
Estimated LLM costs:
  Findings: 42
  Estimated tokens: 84,000
  Estimated cost: $0.42 (GPT-4 Turbo)
  
Proceed with scan? [y/N]
```

Set cost limits:
```yaml
llm:
  cost_limit_per_scan: 5.00  # USD
  warn_threshold: 1.00
```

## Caching

LLM responses are cached to:
- Reduce API costs
- Improve performance
- Work offline after initial scan

Cache location: `~/.coding-agent-cli/llm-cache/`

Clear cache:
```bash
coding-agent-cli cache clear --llm
```

View cache stats:
```bash
coding-agent-cli cache stats
```

Output:
```
LLM Cache Statistics:
  Total entries: 1,234
  Cache hits: 892 (72.3%)
  Cache misses: 342 (27.7%)
  Disk usage: 45.2 MB
  Cost saved: $12.34
```

## PII Redaction

Sensitive information is automatically redacted before sending to LLM:
- API keys
- Passwords
- Email addresses
- Private keys

## Offline Mode

Disable LLM integration:
```bash
coding-agent-cli scan /path --offline
```

Or in config:
```yaml
llm:
  enabled: false
```

## Remediation Guidance

LLM provides:
- Explanation of the vulnerability
- Step-by-step remediation instructions
- Example code fixes
- Best practices
- Links to relevant documentation

View remediation:
```bash
coding-agent-cli findings show <finding-id>
```

Example output:
```
Finding: SQL Injection in database.py:42

Vulnerability Explanation:
The code constructs SQL queries using string concatenation with user input,
making it vulnerable to SQL injection attacks. An attacker could manipulate
the query to access unauthorized data or modify the database.

Remediation Steps:
1. Replace string concatenation with parameterized queries
2. Use the database library's parameter binding feature
3. Validate and sanitize all user inputs
4. Implement least-privilege database access

Code Fix:
# Before (vulnerable):
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)

# After (secure):
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))

Best Practices:
- Always use parameterized queries or prepared statements
- Never trust user input
- Use ORM frameworks that handle parameterization automatically
- Implement input validation as defense-in-depth

References:
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
```

## Rate Limiting

Each provider has rate limits:

**OpenAI**:
- GPT-4: 10,000 tokens/min (Tier 1)
- GPT-3.5: 90,000 tokens/min (Tier 1)

**Anthropic**:
- Claude 3: 50,000 tokens/min (default)

**Ollama**:
- No rate limits (local)

Configure retry behavior:
```yaml
llm:
  retry:
    max_attempts: 3
    initial_delay: 1s
    max_delay: 30s
    exponential_backoff: true
```

## Error Handling

Common errors and solutions:

**Invalid API Key**:
```
Error: OpenAI API authentication failed
Solution: Check your OPENAI_API_KEY environment variable
```

**Rate Limit Exceeded**:
```
Error: Rate limit exceeded, retrying in 30s...
Solution: Wait or switch to a different provider
```

**Provider Unavailable**:
```
Error: OpenAI API unavailable, falling back to Anthropic
```

**Cost Limit Exceeded**:
```
Error: Estimated cost ($6.50) exceeds limit ($5.00)
Solution: Increase cost_limit_per_scan or scan fewer files
```
