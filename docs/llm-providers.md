# LLM Provider Configuration

This document describes how to configure and use different LLM providers for generating security remediation guidance.

## Supported Providers

The Coding Agent CLI supports multiple LLM providers for generating security remediation guidance:

1. **OpenAI** (GPT-3.5-turbo, GPT-4) - Cloud-based, high quality, paid
2. **Anthropic** (Claude 3 Opus, Sonnet, Haiku) - Cloud-based, high quality, paid
3. **Ollama** (Local LLMs) - Local, privacy-focused, free
4. **Mock** - Testing/development, instant responses, free

### 1. OpenAI (GPT-3.5-turbo, GPT-4)

The OpenAI provider uses OpenAI's API to generate remediation guidance.

#### Configuration

```go
config := llm.Config{
    Provider:     "openai",
    APIKey:       "your-openai-api-key",
    Model:        "gpt-3.5-turbo", // or "gpt-4", "gpt-4-turbo"
    MaxTokens:    1024,
    Temperature:  0.7,
    Timeout:      30 * time.Second,
    CacheEnabled: true,
    CacheDir:     "/path/to/cache",
}

manager, err := llm.NewManager(config)
if err != nil {
    log.Fatal(err)
}
defer manager.Close()
```

#### Environment Variables

You can also configure the OpenAI provider using environment variables:

```bash
export OPENAI_API_KEY="your-api-key"
export OPENAI_MODEL="gpt-3.5-turbo"
```

#### Supported Models

- **gpt-3.5-turbo**: Fast and cost-effective ($0.0005/1K input tokens, $0.0015/1K output tokens)
- **gpt-4**: More capable but slower ($0.03/1K input tokens, $0.06/1K output tokens)
- **gpt-4-turbo**: Faster GPT-4 variant ($0.01/1K input tokens, $0.03/1K output tokens)

#### Cost Estimation

The OpenAI provider includes cost estimation:

```go
req := llm.RemediationRequest{
    CWEID:       "CWE-89",
    CodeSnippet: "query = \"SELECT * FROM users WHERE id = \" + user_input",
    Severity:    "high",
}

cost, err := manager.EstimateCost(req)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Estimated cost: $%.4f\n", cost)
```

#### Cost Limits

You can set a cost limit to prevent expensive requests:

```go
config := llm.Config{
    Provider:  "openai",
    APIKey:    "your-api-key",
    CostLimit: 0.01, // Maximum $0.01 per request
}
```

#### Rate Limiting

The OpenAI provider automatically rate limits requests to 10 requests per second to comply with OpenAI's rate limits.

### 2. Mock Provider (Default)

The mock provider is used for testing and development. It generates predefined responses based on CWE categories.

```go
config := llm.Config{
    Provider: "mock",
}

manager, err := llm.NewManager(config)
```

The mock provider:
- Returns instant responses
- Has zero cost
- Provides CWE-specific guidance for common vulnerabilities
- Always available (no API key required)

### 3. Anthropic (Claude 3 Opus, Sonnet, Haiku)

The Anthropic provider uses Anthropic's Claude API to generate remediation guidance.

#### Configuration

```go
config := llm.Config{
    Provider:     "anthropic",
    APIKey:       "your-anthropic-api-key",
    Model:        "claude-3-sonnet-20240229", // or "claude-3-opus-20240229", "claude-3-haiku-20240307"
    MaxTokens:    1024,
    Temperature:  0.7,
    Timeout:      30 * time.Second,
    CacheEnabled: true,
    CacheDir:     "/path/to/cache",
}

manager, err := llm.NewManager(config)
if err != nil {
    log.Fatal(err)
}
defer manager.Close()
```

#### Environment Variables

You can also configure the Anthropic provider using environment variables:

```bash
export ANTHROPIC_API_KEY="your-api-key"
export ANTHROPIC_MODEL="claude-3-sonnet-20240229"
```

#### Supported Models

- **claude-3-haiku-20240307**: Fastest and most cost-effective ($0.25/1M input tokens, $1.25/1M output tokens)
- **claude-3-sonnet-20240229**: Balanced performance and cost ($3.00/1M input tokens, $15.00/1M output tokens)
- **claude-3-opus-20240229**: Most capable model ($15.00/1M input tokens, $75.00/1M output tokens)

#### Cost Estimation

The Anthropic provider includes cost estimation:

```go
req := llm.RemediationRequest{
    CWEID:       "CWE-89",
    CodeSnippet: "query = \"SELECT * FROM users WHERE id = \" + user_input",
    Severity:    "high",
}

cost, err := manager.EstimateCost(req)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Estimated cost: $%.6f\n", cost)
```

#### Cost Limits

You can set a cost limit to prevent expensive requests:

```go
config := llm.Config{
    Provider:  "anthropic",
    APIKey:    "your-api-key",
    CostLimit: 0.01, // Maximum $0.01 per request
}
```

#### Rate Limiting

The Anthropic provider automatically rate limits requests to 10 requests per second to comply with Anthropic's rate limits.

### 4. Ollama (Local LLMs)

The Ollama provider enables you to use local LLMs running on your machine via [Ollama](https://ollama.ai/). This is ideal for:
- Privacy-sensitive environments
- Offline usage
- Zero API costs
- Custom or fine-tuned models

#### Prerequisites

1. Install Ollama from [ollama.ai](https://ollama.ai/)
2. Pull a model: `ollama pull llama2`
3. Start Ollama (it runs on port 11434 by default)

#### Configuration

```go
config := llm.Config{
    Provider:     "ollama",
    Model:        "llama2", // or "codellama", "mistral", etc.
    BaseURL:      "http://localhost:11434", // Default Ollama URL
    MaxTokens:    1024,
    Temperature:  0.7,
    Timeout:      60 * time.Second, // Longer timeout for local models
    CacheEnabled: true,
    CacheDir:     "/path/to/cache",
}

manager, err := llm.NewManager(config)
if err != nil {
    log.Fatal(err)
}
defer manager.Close()
```

#### Environment Variables

You can also configure the Ollama provider using environment variables:

```bash
export OLLAMA_HOST="http://localhost:11434"
export OLLAMA_MODEL="llama2"
```

#### Supported Models

Ollama supports many models. Popular choices for security analysis:

- **llama2**: General-purpose model, good balance of speed and quality
- **codellama**: Optimized for code understanding and generation
- **mistral**: Fast and capable, good for security analysis
- **mixtral**: Mixture of experts model, high quality
- **phi**: Small but capable model, very fast

To see available models: `ollama list`
To pull a new model: `ollama pull <model-name>`

#### Cost Estimation

Local models are free to run:

```go
cost, err := manager.EstimateCost(req)
// cost will always be 0.0 for Ollama
```

#### Performance Considerations

- **First request**: May be slower as the model loads into memory
- **Subsequent requests**: Faster as the model stays loaded
- **Hardware**: Performance depends on your CPU/GPU
- **Model size**: Smaller models (7B parameters) are faster than larger ones (70B parameters)

#### Connection Error Handling

The Ollama provider gracefully handles connection errors:

```go
manager, err := llm.NewManager(config)
if err != nil {
    log.Fatal(err)
}

// Check if Ollama is available
if !manager.IsAvailable() {
    log.Println("Ollama is not running. Please start Ollama and try again.")
    log.Println("Run: ollama serve")
    return
}
```

#### Rate Limiting

The Ollama provider has minimal rate limiting (10ms between requests) since it's running locally.

#### Example Usage

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"
    
    "github.com/coding-agent/cli/internal/llm"
)

func main() {
    // Configure Ollama provider
    config := llm.Config{
        Provider:     "ollama",
        Model:        "codellama", // Good for code analysis
        BaseURL:      "http://localhost:11434",
        MaxTokens:    1024,
        Temperature:  0.7,
        Timeout:      60 * time.Second,
        CacheEnabled: true,
        CacheDir:     "/tmp/llm-cache",
    }
    
    manager, err := llm.NewManager(config)
    if err != nil {
        log.Fatal(err)
    }
    defer manager.Close()
    
    // Check availability
    if !manager.IsAvailable() {
        log.Fatal("Ollama is not running. Start it with: ollama serve")
    }
    
    // Create remediation request
    req := llm.RemediationRequest{
        CWEID:          "CWE-89",
        CWEDescription: "SQL Injection",
        CodeSnippet:    "query = \"SELECT * FROM users WHERE id = \" + user_input",
        FilePath:       "app.py",
        LineNumber:     42,
        Severity:       "high",
    }
    
    // Generate remediation (free!)
    ctx := context.Background()
    resp, err := manager.GenerateRemediation(ctx, req)
    if err != nil {
        log.Fatal(err)
    }
    
    // Display results
    fmt.Printf("Explanation: %s\n", resp.Explanation)
    fmt.Println("\nRemediation Steps:")
    for i, step := range resp.RemediationSteps {
        fmt.Printf("%d. %s\n", i+1, step)
    }
    fmt.Printf("\nConfidence: %.2f\n", resp.Confidence)
}
```

#### Troubleshooting

**"Connection refused" error**
- Ensure Ollama is running: `ollama serve`
- Check if Ollama is listening on the correct port
- Verify firewall settings

**"Model not found" error**
- Pull the model: `ollama pull llama2`
- List available models: `ollama list`
- Check model name spelling

**Slow responses**
- Use a smaller model (e.g., phi instead of llama2:70b)
- Ensure sufficient RAM (8GB+ recommended)
- Close other applications to free up resources
- Consider using GPU acceleration if available

**Out of memory errors**
- Use a smaller model
- Reduce MaxTokens
- Close other applications
- Increase system swap space

#### Advantages

✅ **Privacy**: Data never leaves your machine
✅ **Cost**: Completely free to run
✅ **Offline**: Works without internet connection
✅ **Customization**: Use custom or fine-tuned models
✅ **No rate limits**: Limited only by your hardware

#### Disadvantages

❌ **Quality**: May not match GPT-4 or Claude 3 Opus
❌ **Speed**: Slower than cloud APIs (depends on hardware)
❌ **Resources**: Requires significant RAM/CPU
❌ **Setup**: Requires installing and managing Ollama

## Provider Fallback Chain

You can configure multiple providers with automatic fallback:

```go
config := llm.Config{
    Provider:          "openai",
    FallbackProviders: []string{"anthropic", "ollama", "mock"},
    APIKey:            "your-openai-api-key",
}

manager, err := llm.NewManager(config)
```

If the primary provider (OpenAI) fails, the manager will automatically try the fallback providers in order.

**Example with Anthropic as primary and Ollama as fallback:**

```go
config := llm.Config{
    Provider:          "anthropic",
    FallbackProviders: []string{"ollama", "mock"},
    APIKey:            "your-anthropic-api-key",
}
```

**Example with Ollama as primary (privacy-first):**

```go
config := llm.Config{
    Provider:          "ollama",
    FallbackProviders: []string{"mock"}, // Fallback to mock if Ollama is down
    Model:             "codellama",
}
```

## Caching

All providers support response caching to reduce costs and improve performance:

```go
config := llm.Config{
    Provider:     "openai",
    APIKey:       "your-api-key",
    CacheEnabled: true,
    CacheDir:     "/path/to/cache",
}
```

Cached responses are stored in a SQLite database and keyed by:
- CWE ID
- File path
- Code snippet
- Line number
- Rule ID

## Retry Logic

The manager implements exponential backoff retry for transient failures:

```go
config := llm.Config{
    Provider:        "openai",
    APIKey:          "your-api-key",
    MaxRetries:      3,
    RetryDelay:      1 * time.Second,
    RetryMultiplier: 2.0, // Delay doubles after each retry
}
```

## PII Redaction

All providers automatically redact sensitive information before sending requests:

- API keys
- Passwords
- Tokens
- Email addresses
- IP addresses
- Credit card numbers

Redacted values are replaced with placeholders like `[REDACTED_API_KEY]`.

## Usage Example

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"
    
    "github.com/coding-agent/cli/internal/llm"
)

func main() {
    // Configure LLM manager
    config := llm.Config{
        Provider:     "openai",
        APIKey:       "your-openai-api-key",
        Model:        "gpt-3.5-turbo",
        MaxTokens:    1024,
        Temperature:  0.7,
        Timeout:      30 * time.Second,
        CacheEnabled: true,
        CacheDir:     "/tmp/llm-cache",
    }
    
    manager, err := llm.NewManager(config)
    if err != nil {
        log.Fatal(err)
    }
    defer manager.Close()
    
    // Create remediation request
    req := llm.RemediationRequest{
        CWEID:          "CWE-89",
        CWEDescription: "SQL Injection",
        CodeSnippet:    "query = \"SELECT * FROM users WHERE id = \" + user_input",
        FilePath:       "app.py",
        LineNumber:     42,
        Severity:       "high",
        RuleID:         "B608",
        Message:        "SQL injection vulnerability detected",
    }
    
    // Estimate cost
    cost, err := manager.EstimateCost(req)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Estimated cost: $%.4f\n", cost)
    
    // Generate remediation
    ctx := context.Background()
    resp, err := manager.GenerateRemediation(ctx, req)
    if err != nil {
        log.Fatal(err)
    }
    
    // Display results
    fmt.Printf("Explanation: %s\n", resp.Explanation)
    fmt.Println("\nRemediation Steps:")
    for i, step := range resp.RemediationSteps {
        fmt.Printf("%d. %s\n", i+1, step)
    }
    fmt.Printf("\nExample Fix:\n%s\n", resp.ExampleFix)
    fmt.Printf("\nConfidence: %.2f\n", resp.Confidence)
    fmt.Printf("Cached: %v\n", resp.Cached)
}
```

## Best Practices

1. **Use caching**: Enable caching to reduce costs and improve performance
2. **Set cost limits**: Prevent unexpected charges with cost limits
3. **Configure fallbacks**: Use fallback providers for reliability
4. **Choose appropriate models**: Use gpt-3.5-turbo for most cases, gpt-4 for complex vulnerabilities
5. **Monitor costs**: Track API usage and costs regularly
6. **Use timeouts**: Set reasonable timeouts to prevent hanging requests
7. **Handle errors**: Implement proper error handling for API failures

## Troubleshooting

### "Invalid API key" error

- Verify your API key is correct
- Check that the API key has the necessary permissions
- Ensure the API key is not expired

### "Rate limit exceeded" error

- The provider automatically rate limits requests
- If you hit OpenAI's rate limits, wait a few seconds and retry
- Consider upgrading your OpenAI plan for higher rate limits

### High costs

- Enable caching to avoid duplicate requests
- Use gpt-3.5-turbo instead of gpt-4 for most cases
- Set cost limits to prevent expensive requests
- Review your usage in the OpenAI dashboard

### Slow responses

- Use gpt-3.5-turbo for faster responses
- Reduce MaxTokens to limit response length
- Enable caching to serve cached responses instantly
- Check your network connection

## Security Considerations

1. **API Key Storage**: Never commit API keys to version control
2. **Environment Variables**: Store API keys in environment variables or secure vaults
3. **PII Redaction**: The provider automatically redacts PII, but review code snippets before sending
4. **Cost Monitoring**: Monitor API usage to detect unauthorized access
5. **Rate Limiting**: The provider enforces rate limits to prevent abuse

## References

- [OpenAI API Documentation](https://platform.openai.com/docs/api-reference)
- [OpenAI Pricing](https://openai.com/pricing)
- [OpenAI Rate Limits](https://platform.openai.com/docs/guides/rate-limits)
- [Anthropic API Documentation](https://docs.anthropic.com/claude/reference/getting-started-with-the-api)
- [Anthropic Pricing](https://www.anthropic.com/api)
- [Anthropic Models](https://docs.anthropic.com/claude/docs/models-overview)
