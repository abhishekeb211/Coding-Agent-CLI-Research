# LLM Provider Error Handling

This document describes the error handling improvements implemented for LLM providers in v1.2.

## Overview

The LLM provider system now includes comprehensive error handling with:
- Clear, user-friendly error messages
- Automatic fallback chain (primary → secondary → cache → mock)
- Intelligent retry logic for transient errors
- Detailed error classification

## Error Types

### Standard Errors

- `ErrInvalidAPIKey`: API key is invalid, missing, or has insufficient permissions
- `ErrProviderUnavailable`: Provider service is temporarily unavailable
- `ErrRateLimitExceeded`: API rate limit has been exceeded
- `ErrCostLimitExceeded`: Estimated cost exceeds configured limit
- `ErrTimeout`: Request timed out
- `ErrInvalidModel`: Specified model is not supported
- `ErrNoProvidersAvailable`: No providers are configured or available

### Provider Errors

All provider-specific errors are wrapped in a `ProviderError` that includes:
- Provider name (e.g., "openai", "anthropic", "ollama")
- Underlying error
- User-friendly message
- Retryable flag

## Fallback Chain

The system automatically tries providers in order until one succeeds:

```
1. Primary Provider (e.g., OpenAI)
   ↓ (if fails)
2. Secondary Provider (e.g., Anthropic)
   ↓ (if fails)
3. Cached Response (if available)
   ↓ (if no cache)
4. Mock Provider (fallback)
```

### Configuration Example

```yaml
llm:
  provider: openai
  fallback_providers:
    - anthropic
    - ollama
    - mock
  api_keys:
    openai: sk-...
    anthropic: sk-ant-...
```

## Error Messages

### Invalid API Key

When an API key is invalid or missing:

```
❌ openai: Invalid API key. Please check your OpenAI API key configuration.

To fix this:
  1. Check your API key in the configuration
  2. Verify the key has not expired
  3. Ensure the key has proper permissions

Configuration file: ~/.coding-agent-cli/config.yaml
```

### Provider Unavailable

When a provider service is down:

```
⚠️  anthropic: Provider server error (status 503). Will retry with fallback.

The system will automatically try fallback providers.
```

### Rate Limit Exceeded

When rate limits are hit:

```
⏱️  openai: Rate limit exceeded. Please wait before retrying.

The system will automatically retry with exponential backoff.
```

### All Providers Failed

When all providers in the chain fail:

```
All LLM providers failed:
  • openai: Invalid API key. Please check your OpenAI API key configuration.
  • anthropic: Provider server error (status 503). Will retry with fallback.
  • ollama: Cannot connect to Ollama. Please ensure Ollama is running.

Troubleshooting:
  1. Check your API keys are configured correctly
  2. Verify network connectivity
  3. Ensure at least one provider is available
  4. Check the documentation: https://docs.coding-agent-cli.dev/llm-providers
```

## Retry Logic

### Retryable Errors

The following errors trigger automatic retry with exponential backoff:
- Rate limit exceeded (429)
- Server errors (500, 502, 503, 504)
- Timeout errors
- Network connection errors

### Non-Retryable Errors

The following errors fail immediately without retry:
- Invalid API key (401, 403)
- Invalid model
- Cost limit exceeded
- Invalid request format

### Retry Configuration

```yaml
llm:
  max_retries: 3
  retry_delay: 1s
  retry_multiplier: 2.0
```

This configuration will retry up to 3 times with delays of 1s, 2s, 4s.

## HTTP Error Classification

The system automatically classifies HTTP errors:

| Status Code | Error Type | Retryable | Message |
|------------|------------|-----------|---------|
| 401 | Invalid API Key | No | Authentication failed |
| 403 | Invalid API Key | No | Access forbidden |
| 429 | Rate Limit | Yes | Rate limit exceeded |
| 500 | Provider Unavailable | Yes | Server error |
| 502 | Provider Unavailable | Yes | Bad gateway |
| 503 | Provider Unavailable | Yes | Service unavailable |
| 504 | Provider Unavailable | Yes | Gateway timeout |

## Provider-Specific Handling

### OpenAI

- Detects invalid API key from error type `invalid_request_error`
- Handles rate limiting with exponential backoff
- Provides model-specific error messages

### Anthropic

- Detects authentication errors from error type `authentication_error`
- Handles Claude-specific error responses
- Provides clear model availability messages

### Ollama

- Detects connection failures (Ollama not running)
- Provides helpful "start Ollama" messages
- Handles local model availability

## Cost Limit Protection

To prevent unexpected costs, you can set a cost limit:

```yaml
llm:
  cost_limit: 0.10  # Maximum $0.10 per request
```

If the estimated cost exceeds this limit, the request fails with:

```
❌ openai: estimated cost $0.15 exceeds limit $0.10

Consider:
  1. Using a cheaper model (e.g., gpt-3.5-turbo instead of gpt-4)
  2. Reducing max_tokens
  3. Increasing cost_limit if acceptable
```

## Testing

The error handling system includes comprehensive tests:

- `errors_test.go`: Tests error types and classification
- `fallback_test.go`: Tests fallback chain and retry logic

Run tests with:

```bash
go test ./internal/llm/... -v
```

## Best Practices

1. **Configure Multiple Providers**: Set up at least 2 providers for redundancy
2. **Set Reasonable Timeouts**: Default 30s is usually sufficient
3. **Enable Caching**: Reduces costs and improves reliability
4. **Monitor Costs**: Set cost limits to prevent surprises
5. **Check Logs**: Review error messages to identify configuration issues

## Troubleshooting

### "Invalid API key" errors

1. Check environment variables: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`
2. Verify keys in config file: `~/.coding-agent-cli/config.yaml`
3. Test keys with provider's CLI tools
4. Check key permissions and quotas

### "Provider unavailable" errors

1. Check network connectivity
2. Verify provider status pages
3. For Ollama: ensure `ollama serve` is running
4. Check firewall/proxy settings

### "All providers failed" errors

1. Review each provider's specific error
2. Fix configuration issues one by one
3. Test each provider independently
4. Consider using mock provider as ultimate fallback

## Migration from v1.0

In v1.0, errors were generic and unhelpful:

```
Error: failed to generate remediation
```

In v1.2, errors are specific and actionable:

```
❌ openai: Invalid API key. Please check your OpenAI API key configuration.

To fix this:
  1. Check your API key in the configuration
  2. Verify the key has not expired
  3. Ensure the key has proper permissions
```

No code changes are required - the improved error handling is automatic.
