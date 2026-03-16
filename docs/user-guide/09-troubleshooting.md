# Troubleshooting Guide

## Common Issues

### Scanner Not Found

**Error**: `bandit: command not found`

**Solution**:
```bash
pip install bandit
```

Verify:
```bash
bandit --version
```

### Permission Denied

**Error**: `permission denied: /path/to/code`

**Solution**:
- Check file permissions
- Run with appropriate user permissions
- Avoid scanning system directories

### Database Locked

**Error**: `database is locked`

**Solution**:
- Close other instances of the CLI
- Check for stale lock files
- Use a different database path

### LLM API Errors

**Error**: `LLM API request failed`

**Solutions**:
- Check API key is set correctly
- Verify internet connection
- Check API rate limits
- Use `--offline` flag to skip LLM

### Invalid Policy File

**Error**: `failed to parse policy YAML`

**Solution**:
- Validate YAML syntax
- Check required fields (id, action, cwe)
- Use `policy validate` command

## Performance Issues

### Slow Scans

**Solutions**:
- Use specific scanners instead of all
- Exclude large directories
- Use `--offline` mode
- Increase timeout values

### High Memory Usage

**Solutions**:
- Scan smaller directories
- Use `--offline` mode
- Close other applications

## Getting Help

### Enable Verbose Logging

```bash
coding-agent-cli scan /path --verbose
```

### Check Version

```bash
coding-agent-cli --version
```

### View Help

```bash
coding-agent-cli --help
coding-agent-cli scan --help
```

### Report Issues

Report bugs at: https://github.com/coding-agent/cli/issues

Include:
- CLI version
- Operating system
- Scanner versions
- Error messages
- Steps to reproduce
