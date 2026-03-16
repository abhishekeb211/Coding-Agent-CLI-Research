# Contributing to Coding Agent CLI

Thank you for your interest in contributing to Coding Agent CLI! This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful, inclusive, and professional in all interactions.

## Getting Started

### Prerequisites
- Go 1.21 or higher
- Git
- Python 3.8+ (for Bandit)
- Semgrep CLI

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/coding-agent/cli.git
cd cli

# Install dependencies
go mod download

# Install scanners
pip install bandit semgrep

# Build the project
go build -o coding-agent-cli

# Run tests
go test ./...
```

## Development Workflow

### 1. Create a Branch
```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 2. Make Changes
- Write clean, idiomatic Go code
- Follow existing code style
- Add tests for new functionality
- Update documentation as needed

### 3. Test Your Changes
```bash
# Run all tests
go test ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Run integration tests
go test -v -tags=integration ./tests/integration/...

# Phase-based test run (build check + all phases + integration)
# From repo root: Linux/macOS: ./scripts/test-phases.sh
#                 Windows:      scripts\test-phases.bat

# Check for race conditions
go test -race ./...

# Run linter
go vet ./...
```

### 4. Commit Your Changes
```bash
git add .
git commit -m "feat: add new feature"
# or
git commit -m "fix: resolve bug in scanner"
```

Use conventional commit messages:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions or changes
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

### 5. Push and Create Pull Request
```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub.

## Coding Standards

### Go Style
- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Use `gofmt` for formatting
- Use meaningful variable and function names
- Add comments for exported functions and types
- Keep functions small and focused

### Testing
- Write unit tests for all new code
- Aim for >70% code coverage
- Use table-driven tests where appropriate
- Test edge cases and error conditions
- Use descriptive test names

### Documentation
- Add godoc comments for all exported items
- Update README.md for user-facing changes
- Update relevant documentation in docs/
- Include examples in documentation

## Project Structure

```
coding-agent-cli/
├── cmd/                    # CLI commands
├── internal/              # Internal packages
│   ├── scanner/          # Scanner orchestration
│   ├── storage/          # Database layer
│   ├── llm/              # LLM integration
│   ├── policy/           # Policy engine
│   ├── sarif/            # SARIF output
│   └── cwe/              # CWE mapping
├── plugins/              # Scanner plugins
├── docs/                 # Documentation
├── examples/             # Example files
├── tests/                # Integration tests
└── testdata/             # Test fixtures
```

## Adding New Features

### Scanner Plugin
1. Create new package in `plugins/`
2. Implement `Scanner` interface
3. Add tests
4. Update documentation
5. Add example usage

### Policy Rule
1. Update policy schema in `internal/policy/types.go`
2. Implement matching logic
3. Add tests
4. Document in `docs/policy-guide/`
5. Add example policy

### Report Format
1. Add formatter in `internal/policy/formatters.go`
2. Implement generation logic
3. Add tests
4. Update documentation
5. Add example output

## Testing Guidelines

### Unit Tests
- Test individual functions and methods
- Mock external dependencies
- Use test fixtures from `testdata/`
- Verify error handling

### Integration Tests
- Test end-to-end workflows
- Use real scanners when possible
- Verify database persistence
- Test CLI commands

### Benchmarks
- Add benchmarks for performance-critical code
- Compare before and after changes
- Document performance improvements

## Documentation

### User Documentation
- Installation instructions
- Usage examples
- Configuration options
- Troubleshooting guides

### Developer Documentation
- Architecture overview
- API reference
- Plugin development guide
- Testing guide

### Policy Documentation
- Policy syntax
- Example policies
- Best practices
- Compliance frameworks

## Pull Request Process

1. **Create PR** with clear title and description
2. **Link Issues** if applicable
3. **Pass CI** - all tests must pass
4. **Code Review** - address reviewer feedback
5. **Update Docs** - if needed
6. **Squash Commits** - if requested
7. **Merge** - after approval

## Review Criteria

- Code quality and style
- Test coverage
- Documentation completeness
- Performance impact
- Breaking changes (avoid if possible)
- Security considerations

## Getting Help

- **Documentation**: Check docs/ folder
- **Issues**: Search existing issues
- **Discussions**: Use GitHub Discussions
- **Questions**: Open an issue with "question" label

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Recognition

Contributors will be recognized in:
- CHANGELOG.md
- Release notes
- GitHub contributors page

Thank you for contributing to Coding Agent CLI!
