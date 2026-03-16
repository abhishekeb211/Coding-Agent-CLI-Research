# Contributing Guide

## Getting Started

### Prerequisites
- Go 1.21 or higher
- Git
- Python 3.8+ (for scanners)
- Bandit and Semgrep installed

### Fork and Clone

```bash
git clone https://github.com/your-username/coding-agent-cli.git
cd coding-agent-cli
```

### Build

```bash
go build -o coding-agent-cli .
```

### Run Tests

```bash
go test ./...
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/my-feature
```

### 2. Make Changes

- Write code
- Add tests
- Update documentation

### 3. Run Tests

```bash
go test ./...
go test -race ./...
go test -cover ./...
```

### 4. Format Code

```bash
go fmt ./...
go vet ./...
```

### 5. Commit Changes

```bash
git add .
git commit -m "Add feature: description"
```

### 6. Push and Create PR

```bash
git push origin feature/my-feature
```

Create a pull request on GitHub.

## Code Style

### Go Style Guide
Follow the [Effective Go](https://golang.org/doc/effective_go.html) guidelines.

### Naming Conventions
- Use camelCase for variables and functions
- Use PascalCase for exported types
- Use descriptive names

### Comments
- Add godoc comments for all exported functions
- Explain complex logic
- Document assumptions

## Testing Requirements

### Unit Tests
- Test all new functions
- Achieve >70% code coverage
- Use table-driven tests

### Integration Tests
- Test end-to-end workflows
- Use build tag `// +build integration`

### Test Naming
```go
func TestFunctionName(t *testing.T)
func TestFunctionName_EdgeCase(t *testing.T)
```

## Pull Request Guidelines

### PR Title
Use conventional commits format:
- `feat: Add new feature`
- `fix: Fix bug`
- `docs: Update documentation`
- `test: Add tests`
- `refactor: Refactor code`

### PR Description
Include:
- What changed
- Why it changed
- How to test
- Related issues

### Review Process
- All tests must pass
- Code coverage must not decrease
- At least one approval required
- No merge conflicts

## Reporting Issues

### Bug Reports
Include:
- CLI version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages

### Feature Requests
Include:
- Use case
- Proposed solution
- Alternatives considered

## Community

- GitHub Discussions: Ask questions
- GitHub Issues: Report bugs
- Pull Requests: Contribute code

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
