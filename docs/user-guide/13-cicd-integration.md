# CI/CD Integration

## Overview

Integrate Coding Agent CLI into your CI/CD pipelines to automatically scan code for security vulnerabilities on every commit or pull request.

## GitHub Actions

### Quick Start

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Security Scan
        uses: coding-agent/scan-action@v1
        with:
          path: ./src
          scanners: bandit,semgrep,gosec
          fail-on: critical,high
          upload-sarif: true
```

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Path to scan | `.` |
| `scanners` | Comma-separated scanner list | `bandit,semgrep` |
| `policies` | Path to policy files | - |
| `fail-on` | Severity levels to fail on | `critical` |
| `upload-sarif` | Upload SARIF to GitHub Security | `false` |
| `comment-pr` | Post results as PR comment | `false` |
| `llm-enabled` | Enable LLM remediation | `false` |

### Advanced Configuration

```yaml
name: Advanced Security Scan

on:
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Security Scan
        uses: coding-agent/scan-action@v1
        with:
          path: ./src
          scanners: bandit,semgrep,gosec,eslint
          policies: ./policies
          fail-on: critical,high
          upload-sarif: true
          comment-pr: true
          llm-enabled: true
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
      
      - name: Upload Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-scan-results
          path: scan-results.json
```

### SARIF Upload

Upload results to GitHub Security tab:

```yaml
- name: Run Security Scan
  uses: coding-agent/scan-action@v1
  with:
    upload-sarif: true

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### PR Comments

Post scan results as PR comments:

```yaml
- name: Run Security Scan
  uses: coding-agent/scan-action@v1
  with:
    comment-pr: true
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Matrix Builds

Scan multiple languages in parallel:

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        language: [python, javascript, go]
        include:
          - language: python
            scanners: bandit,semgrep
            path: ./backend
          - language: javascript
            scanners: eslint,semgrep
            path: ./frontend
          - language: go
            scanners: gosec,semgrep
            path: ./services
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Scan ${{ matrix.language }}
        uses: coding-agent/scan-action@v1
        with:
          path: ${{ matrix.path }}
          scanners: ${{ matrix.scanners }}
```

### Caching

Speed up scans with caching:

```yaml
- name: Cache Scanner Binaries
  uses: actions/cache@v4
  with:
    path: |
      ~/.cache/coding-agent-cli
      ~/.local/bin
    key: scanners-${{ runner.os }}-${{ hashFiles('**/requirements.txt') }}

- name: Run Security Scan
  uses: coding-agent/scan-action@v1
```

## GitLab CI

### Quick Start

Create `.gitlab-ci.yml`:

```yaml
include:
  - remote: 'https://raw.githubusercontent.com/coding-agent/cli/main/.gitlab-ci-template.yml'

security_scan:
  extends: .security_scan_template
  variables:
    SCAN_PATH: ./src
    SCANNERS: bandit,semgrep,gosec
```

### Full Configuration

```yaml
stages:
  - security

security_scan:
  stage: security
  image: coding-agent/cli:latest
  script:
    - coding-agent-cli scan $SCAN_PATH --scanners $SCANNERS --policies ./policies
  artifacts:
    reports:
      sast: gl-sast-report.json
    paths:
      - scan-results.json
    expire_in: 30 days
  variables:
    SCAN_PATH: ./src
    SCANNERS: bandit,semgrep,gosec,eslint
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

### GitLab Security Dashboard

Generate GitLab-compatible SAST report:

```yaml
security_scan:
  script:
    - coding-agent-cli scan ./src --format gitlab-sast --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Merge Request Integration

Post results to merge requests:

```yaml
security_scan:
  script:
    - coding-agent-cli scan ./src
    - coding-agent-cli gitlab post-mr-note --mr-iid $CI_MERGE_REQUEST_IID
  only:
    - merge_requests
```

### Pipeline Failure

Fail pipeline on critical findings:

```yaml
security_scan:
  script:
    - coding-agent-cli scan ./src --fail-on critical,high
  allow_failure: false
```

## Jenkins

### Jenkinsfile

```groovy
pipeline {
    agent any
    
    stages {
        stage('Security Scan') {
            steps {
                sh '''
                    coding-agent-cli scan ./src \
                        --scanners bandit,semgrep,gosec \
                        --policies ./policies \
                        --output scan-results.json
                '''
            }
        }
        
        stage('Check Results') {
            steps {
                script {
                    def results = readJSON file: 'scan-results.json'
                    if (results.summary.critical > 0) {
                        error("Critical vulnerabilities found!")
                    }
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'scan-results.json', fingerprint: true
            publishHTML([
                reportDir: '.',
                reportFiles: 'report.html',
                reportName: 'Security Scan Report'
            ])
        }
    }
}
```

## CircleCI

### config.yml

```yaml
version: 2.1

jobs:
  security-scan:
    docker:
      - image: coding-agent/cli:latest
    steps:
      - checkout
      - run:
          name: Run Security Scan
          command: |
            coding-agent-cli scan ./src \
              --scanners bandit,semgrep,gosec \
              --policies ./policies
      - store_artifacts:
          path: scan-results.json
      - store_test_results:
          path: scan-results.json

workflows:
  version: 2
  security:
    jobs:
      - security-scan
```

## Azure Pipelines

### azure-pipelines.yml

```yaml
trigger:
  - main
  - develop

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: Docker@2
  inputs:
    command: 'run'
    arguments: >
      -v $(Build.SourcesDirectory):/code
      coding-agent/cli:latest
      scan /code --scanners bandit,semgrep,gosec

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: 'scan-results.json'
    artifactName: 'security-scan'
```

## Docker

### Using Docker Image

```bash
docker run -v $(pwd):/code coding-agent/cli:latest scan /code
```

### Custom Dockerfile

```dockerfile
FROM coding-agent/cli:latest

# Copy policies
COPY policies /policies

# Set default command
CMD ["scan", "/code", "--policies", "/policies"]
```

Build and run:
```bash
docker build -t my-security-scanner .
docker run -v $(pwd):/code my-security-scanner
```

## Best Practices

### 1. Fail Fast

Fail builds on critical/high severity findings:

```yaml
- coding-agent-cli scan ./src --fail-on critical,high
```

### 2. Use Policies

Define project-specific security policies:

```yaml
- coding-agent-cli scan ./src --policies ./policies
```

### 3. Cache Results

Cache scanner binaries and results for faster builds:

```yaml
# GitHub Actions
- uses: actions/cache@v4
  with:
    path: ~/.cache/coding-agent-cli
    key: scanners-${{ runner.os }}
```

### 4. Incremental Scanning

Scan only changed files in PRs:

```bash
# Get changed files
git diff --name-only origin/main...HEAD > changed-files.txt

# Scan only changed files
coding-agent-cli scan --files-from changed-files.txt
```

### 5. Separate Jobs

Run different scanners in parallel:

```yaml
jobs:
  scan-python:
    steps:
      - run: coding-agent-cli scan ./backend --scanners bandit
  
  scan-javascript:
    steps:
      - run: coding-agent-cli scan ./frontend --scanners eslint
```

### 6. Store Artifacts

Always store scan results:

```yaml
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: security-scan-results
    path: scan-results.json
```

### 7. Notifications

Send notifications on failures:

```yaml
- name: Notify on Failure
  if: failure()
  run: |
    curl -X POST $WEBHOOK_URL \
      -H 'Content-Type: application/json' \
      -d '{"text":"Security scan failed!"}'
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `OPENAI_API_KEY` | OpenAI API key for LLM |
| `ANTHROPIC_API_KEY` | Anthropic API key for LLM |
| `CODING_AGENT_CONFIG` | Path to config file |
| `CODING_AGENT_DB` | Path to database file |
| `CODING_AGENT_CACHE` | Path to cache directory |

## Troubleshooting

### Scanner Not Found

Install scanners in CI environment:

```yaml
- name: Install Scanners
  run: |
    pip install bandit semgrep
    go install github.com/securego/gosec/v2/cmd/gosec@latest
```

### Permission Denied

Ensure proper permissions:

```yaml
permissions:
  contents: read
  security-events: write
  pull-requests: write
```

### Timeout Issues

Increase timeout for large codebases:

```yaml
- name: Run Security Scan
  timeout-minutes: 30
  run: coding-agent-cli scan ./src
```

## Next Steps

- Set up [Webhooks](14-webhooks.md) for notifications
- Configure [Policies](06-policies.md) for your project
- Learn about [Performance Optimization](15-performance.md)
