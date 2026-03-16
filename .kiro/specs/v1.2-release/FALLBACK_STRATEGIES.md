# Fallback Strategies for v1.2 Features

## Overview

This document provides a quick reference for fallback options when primary implementations fail. Each feature has multiple implementation paths to ensure delivery even if challenges arise.

## Feature Fallback Matrix

### 1. Web Dashboard

| Priority | Option | Complexity | Time | Risk |
|----------|--------|------------|------|------|
| Primary | React SPA with Vite | High | 3 weeks | Medium |
| Fallback 1 | Server-side templates + htmx | Medium | 2 weeks | Low |
| Fallback 2 | Vanilla JS + Web Components | Low | 1 week | Very Low |
| Fallback 3 | Enhanced static HTML reports | Very Low | 3 days | None |

**Decision Criteria:**
- Use React if team has React experience
- Use htmx if server-side rendering preferred
- Use Vanilla JS if no framework dependencies desired
- Use Enhanced HTML as last resort

### 2. REST API

| Priority | Option | Complexity | Time | Risk |
|----------|--------|------------|------|------|
| Primary | net/http + chi router | Low | 1 week | Very Low |
| Fallback 1 | Gin web framework | Low | 1 week | Low |
| Fallback 2 | Echo framework | Low | 1 week | Low |
| Fallback 3 | Minimal HTTP with --json-api flag | Very Low | 2 days | None |

**Decision Criteria:**
- Use chi for standard library approach
- Use Gin for faster development with more features
- Use Echo for lightweight with good middleware
- Use minimal HTTP for basic needs only

### 3. LLM Provider Integration

| Priority | Option | Complexity | Time | Risk |
|----------|--------|------------|------|------|
| Primary | Official SDKs (OpenAI, Anthropic) | Medium | 2 weeks | Medium |
| Fallback 1 | HTTP client with custom implementation | Medium | 2 weeks | Low |
| Fallback 2 | Proxy service for unified interface | High | 3 weeks | Medium |
| Fallback 3 | Continue with mock provider | Very Low | 0 days | None |

**Decision Criteria:**
- Use official SDKs if available and stable
- Use HTTP client if SDKs have issues
- Use proxy service for complex multi-provider scenarios
- Use mock provider if real providers unavailable

**Fallback Chain for Runtime:**
```
OpenAI → Anthropic → Ollama → Cache → Mock → Error
```

### 4. Scanner Plugins

| Priority | Option | Complexity | Time | Risk |
|----------|--------|------------|------|------|
| Primary | Native Go integration | Low | 1 week per scanner | Low |
| Fallback 1 | External process with JSON parsing | Low | 1 week per scanner | Very Low |
| Fallback 2 | Docker container-based | Medium | 2 weeks per scanner | Medium |
| Fallback 3 | Manual result import | Very Low | 2 days | None |

**Decision Criteria:**
- Use native integration for best performance
- Use external process if native integration difficult
- Use Docker for complex scanner dependencies
- Use manual import as last resort

### 5. Analytics Engine

| Priority | Option | Complexity | Time | Risk |
|----------|--------|------------|------|------|
| Primary | SQL queries with aggregation | Low | 1 week | Very Low |
| Fallback 1 | Time-series database (InfluxDB) | High | 3 weeks | High |
| Fallback 2 | In-memory analytics with snapshots | Medium | 2 weeks | Medium |
| Fallback 3 | CSV export for external tools | Very Low | 2 days | None |

**Decision Criteria:**
- Use SQL queries for simplicity
- Use time-series DB for advanced analytics
- Use in-memory for performance-critical scenarios
- Use CSV export for minimal implementation

### 6. Template Engine

| Priority | Option | Complexity | Time | Risk |
|----------|--------|------------|------|------|
| Primary | Go html/template | Very Low | 3 days | None |
| Fallback 1 | Handlebars via third-party library | Low | 1 week | Low |
| Fallback 2 | Markdown with front-matter | Very Low | 2 days | None |
| Fallback 3 | CSS customization of existing reports | Very Low | 1 day | None |

**Decision Criteria:**
- Use Go templates for standard approach
- Use Handlebars for familiar syntax
- Use Markdown for simple templates
- Use CSS for minimal customization

### 7. Pattern Matching

| Priority | Option | Complexity | Time | Risk |
|----------|--------|------------|------|------|
| Primary | doublestar library for ** support | Low | 3 days | Very Low |
| Fallback 1 | regexp package for full regex | Low | 3 days | Low |
| Fallback 2 | go-gitignore for gitignore-style | Low | 3 days | Low |
| Fallback 3 | Simple prefix/suffix matching | Very Low | 1 day | None |

**Decision Criteria:**
- Use doublestar for glob patterns
- Use regexp for complex patterns
- Use go-gitignore for familiar syntax
- Use simple matching for basic needs

### 8. GitHub Actions Integration

| Priority | Option | Complexity | Time | Risk |
|----------|--------|------------|------|------|
| Primary | Docker-based action | Medium | 1 week | Low |
| Fallback 1 | JavaScript action with binary download | Medium | 1 week | Medium |
| Fallback 2 | Composite action with shell scripts | Low | 3 days | Low |
| Fallback 3 | Documentation for manual setup | Very Low | 1 day | None |

**Decision Criteria:**
- Use Docker for consistency
- Use JavaScript for faster startup
- Use composite for simplicity
- Use documentation for minimal effort

### 9. GitLab CI Integration

| Priority | Option | Complexity | Time | Risk |
|----------|--------|------------|------|------|
| Primary | Docker image with GitLab format | Medium | 1 week | Low |
| Fallback 1 | Shell script with binary download | Low | 3 days | Low |
| Fallback 2 | GitLab CI component | Medium | 1 week | Medium |
| Fallback 3 | Documentation for manual setup | Very Low | 1 day | None |

**Decision Criteria:**
- Use Docker for consistency
- Use shell script for simplicity
- Use CI component for reusability
- Use documentation for minimal effort

### 10. Webhook System

| Priority | Option | Complexity | Time | Risk |
|----------|--------|------------|------|------|
| Primary | Built-in with retry queue | Medium | 1 week | Low |
| Fallback 1 | Integration with ntfy/Gotify | Low | 3 days | Low |
| Fallback 2 | Plugin system for custom notifiers | High | 2 weeks | Medium |
| Fallback 3 | Email notifications via SMTP | Low | 2 days | Very Low |

**Decision Criteria:**
- Use built-in for full control
- Use ntfy/Gotify for quick implementation
- Use plugin system for extensibility
- Use email for basic notifications

### 11. Database

| Priority | Option | Complexity | Time | Risk |
|----------|--------|------------|------|------|
| Primary | SQLite with migrations | Low | 1 week | Very Low |
| Fallback 1 | PostgreSQL support | Medium | 2 weeks | Medium |
| Fallback 2 | Hybrid (SQLite + PostgreSQL) | High | 3 weeks | High |
| Fallback 3 | SQLite only (no PostgreSQL) | Very Low | 0 days | None |

**Decision Criteria:**
- Use SQLite for simplicity
- Use PostgreSQL for enterprise deployments
- Use hybrid for flexibility
- Skip PostgreSQL if not needed

### 12. Authentication

| Priority | Option | Complexity | Time | Risk |
|----------|--------|------------|------|------|
| Primary | JWT with refresh tokens | Medium | 1 week | Medium |
| Fallback 1 | Session-based with cookies | Low | 3 days | Low |
| Fallback 2 | HTTP Basic Auth with bcrypt | Very Low | 2 days | Very Low |
| Fallback 3 | Skip authentication (optional feature) | None | 0 days | None |

**Decision Criteria:**
- Use JWT for stateless API
- Use sessions for traditional web app
- Use Basic Auth for simplicity
- Skip if not required

### 13. Performance Optimization

| Priority | Option | Complexity | Time | Risk |
|----------|--------|------------|------|------|
| Primary | Git-based incremental scanning | Medium | 1 week | Medium |
| Fallback 1 | File hash-based caching | Low | 3 days | Low |
| Fallback 2 | Timestamp-based caching | Very Low | 1 day | Very Low |
| Fallback 3 | Full scans (no optimization) | None | 0 days | None |

**Decision Criteria:**
- Use git-based for best results
- Use file hash for reliability
- Use timestamp for simplicity
- Accept full scans if optimization fails

## Decision Framework

### When to Use Fallback Options

1. **Technical Blockers**
   - Primary implementation has critical bugs
   - Dependencies are unavailable or incompatible
   - Performance is unacceptable
   - Security vulnerabilities discovered

2. **Resource Constraints**
   - Time running short
   - Team lacks expertise
   - Budget limitations
   - Infrastructure unavailable

3. **Risk Management**
   - Primary option too risky for deadline
   - Fallback provides faster delivery
   - Stakeholder preference
   - Regulatory requirements

### Evaluation Criteria

For each feature, evaluate:
1. **Complexity**: How difficult to implement?
2. **Time**: How long will it take?
3. **Risk**: What could go wrong?
4. **Value**: How much value does it provide?
5. **Dependencies**: What does it depend on?

### Decision Process

```
1. Attempt primary implementation
2. If blocked, evaluate cause
3. Check if issue is temporary or permanent
4. If temporary, wait/fix
5. If permanent, move to Fallback 1
6. Repeat process for each fallback
7. Document decision and rationale
```

## Fallback Documentation Template

When using a fallback option, document:

```markdown
## Feature: [Feature Name]

**Original Plan**: [Primary option]
**Fallback Used**: [Fallback option]
**Reason**: [Why fallback was needed]
**Impact**: [What changed]
**Future Plan**: [Will we revisit primary option?]
```

## Examples of Fallback Usage

### Example 1: Web Dashboard

**Scenario**: React SPA too complex for team

**Decision**:
- Attempted: React SPA
- Issue: Team lacks React experience, taking too long
- Fallback: Server-side templates with htmx
- Result: Delivered in 2 weeks instead of 4
- Trade-off: Less interactive, but functional

### Example 2: LLM Integration

**Scenario**: OpenAI API rate limits hit

**Decision**:
- Attempted: OpenAI as primary
- Issue: Rate limits exceeded
- Fallback: Anthropic as secondary
- Result: Seamless failover
- Trade-off: Higher cost, but reliable

### Example 3: Authentication

**Scenario**: JWT implementation complex

**Decision**:
- Attempted: JWT with refresh tokens
- Issue: Token rotation logic complex
- Fallback: Session-based authentication
- Result: Simpler, faster implementation
- Trade-off: Stateful, but adequate

## Monitoring Fallback Usage

Track which fallbacks are used:
- Document in tasks.md
- Update CHANGELOG.md
- Note in release notes
- Plan future improvements

## Conclusion

Fallback strategies ensure v1.2 delivers value even when challenges arise. By having multiple implementation paths, we reduce risk and maintain momentum toward release goals.

**Key Principles**:
1. Always have a fallback plan
2. Document fallback decisions
3. Evaluate trade-offs carefully
4. Deliver value incrementally
5. Plan to revisit if needed
