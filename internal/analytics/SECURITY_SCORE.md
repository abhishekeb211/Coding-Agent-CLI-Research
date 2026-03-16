# Security Score Implementation

## Overview

The security score feature provides a quantitative measure of the overall security posture based on security findings. The score ranges from 0 to 100, where 100 represents a perfect security posture with no findings.

## Scoring Algorithm

The security score is calculated using a severity-based deduction system:

### Base Score
- Start with a perfect score of 100

### Deductions by Severity
- **Critical findings**: -10 points each
- **High findings**: -5 points each
- **Medium findings**: -2 points each
- **Low findings**: -0.5 points each

### Score Bounds
- Minimum score: 0 (score cannot go below zero)
- Maximum score: 100 (perfect security posture)

### Example Calculation
```
Findings:
- 2 Critical
- 3 High
- 5 Medium
- 10 Low

Score = 100 - (2×10) - (3×5) - (5×2) - (10×0.5)
      = 100 - 20 - 15 - 10 - 5
      = 50
```

## Grading System

Scores are converted to letter grades for easier interpretation:

| Score Range | Grade | Description |
|-------------|-------|-------------|
| 90-100      | A     | Excellent security posture |
| 80-89       | B     | Good security posture |
| 70-79       | C     | Acceptable security posture |
| 60-69       | D     | Poor security posture |
| 0-59        | F     | Critical security issues |

## Trend Analysis

The security score tracks changes over time to identify trends:

### Trend Directions
- **Improving**: Score increased by more than 2 points
- **Declining**: Score decreased by more than 2 points
- **Stable**: Score changed by 2 points or less

### Change Calculation
The change from the previous score is calculated as:
```
ChangeFromPrev = CurrentScore - PreviousScore
```

## API Usage

### Get Current Security Score

```go
engine := analytics.NewEngine(db)
score, err := engine.GetSecurityScore()
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Security Score: %.1f (%s)\n", score.Score, score.Grade)
fmt.Printf("Trend: %s (%.1f points)\n", score.TrendDirection, score.ChangeFromPrev)
```

### Get Score for Specific Scan

```go
score, err := engine.GetScoreForScan("scan-id-123")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Scan Score: %.1f (%s)\n", score.Score, score.Grade)
```

### Get Score History

```go
start := time.Now().AddDate(0, -1, 0) // Last month
end := time.Now()
history, err := engine.GetScoreHistory(start, end, 30)
if err != nil {
    log.Fatal(err)
}

for i, date := range history.Dates {
    fmt.Printf("%s: %.1f (%s)\n", date, history.Scores[i], history.Grades[i])
}
```

## Database Schema

### security_scores Table

```sql
CREATE TABLE security_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    score REAL NOT NULL,
    grade TEXT NOT NULL,
    total_findings INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX idx_security_scores_created_at ON security_scores(created_at);
CREATE INDEX idx_security_scores_score ON security_scores(score);
```

## Caching

Security scores are cached for 5 minutes to improve performance:

- **Current score**: `security_score:current`
- **Scan score**: `security_score:scan:{scanID}`
- **Score history**: `score_history:{start}:{end}:{limit}`

Cache is automatically invalidated when:
- New scores are recorded
- Findings are added or removed

## Design Decisions

### Why Severity-Based Scoring?

The severity-based scoring algorithm was chosen as the primary approach (with fallback support) because:

1. **Simplicity**: Easy to understand and explain to stakeholders
2. **Transparency**: Clear how each finding impacts the score
3. **Actionable**: Prioritizes fixing high-severity issues
4. **Stable**: Consistent scoring across different codebases

### Alternative Approaches Considered

1. **Weighted by CWE Risk**: More complex, requires CWE risk database
2. **CVSS-Based**: Requires CVSS scores for all findings
3. **Machine Learning**: Requires training data and ongoing maintenance

The simple severity-based approach was selected as the fallback option per the requirements, providing a reliable baseline that can be enhanced in future versions.

## Future Enhancements

Potential improvements for future versions:

1. **Configurable Weights**: Allow customization of severity weights
2. **CWE Risk Integration**: Factor in CWE risk ratings
3. **Trend Prediction**: Predict future scores based on historical data
4. **Benchmark Comparison**: Compare scores against industry benchmarks
5. **Custom Scoring Rules**: Allow organizations to define custom scoring logic

## Testing

The security score implementation includes comprehensive tests:

- **Unit Tests**: Test individual functions and edge cases
- **Integration Tests**: Test with real database
- **Cache Tests**: Verify caching behavior
- **Trend Tests**: Verify trend calculation
- **Edge Cases**: Perfect score, minimum score, boundary conditions

Run tests with:
```bash
go test -v ./internal/analytics -run TestGetSecurityScore
```

## References

- Requirements: 5.7 (Calculate security score based on findings)
- Task: 3.1.4 (Implement security score)
- Design: Fallback - Simple severity-based score
