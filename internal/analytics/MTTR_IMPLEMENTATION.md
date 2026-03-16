# MTTR (Mean Time To Remediation) Implementation

## Overview

This document describes the implementation of MTTR calculation for the Coding Agent CLI v1.2 release.

## What is MTTR?

MTTR (Mean Time To Remediation) is a key security metric that measures how long it takes to fix security findings after they are discovered. It helps security teams:

- Track remediation effectiveness
- Identify bottlenecks in the fix process
- Prioritize resources based on severity
- Measure improvement over time

## Implementation Details

### Data Model

The implementation uses the existing `findings_normalized` table to track finding lifecycles:

```sql
SELECT 
    code_fingerprint,
    MIN(created_at) as first_seen,
    MAX(created_at) as last_seen,
    severity,
    cwe_id
FROM findings_normalized
GROUP BY code_fingerprint, severity, cwe_id
```

### Key Concepts

1. **Finding Lifecycle**: Tracked using `code_fingerprint` to identify unique findings across scans
2. **First Seen**: The earliest timestamp when a finding was detected
3. **Last Seen**: The most recent timestamp when a finding was detected
4. **Resolved**: A finding is considered resolved if it doesn't appear in scans after `last_seen`
5. **Time To Remediation (TTR)**: The duration between `first_seen` and `last_seen` for resolved findings

### Metrics Calculated

The `MTTRMetrics` struct provides comprehensive statistics:

```go
type MTTRMetrics struct {
    MeanTTR       time.Duration            // Average time to remediation
    MedianTTR     time.Duration            // 50th percentile (p50)
    P75TTR        time.Duration            // 75th percentile
    P90TTR        time.Duration            // 90th percentile
    P95TTR        time.Duration            // 95th percentile
    MinTTR        time.Duration            // Fastest remediation
    MaxTTR        time.Duration            // Slowest remediation
    TotalResolved int                      // Number of resolved findings
    BySeverity    map[string]*MTTRMetrics  // Breakdown by severity level
}
```

### API Methods

#### 1. `GetMTTR() (*MTTRMetrics, error)`

Calculates MTTR for all resolved findings across all time periods and severities.

**Example Usage:**
```go
engine := analytics.NewEngine(db)
metrics, err := engine.GetMTTR()
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Mean TTR: %v\n", metrics.MeanTTR)
fmt.Printf("Median TTR: %v\n", metrics.MedianTTR)
fmt.Printf("Total Resolved: %d\n", metrics.TotalResolved)

// By severity breakdown
for severity, sevMetrics := range metrics.BySeverity {
    fmt.Printf("%s: Mean TTR = %v, Count = %d\n", 
        severity, sevMetrics.MeanTTR, sevMetrics.TotalResolved)
}
```

#### 2. `GetMTTRWithFilter(start, end time.Time, severity string) (*MTTRMetrics, error)`

Calculates MTTR with optional filtering:
- **Date Range**: Filter findings by creation date
- **Severity**: Filter by specific severity level (critical, high, medium, low)

**Example Usage:**
```go
// Get MTTR for critical findings only
metrics, err := engine.GetMTTRWithFilter(time.Time{}, time.Time{}, "critical")

// Get MTTR for findings in January 2024
start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
end := time.Date(2024, 1, 31, 23, 59, 59, 0, time.UTC)
metrics, err := engine.GetMTTRWithFilter(start, end, "")

// Get MTTR for high severity findings in Q1 2024
start := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
end := time.Date(2024, 3, 31, 23, 59, 59, 0, time.UTC)
metrics, err := engine.GetMTTRWithFilter(start, end, "high")
```

### Percentile Calculation

The implementation uses linear interpolation for accurate percentile calculations:

```go
func (e *Engine) calculatePercentile(sortedDurations []time.Duration, percentile int) time.Duration
```

This provides more accurate results than simple index-based percentiles, especially for small datasets.

### Caching

MTTR calculations are cached to improve performance:
- Cache key format: `mttr:{start_date}:{end_date}:{severity}`
- Default TTL: 5 minutes
- Cache is invalidated when new findings are added

### Fallback Strategy

As specified in the requirements, the implementation includes fallbacks:

1. **Primary**: Full percentile calculations (p50, p75, p90, p95)
2. **Fallback**: Simple average (MeanTTR) if percentile calculation fails
3. **Edge Case**: Returns zero metrics if no resolved findings exist

### Resolution Detection

A finding is considered "resolved" if:
1. It has a `last_seen` timestamp
2. It does NOT appear in any scans after `last_seen`

This is checked using:
```go
func (e *Engine) isFindingResolved(fingerprint string, lastSeen time.Time) bool
```

## Testing

Comprehensive tests cover:

1. **Basic MTTR calculation** - Multiple findings with different lifecycles
2. **No resolved findings** - All findings still active
3. **Severity filtering** - Filter by specific severity level
4. **Date range filtering** - Filter by time period
5. **Percentile calculation** - Verify p50, p75, p90, p95 accuracy
6. **Edge cases** - Empty datasets, single values
7. **Caching** - Verify cache hit/miss behavior
8. **By-severity breakdown** - Verify severity-specific metrics

## Performance Considerations

1. **Database Queries**: Uses GROUP BY on `code_fingerprint` to minimize rows scanned
2. **Indexes**: Leverages existing indexes on `code_fingerprint` and `created_at`
3. **Caching**: Results are cached for 5 minutes to reduce database load
4. **Sorting**: In-memory sorting of durations for percentile calculation

## Future Enhancements

Potential improvements for future versions:

1. **Streaming Percentiles**: Use approximate algorithms (P² algorithm) for large datasets
2. **Time-based Bucketing**: Pre-calculate MTTR by day/week/month
3. **CWE-specific MTTR**: Track MTTR by vulnerability type
4. **Team-based MTTR**: Track MTTR by team or repository
5. **SLA Tracking**: Compare MTTR against defined SLAs

## Requirements Satisfied

This implementation satisfies requirement 5.2 from the v1.2 release spec:

- ✅ Track finding lifecycle using code_fingerprint
- ✅ Calculate mean time to remediation
- ✅ Add percentile calculations (p50, p75, p90, p95)
- ✅ Fallback to simple average (MeanTTR)
- ✅ Filter by severity level
- ✅ Filter by date range
- ✅ Provide by-severity breakdown

## API Integration

The MTTR metrics can be exposed via REST API:

```go
// GET /api/v1/analytics/mttr
func (s *Server) handleGetMTTR(w http.ResponseWriter, r *http.Request) {
    // Parse query parameters
    severity := r.URL.Query().Get("severity")
    startStr := r.URL.Query().Get("start")
    endStr := r.URL.Query().Get("end")
    
    // Parse dates
    var start, end time.Time
    if startStr != "" {
        start, _ = time.Parse("2006-01-02", startStr)
    }
    if endStr != "" {
        end, _ = time.Parse("2006-01-02", endStr)
    }
    
    // Get MTTR metrics
    metrics, err := s.analytics.GetMTTRWithFilter(start, end, severity)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    
    json.NewEncoder(w).Encode(metrics)
}
```

## Example Output

```json
{
  "mean_ttr": "172800000000000",
  "median_ttr": "86400000000000",
  "p75_ttr": "259200000000000",
  "p90_ttr": "345600000000000",
  "p95_ttr": "432000000000000",
  "min_ttr": "3600000000000",
  "max_ttr": "604800000000000",
  "total_resolved": 42,
  "by_severity": {
    "critical": {
      "mean_ttr": "43200000000000",
      "median_ttr": "36000000000000",
      "total_resolved": 5
    },
    "high": {
      "mean_ttr": "86400000000000",
      "median_ttr": "72000000000000",
      "total_resolved": 15
    },
    "medium": {
      "mean_ttr": "259200000000000",
      "median_ttr": "216000000000000",
      "total_resolved": 18
    },
    "low": {
      "mean_ttr": "604800000000000",
      "median_ttr": "518400000000000",
      "total_resolved": 4
    }
  }
}
```

Note: Duration values are in nanoseconds (Go's time.Duration format). Convert to human-readable format in the API layer.
