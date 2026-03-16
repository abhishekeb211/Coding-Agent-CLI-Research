#!/bin/bash

# Benchmark tracking script for Coding Agent CLI
# Runs benchmarks, stores results, and detects performance regressions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BENCH_DIR="$PROJECT_ROOT/.benchmarks"
RESULTS_FILE="$BENCH_DIR/results.txt"
HISTORY_FILE="$BENCH_DIR/history.json"
REGRESSION_THRESHOLD=20  # 20% performance degradation threshold

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Create benchmark directory if it doesn't exist
mkdir -p "$BENCH_DIR"

echo "========================================="
echo "  Coding Agent CLI - Benchmark Suite"
echo "========================================="
echo ""

# Function to run benchmarks
run_benchmarks() {
    echo "Running benchmarks..."
    echo ""
    
    cd "$PROJECT_ROOT"
    
    # Run benchmarks with memory profiling
    go test -bench=. -benchmem -benchtime=3s ./... > "$RESULTS_FILE" 2>&1
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Benchmarks completed successfully${NC}"
    else
        echo -e "${RED}✗ Benchmarks failed${NC}"
        cat "$RESULTS_FILE"
        exit 1
    fi
}

# Function to parse benchmark results
parse_results() {
    echo ""
    echo "Parsing benchmark results..."
    
    # Extract key metrics
    grep "Benchmark" "$RESULTS_FILE" | while read -r line; do
        benchmark_name=$(echo "$line" | awk '{print $1}')
        ns_per_op=$(echo "$line" | awk '{print $3}')
        bytes_per_op=$(echo "$line" | awk '{print $5}')
        allocs_per_op=$(echo "$line" | awk '{print $7}')
        
        echo "  $benchmark_name: $ns_per_op ns/op, $bytes_per_op B/op, $allocs_per_op allocs/op"
    done
}

# Function to store results in history
store_results() {
    echo ""
    echo "Storing results in history..."
    
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    commit_hash=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    
    # Create JSON entry
    result_entry=$(cat <<EOF
{
  "timestamp": "$timestamp",
  "commit": "$commit_hash",
  "results": $(grep "Benchmark" "$RESULTS_FILE" | awk '{print "{\"name\":\""$1"\",\"ns_per_op\":"$3",\"bytes_per_op\":"$5",\"allocs_per_op\":"$7"}"}' | jq -s '.')
}
EOF
)
    
    # Append to history file
    if [ -f "$HISTORY_FILE" ]; then
        # Read existing history and append new entry
        jq ". += [$result_entry]" "$HISTORY_FILE" > "$HISTORY_FILE.tmp"
        mv "$HISTORY_FILE.tmp" "$HISTORY_FILE"
    else
        # Create new history file
        echo "[$result_entry]" > "$HISTORY_FILE"
    fi
    
    echo -e "${GREEN}✓ Results stored${NC}"
}

# Function to detect regressions
detect_regressions() {
    echo ""
    echo "Checking for performance regressions..."
    
    if [ ! -f "$HISTORY_FILE" ]; then
        echo "No historical data available for comparison"
        return 0
    fi
    
    # Get previous results
    prev_results=$(jq '.[-2].results // []' "$HISTORY_FILE")
    curr_results=$(jq '.[-1].results // []' "$HISTORY_FILE")
    
    if [ "$prev_results" == "[]" ]; then
        echo "No previous results to compare against"
        return 0
    fi
    
    regressions_found=0
    
    # Compare each benchmark
    echo "$curr_results" | jq -c '.[]' | while read -r curr_bench; do
        bench_name=$(echo "$curr_bench" | jq -r '.name')
        curr_ns=$(echo "$curr_bench" | jq -r '.ns_per_op')
        
        # Find matching previous benchmark
        prev_ns=$(echo "$prev_results" | jq -r ".[] | select(.name == \"$bench_name\") | .ns_per_op")
        
        if [ -n "$prev_ns" ] && [ "$prev_ns" != "null" ]; then
            # Calculate percentage change
            change=$(awk "BEGIN {printf \"%.2f\", (($curr_ns - $prev_ns) / $prev_ns) * 100}")
            
            if (( $(echo "$change > $REGRESSION_THRESHOLD" | bc -l) )); then
                echo -e "${RED}⚠ REGRESSION: $bench_name degraded by ${change}%${NC}"
                regressions_found=1
            elif (( $(echo "$change < -10" | bc -l) )); then
                echo -e "${GREEN}✓ IMPROVEMENT: $bench_name improved by ${change#-}%${NC}"
            fi
        fi
    done
    
    if [ $regressions_found -eq 1 ]; then
        echo ""
        echo -e "${RED}Performance regressions detected!${NC}"
        return 1
    else
        echo -e "${GREEN}✓ No regressions detected${NC}"
        return 0
    fi
}

# Function to generate summary report
generate_summary() {
    echo ""
    echo "========================================="
    echo "  Benchmark Summary"
    echo "========================================="
    echo ""
    
    # Scanner benchmarks
    echo "Scanner Performance:"
    grep "BenchmarkScan" "$RESULTS_FILE" | head -5
    echo ""
    
    # Database benchmarks
    echo "Database Performance:"
    grep "BenchmarkDatabase" "$RESULTS_FILE" | head -5
    echo ""
    
    # LLM cache benchmarks
    echo "LLM Cache Performance:"
    grep "BenchmarkCache" "$RESULTS_FILE" | head -5
    echo ""
    
    # Report generation benchmarks
    echo "Report Generation Performance:"
    grep "BenchmarkReport" "$RESULTS_FILE" | head -5
    echo ""
}

# Function to verify performance targets
verify_targets() {
    echo ""
    echo "Verifying performance targets..."
    
    targets_met=0
    
    # Target: 10K LOC scan completes within 5 minutes (300 seconds = 300,000,000,000 ns)
    scan_10k=$(grep "BenchmarkScan10KLOC" "$RESULTS_FILE" | awk '{print $3}')
    if [ -n "$scan_10k" ]; then
        if (( $(echo "$scan_10k < 300000000000" | bc -l) )); then
            echo -e "${GREEN}✓ 10K LOC scan target met: ${scan_10k} ns${NC}"
        else
            echo -e "${RED}✗ 10K LOC scan target missed: ${scan_10k} ns (target: <300s)${NC}"
            targets_met=1
        fi
    fi
    
    # Target: Database queries complete within 100ms (100,000,000 ns)
    db_query=$(grep "BenchmarkFindingRetrievalByID" "$RESULTS_FILE" | awk '{print $3}')
    if [ -n "$db_query" ]; then
        if (( $(echo "$db_query < 100000000" | bc -l) )); then
            echo -e "${GREEN}✓ Database query target met: ${db_query} ns${NC}"
        else
            echo -e "${RED}✗ Database query target missed: ${db_query} ns (target: <100ms)${NC}"
            targets_met=1
        fi
    fi
    
    # Target: Report generation completes within 30 seconds (30,000,000,000 ns)
    report_gen=$(grep "BenchmarkReportWith1KFindings" "$RESULTS_FILE" | awk '{print $3}')
    if [ -n "$report_gen" ]; then
        if (( $(echo "$report_gen < 30000000000" | bc -l) )); then
            echo -e "${GREEN}✓ Report generation target met: ${report_gen} ns${NC}"
        else
            echo -e "${RED}✗ Report generation target missed: ${report_gen} ns (target: <30s)${NC}"
            targets_met=1
        fi
    fi
    
    return $targets_met
}

# Main execution
main() {
    run_benchmarks
    parse_results
    store_results
    generate_summary
    
    regression_status=0
    target_status=0
    
    detect_regressions || regression_status=$?
    verify_targets || target_status=$?
    
    echo ""
    echo "========================================="
    
    if [ $regression_status -eq 0 ] && [ $target_status -eq 0 ]; then
        echo -e "${GREEN}All benchmarks passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some benchmarks failed!${NC}"
        exit 1
    fi
}

# Run main function
main
