package policy

import (
	"fmt"
	"path/filepath"
	"strings"
)

// PatternType represents the type of pattern matching to use
type PatternType int

const (
	// PatternTypeGlob uses glob patterns with * and ** wildcards
	PatternTypeGlob PatternType = iota
	// PatternTypePrefix uses simple prefix matching
	PatternTypePrefix
	// PatternTypeSuffix uses simple suffix matching
	PatternTypeSuffix
)

// Pattern represents a file path pattern for matching
type Pattern struct {
	// Raw is the original pattern string
	Raw string
	// Type is the pattern matching type
	Type PatternType
	// Compiled indicates if the pattern has been validated
	Compiled bool
}

// PatternMatcher provides file path pattern matching functionality
type PatternMatcher struct {
	// useDoublestar indicates if doublestar library is available
	useDoublestar bool
}

// NewPatternMatcher creates a new pattern matcher
func NewPatternMatcher() *PatternMatcher {
	return &PatternMatcher{
		useDoublestar: false, // Will be set to true when doublestar is available
	}
}

// ValidatePattern validates a pattern string
func (pm *PatternMatcher) ValidatePattern(pattern string) error {
	if pattern == "" {
		return fmt.Errorf("pattern cannot be empty")
	}

	// Check for invalid characters or sequences
	if strings.Contains(pattern, "***") {
		return fmt.Errorf("pattern contains invalid sequence '***'")
	}

	// Try to compile the pattern
	_, err := pm.CompilePattern(pattern)
	return err
}

// CompilePattern compiles a pattern string into a Pattern
func (pm *PatternMatcher) CompilePattern(pattern string) (*Pattern, error) {
	if pattern == "" {
		return nil, fmt.Errorf("pattern cannot be empty")
	}

	p := &Pattern{
		Raw:      pattern,
		Compiled: true,
	}

	// Determine pattern type
	if strings.Contains(pattern, "*") {
		p.Type = PatternTypeGlob
	} else if strings.HasPrefix(pattern, "*") {
		p.Type = PatternTypeSuffix
	} else if strings.HasSuffix(pattern, "*") {
		p.Type = PatternTypePrefix
	} else {
		// Exact match is treated as glob
		p.Type = PatternTypeGlob
	}

	return p, nil
}

// Match checks if a file path matches a pattern
func (pm *PatternMatcher) Match(pattern *Pattern, path string) (bool, error) {
	if pattern == nil {
		return false, fmt.Errorf("pattern is nil")
	}

	if !pattern.Compiled {
		return false, fmt.Errorf("pattern not compiled")
	}

	// Normalize path separators to forward slashes
	normalizedPath := filepath.ToSlash(path)

	switch pattern.Type {
	case PatternTypeGlob:
		return pm.matchGlob(pattern.Raw, normalizedPath)
	case PatternTypePrefix:
		prefix := strings.TrimSuffix(pattern.Raw, "*")
		return strings.HasPrefix(normalizedPath, prefix), nil
	case PatternTypeSuffix:
		suffix := strings.TrimPrefix(pattern.Raw, "*")
		return strings.HasSuffix(normalizedPath, suffix), nil
	default:
		return false, fmt.Errorf("unknown pattern type: %d", pattern.Type)
	}
}

// matchGlob performs glob pattern matching with fallback strategies
func (pm *PatternMatcher) matchGlob(pattern, path string) (bool, error) {
	// Primary: doublestar library (when available)
	if pm.useDoublestar {
		return pm.matchDoublestar(pattern, path)
	}

	// Fallback 1: filepath.Match for simple patterns (no **)
	if !strings.Contains(pattern, "**") {
		matched, err := filepath.Match(pattern, path)
		if err != nil {
			// Fallback 2: simple prefix/suffix matching
			return pm.matchSimple(pattern, path), nil
		}
		return matched, nil
	}

	// Fallback 2: manual ** handling with filepath.Match
	return pm.matchDoublestarFallback(pattern, path)
}

// matchDoublestar uses the doublestar library (placeholder for when library is added)
func (pm *PatternMatcher) matchDoublestar(pattern, path string) (bool, error) {
	// This will be implemented when doublestar library is added
	// For now, fall back to other methods
	return pm.matchDoublestarFallback(pattern, path)
}

// matchDoublestarFallback manually handles ** patterns
func (pm *PatternMatcher) matchDoublestarFallback(pattern, path string) (bool, error) {
	// Split pattern by **
	parts := strings.Split(pattern, "**")
	
	if len(parts) == 1 {
		// No ** in pattern, use filepath.Match
		matched, err := filepath.Match(pattern, path)
		if err != nil {
			return pm.matchSimple(pattern, path), nil
		}
		return matched, nil
	}

	// Handle ** patterns
	// For simplicity, we'll handle common cases:
	// - **/*.ext (any file with extension in any directory)
	// - dir/** (any file under directory)
	// - **/dir/* (any file in dir at any depth)

	if len(parts) == 2 {
		prefix := parts[0]
		suffix := parts[1]

		// Remove leading/trailing slashes
		prefix = strings.TrimSuffix(prefix, "/")
		suffix = strings.TrimPrefix(suffix, "/")

		// Check prefix match
		if prefix != "" {
			if !strings.HasPrefix(path, prefix) {
				return false, nil
			}
			// Remove prefix from path for suffix matching
			path = strings.TrimPrefix(path, prefix)
			path = strings.TrimPrefix(path, "/")
		}

		// Check suffix match
		if suffix != "" {
			// Use filepath.Match for the suffix part
			matched, err := filepath.Match(suffix, filepath.Base(path))
			if err != nil {
				// Fall back to simple suffix check
				return strings.HasSuffix(path, strings.TrimPrefix(suffix, "*")), nil
			}
			return matched, nil
		}

		// If suffix is empty, any file under prefix matches
		return true, nil
	}

	// For complex patterns with multiple **, fall back to simple matching
	return pm.matchSimple(pattern, path), nil
}

// matchSimple performs simple prefix/suffix matching as last resort
func (pm *PatternMatcher) matchSimple(pattern, path string) bool {
	// Remove wildcards for simple matching
	pattern = strings.ReplaceAll(pattern, "**", "")
	pattern = strings.ReplaceAll(pattern, "*", "")
	pattern = strings.Trim(pattern, "/")

	// Check if path contains the pattern
	return strings.Contains(path, pattern)
}

// MatchDirectory checks if a pattern matches a directory
func (pm *PatternMatcher) MatchDirectory(pattern *Pattern, dirPath string) (bool, error) {
	if pattern == nil {
		return false, fmt.Errorf("pattern is nil")
	}

	// Normalize directory path
	normalizedDir := filepath.ToSlash(dirPath)
	if !strings.HasSuffix(normalizedDir, "/") {
		normalizedDir += "/"
	}

	// Check if pattern matches the directory itself
	matched, err := pm.Match(pattern, normalizedDir)
	if err != nil {
		return false, err
	}
	if matched {
		return true, nil
	}

	// Check if pattern would match files in this directory
	// For patterns like "dir/**", we want to match the directory
	if strings.Contains(pattern.Raw, "**") {
		// Extract the directory part before **
		parts := strings.Split(pattern.Raw, "**")
		if len(parts) > 0 {
			dirPattern := strings.TrimSuffix(parts[0], "/")
			if dirPattern != "" {
				return strings.HasPrefix(normalizedDir, dirPattern), nil
			}
		}
	}

	return false, nil
}

// MatchAny checks if a path matches any of the given patterns
func (pm *PatternMatcher) MatchAny(patterns []*Pattern, path string) (bool, error) {
	for _, pattern := range patterns {
		matched, err := pm.Match(pattern, path)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}

// MatchAll checks if a path matches all of the given patterns
func (pm *PatternMatcher) MatchAll(patterns []*Pattern, path string) (bool, error) {
	if len(patterns) == 0 {
		return false, nil
	}

	for _, pattern := range patterns {
		matched, err := pm.Match(pattern, path)
		if err != nil {
			return false, err
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}
