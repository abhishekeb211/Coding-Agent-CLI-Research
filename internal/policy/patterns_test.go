package policy

import (
	"testing"
)

func TestValidatePattern(t *testing.T) {
	pm := NewPatternMatcher()

	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{
			name:    "valid simple pattern",
			pattern: "*.go",
			wantErr: false,
		},
		{
			name:    "valid doublestar pattern",
			pattern: "**/*.go",
			wantErr: false,
		},
		{
			name:    "valid directory pattern",
			pattern: "src/**",
			wantErr: false,
		},
		{
			name:    "valid exact match",
			pattern: "main.go",
			wantErr: false,
		},
		{
			name:    "empty pattern",
			pattern: "",
			wantErr: true,
		},
		{
			name:    "invalid triple star",
			pattern: "***/*.go",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pm.ValidatePattern(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePattern() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCompilePattern(t *testing.T) {
	pm := NewPatternMatcher()

	tests := []struct {
		name        string
		pattern     string
		wantType    PatternType
		wantErr     bool
		wantCompiled bool
	}{
		{
			name:        "glob pattern with star",
			pattern:     "*.go",
			wantType:    PatternTypeGlob,
			wantErr:     false,
			wantCompiled: true,
		},
		{
			name:        "glob pattern with doublestar",
			pattern:     "**/*.go",
			wantType:    PatternTypeGlob,
			wantErr:     false,
			wantCompiled: true,
		},
		{
			name:        "exact match",
			pattern:     "main.go",
			wantType:    PatternTypeGlob,
			wantErr:     false,
			wantCompiled: true,
		},
		{
			name:        "empty pattern",
			pattern:     "",
			wantType:    PatternTypeGlob,
			wantErr:     true,
			wantCompiled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pm.CompilePattern(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("CompilePattern() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err == nil {
				if got.Type != tt.wantType {
					t.Errorf("CompilePattern() type = %v, want %v", got.Type, tt.wantType)
				}
				if got.Compiled != tt.wantCompiled {
					t.Errorf("CompilePattern() compiled = %v, want %v", got.Compiled, tt.wantCompiled)
				}
				if got.Raw != tt.pattern {
					t.Errorf("CompilePattern() raw = %v, want %v", got.Raw, tt.pattern)
				}
			}
		})
	}
}

func TestMatch(t *testing.T) {
	pm := NewPatternMatcher()

	tests := []struct {
		name      string
		pattern   string
		path      string
		wantMatch bool
		wantErr   bool
	}{
		// Simple wildcard patterns
		{
			name:      "simple wildcard - match",
			pattern:   "*.go",
			path:      "main.go",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "simple wildcard - no match",
			pattern:   "*.go",
			path:      "main.py",
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "simple wildcard with prefix - match",
			pattern:   "test_*.go",
			path:      "test_main.go",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "simple wildcard with prefix - no match",
			pattern:   "test_*.go",
			path:      "main_test.go",
			wantMatch: false,
			wantErr:   false,
		},
		// Doublestar patterns
		{
			name:      "doublestar any file - match",
			pattern:   "**/*.go",
			path:      "src/main.go",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "doublestar any file - match nested",
			pattern:   "**/*.go",
			path:      "src/pkg/util/helper.go",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "doublestar any file - no match",
			pattern:   "**/*.go",
			path:      "src/main.py",
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "doublestar with prefix - match",
			pattern:   "src/**/*.go",
			path:      "src/pkg/main.go",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "doublestar with prefix - no match wrong dir",
			pattern:   "src/**/*.go",
			path:      "test/main.go",
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "doublestar all files in dir",
			pattern:   "src/**",
			path:      "src/main.go",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "doublestar all files in dir nested",
			pattern:   "src/**",
			path:      "src/pkg/util/helper.go",
			wantMatch: true,
			wantErr:   false,
		},
		// Test file patterns
		{
			name:      "test file pattern - match",
			pattern:   "**/*_test.go",
			path:      "pkg/util/helper_test.go",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "test file pattern - no match",
			pattern:   "**/*_test.go",
			path:      "pkg/util/helper.go",
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "test directory pattern - match",
			pattern:   "**/test_*.py",
			path:      "src/test_main.py",
			wantMatch: true,
			wantErr:   false,
		},
		// Exact match
		{
			name:      "exact match - match",
			pattern:   "main.go",
			path:      "main.go",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "exact match - no match",
			pattern:   "main.go",
			path:      "test.go",
			wantMatch: false,
			wantErr:   false,
		},
		// Directory patterns
		{
			name:      "directory pattern - match",
			pattern:   "vendor/**",
			path:      "vendor/pkg/lib.go",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "directory pattern - no match",
			pattern:   "vendor/**",
			path:      "src/main.go",
			wantMatch: false,
			wantErr:   false,
		},
		// Windows-style paths (should be normalized)
		{
			name:      "windows path - match",
			pattern:   "**/*.go",
			path:      "src\\pkg\\main.go",
			wantMatch: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, err := pm.CompilePattern(tt.pattern)
			if err != nil {
				t.Fatalf("CompilePattern() error = %v", err)
			}

			got, err := pm.Match(pattern, tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("Match() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v (pattern: %s, path: %s)", got, tt.wantMatch, tt.pattern, tt.path)
			}
		})
	}
}

func TestMatchDirectory(t *testing.T) {
	pm := NewPatternMatcher()

	tests := []struct {
		name      string
		pattern   string
		dirPath   string
		wantMatch bool
		wantErr   bool
	}{
		{
			name:      "directory with doublestar - match",
			pattern:   "src/**",
			dirPath:   "src",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "directory with doublestar - match nested",
			pattern:   "src/**",
			dirPath:   "src/pkg",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "directory with doublestar - no match",
			pattern:   "src/**",
			dirPath:   "test",
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "exact directory match",
			pattern:   "vendor",
			dirPath:   "vendor",
			wantMatch: false, // Exact match without wildcard won't match directory
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pattern, err := pm.CompilePattern(tt.pattern)
			if err != nil {
				t.Fatalf("CompilePattern() error = %v", err)
			}

			got, err := pm.MatchDirectory(pattern, tt.dirPath)
			if (err != nil) != tt.wantErr {
				t.Errorf("MatchDirectory() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantMatch {
				t.Errorf("MatchDirectory() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestMatchAny(t *testing.T) {
	pm := NewPatternMatcher()

	tests := []struct {
		name      string
		patterns  []string
		path      string
		wantMatch bool
		wantErr   bool
	}{
		{
			name:      "match first pattern",
			patterns:  []string{"*.go", "*.py"},
			path:      "main.go",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "match second pattern",
			patterns:  []string{"*.go", "*.py"},
			path:      "main.py",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "no match any pattern",
			patterns:  []string{"*.go", "*.py"},
			path:      "main.js",
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "empty patterns",
			patterns:  []string{},
			path:      "main.go",
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "complex patterns - match",
			patterns:  []string{"**/*_test.go", "**/test_*.py"},
			path:      "src/helper_test.go",
			wantMatch: true,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var compiledPatterns []*Pattern
			for _, p := range tt.patterns {
				pattern, err := pm.CompilePattern(p)
				if err != nil {
					t.Fatalf("CompilePattern() error = %v", err)
				}
				compiledPatterns = append(compiledPatterns, pattern)
			}

			got, err := pm.MatchAny(compiledPatterns, tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("MatchAny() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantMatch {
				t.Errorf("MatchAny() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestMatchAll(t *testing.T) {
	pm := NewPatternMatcher()

	tests := []struct {
		name      string
		patterns  []string
		path      string
		wantMatch bool
		wantErr   bool
	}{
		{
			name:      "match all patterns",
			patterns:  []string{"*.go", "**/*_test.go"},
			path:      "helper_test.go",
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "match only first pattern",
			patterns:  []string{"*.go", "**/*_test.go"},
			path:      "main.go",
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "match no patterns",
			patterns:  []string{"*.go", "*.py"},
			path:      "main.js",
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "empty patterns",
			patterns:  []string{},
			path:      "main.go",
			wantMatch: false,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var compiledPatterns []*Pattern
			for _, p := range tt.patterns {
				pattern, err := pm.CompilePattern(p)
				if err != nil {
					t.Fatalf("CompilePattern() error = %v", err)
				}
				compiledPatterns = append(compiledPatterns, pattern)
			}

			got, err := pm.MatchAll(compiledPatterns, tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("MatchAll() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.wantMatch {
				t.Errorf("MatchAll() = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestMatchWithNilPattern(t *testing.T) {
	pm := NewPatternMatcher()

	_, err := pm.Match(nil, "test.go")
	if err == nil {
		t.Error("Match() with nil pattern should return error")
	}
}

func TestMatchWithUncompiledPattern(t *testing.T) {
	pm := NewPatternMatcher()

	pattern := &Pattern{
		Raw:      "*.go",
		Compiled: false,
	}

	_, err := pm.Match(pattern, "test.go")
	if err == nil {
		t.Error("Match() with uncompiled pattern should return error")
	}
}
