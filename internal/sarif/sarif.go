package sarif

import (
	"encoding/json"
	"time"

	"github.com/coding-agent/cli/internal/scanner"
)

// SARIF represents a SARIF 2.1.0 document
type SARIF struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

// Run represents a single run in SARIF
type Run struct {
	Tool           Tool           `json:"tool"`
	Results        []Result       `json:"results"`
	Artifacts      []Artifact     `json:"artifacts,omitempty"`
	Invocations    []Invocation   `json:"invocations,omitempty"`
	OriginalUriBaseIds map[string]URIBaseID `json:"originalUriBaseIds,omitempty"`
}

// Tool represents the analysis tool
type Tool struct {
	Driver Driver `json:"driver"`
}

// Driver represents the tool driver
type Driver struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	InformationUri  string `json:"informationUri,omitempty"`
	SemanticVersion string `json:"semanticVersion,omitempty"`
	Rules           []Rule `json:"rules,omitempty"`
}

// Rule represents a reporting descriptor
type Rule struct {
	ID               string           `json:"id"`
	Name             string           `json:"name,omitempty"`
	ShortDescription *Message         `json:"shortDescription,omitempty"`
	FullDescription  *Message         `json:"fullDescription,omitempty"`
	Help             *Message         `json:"help,omitempty"`
	Properties       *RuleProperties  `json:"properties,omitempty"`
}

// RuleProperties contains additional rule metadata
type RuleProperties struct {
	Tags     []string `json:"tags,omitempty"`
	Precision string  `json:"precision,omitempty"`
	Security  string  `json:"security-severity,omitempty"`
}

// Result represents a single finding
type Result struct {
	RuleID    string     `json:"ruleId"`
	RuleIndex int        `json:"ruleIndex,omitempty"`
	Level     string     `json:"level"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations"`
	Properties *ResultProperties `json:"properties,omitempty"`
}

// ResultProperties contains additional result metadata
type ResultProperties struct {
	Fingerprint string `json:"fingerprint,omitempty"`
	CWE         string `json:"cwe,omitempty"`
	Confidence  string `json:"confidence,omitempty"`
}

// Location represents a location in source code
type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

// PhysicalLocation represents a physical location
type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

// ArtifactLocation represents a file location
type ArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

// Region represents a region in a file
type Region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// Message represents a message
type Message struct {
	Text string `json:"text"`
}

// Artifact represents a file artifact
type Artifact struct {
	Location ArtifactLocation `json:"location"`
}

// Invocation represents a tool invocation
type Invocation struct {
	ExecutionSuccessful bool      `json:"executionSuccessful"`
	StartTimeUTC        string    `json:"startTimeUtc"`
	EndTimeUTC          string    `json:"endTimeUtc"`
	ExitCode            int       `json:"exitCode,omitempty"`
}

// URIBaseID represents a base URI
type URIBaseID struct {
	URI string `json:"uri"`
}

// ConvertToSARIF converts a ScanResult to SARIF format
func ConvertToSARIF(result *scanner.ScanResult) (*SARIF, error) {
	sarif := &SARIF{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs:    []Run{},
	}

	// Create a run for the scan
	run := Run{
		Tool: Tool{
			Driver: Driver{
				Name:            "Coding Agent CLI",
				Version:         "1.0.0",
				InformationUri:  "https://github.com/coding-agent/cli",
				SemanticVersion: "1.0.0",
				Rules:           []Rule{},
			},
		},
		Results: []Result{},
		Invocations: []Invocation{
			{
				ExecutionSuccessful: true,
				StartTimeUTC:        result.StartTime.UTC().Format(time.RFC3339),
				EndTimeUTC:          result.EndTime.UTC().Format(time.RFC3339),
				ExitCode:            0,
			},
		},
		OriginalUriBaseIds: map[string]URIBaseID{
			"ROOTPATH": {
				URI: result.TargetPath,
			},
		},
	}

	// Track unique rules
	ruleMap := make(map[string]int)
	ruleIndex := 0

	// Convert findings to SARIF results
	for _, finding := range result.Findings {
		// Add rule if not already present
		if _, exists := ruleMap[finding.CWEID]; !exists {
			rule := Rule{
				ID:   finding.CWEID,
				Name: finding.CWEDescription,
				ShortDescription: &Message{
					Text: finding.CWEDescription,
				},
				FullDescription: &Message{
					Text: finding.Description,
				},
				Properties: &RuleProperties{
					Tags:      []string{"security", finding.Severity},
					Precision: finding.Confidence,
					Security:  mapSeverityToScore(finding.Severity),
				},
			}
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
			ruleMap[finding.CWEID] = ruleIndex
			ruleIndex++
		}

		// Create SARIF result
		sarifResult := Result{
			RuleID:    finding.CWEID,
			RuleIndex: ruleMap[finding.CWEID],
			Level:     mapSeverityToLevel(finding.Severity),
			Message: Message{
				Text: finding.Description,
			},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI:       finding.FilePath,
							URIBaseID: "ROOTPATH",
						},
						Region: Region{
							StartLine: finding.LineNumber,
						},
					},
				},
			},
			Properties: &ResultProperties{
				Fingerprint: finding.CodeFingerprint,
				CWE:         finding.CWEID,
				Confidence:  finding.Confidence,
			},
		}

		run.Results = append(run.Results, sarifResult)
	}

	sarif.Runs = append(sarif.Runs, run)

	return sarif, nil
}

// ToJSON converts SARIF to JSON
func (s *SARIF) ToJSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// mapSeverityToLevel maps internal severity to SARIF level
func mapSeverityToLevel(severity string) string {
	switch severity {
	case "critical":
		return "error"
	case "high":
		return "error"
	case "medium":
		return "warning"
	case "low":
		return "note"
	default:
		return "warning"
	}
}

// mapSeverityToScore maps severity to security-severity score
func mapSeverityToScore(severity string) string {
	switch severity {
	case "critical":
		return "9.0"
	case "high":
		return "7.0"
	case "medium":
		return "5.0"
	case "low":
		return "3.0"
	default:
		return "5.0"
	}
}
