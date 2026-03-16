package policy

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadPolicies loads policies from a file or directory
func LoadPolicies(path string) (*PolicySet, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("failed to stat path: %w", err)
	}

	if info.IsDir() {
		return loadPoliciesFromDirectory(path)
	}
	return loadPoliciesFromFile(path)
}

// loadPoliciesFromFile loads policies from a single YAML file
func loadPoliciesFromFile(path string) (*PolicySet, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policySet PolicySet
	if err := yaml.Unmarshal(data, &policySet); err != nil {
		return nil, fmt.Errorf("failed to parse policy YAML: %w", err)
	}

	if err := policySet.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy set: %w", err)
	}

	return &policySet, nil
}

// loadPoliciesFromDirectory loads policies from all YAML files in a directory
func loadPoliciesFromDirectory(dirPath string) (*PolicySet, error) {
	files, err := ioutil.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	allPolicies := &PolicySet{
		Policies: []Policy{},
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Only process YAML files
		ext := filepath.Ext(file.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		filePath := filepath.Join(dirPath, file.Name())
		policySet, err := loadPoliciesFromFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s: %w", file.Name(), err)
		}

		allPolicies.Policies = append(allPolicies.Policies, policySet.Policies...)
	}

	if len(allPolicies.Policies) == 0 {
		return nil, fmt.Errorf("no policies found in directory: %s", dirPath)
	}

	if err := allPolicies.Validate(); err != nil {
		return nil, fmt.Errorf("invalid combined policy set: %w", err)
	}

	return allPolicies, nil
}

// LoadWaivers loads waivers from a file
func LoadWaivers(path string) (*WaiverSet, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read waiver file: %w", err)
	}

	var waiverSet WaiverSet
	if err := yaml.Unmarshal(data, &waiverSet); err != nil {
		return nil, fmt.Errorf("failed to parse waiver YAML: %w", err)
	}

	if err := waiverSet.Validate(); err != nil {
		return nil, fmt.Errorf("invalid waiver set: %w", err)
	}

	// Update status for each waiver
	for i := range waiverSet.Waivers {
		if waiverSet.Waivers[i].IsExpired() {
			waiverSet.Waivers[i].Status = "expired"
		} else {
			waiverSet.Waivers[i].Status = "active"
		}
	}

	return &waiverSet, nil
}

// SavePolicies saves policies to a YAML file
func SavePolicies(policySet *PolicySet, path string) error {
	if err := policySet.Validate(); err != nil {
		return fmt.Errorf("invalid policy set: %w", err)
	}

	data, err := yaml.Marshal(policySet)
	if err != nil {
		return fmt.Errorf("failed to marshal policies: %w", err)
	}

	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write policy file: %w", err)
	}

	return nil
}

// SaveWaivers saves waivers to a YAML file
func SaveWaivers(waiverSet *WaiverSet, path string) error {
	if err := waiverSet.Validate(); err != nil {
		return fmt.Errorf("invalid waiver set: %w", err)
	}

	data, err := yaml.Marshal(waiverSet)
	if err != nil {
		return fmt.Errorf("failed to marshal waivers: %w", err)
	}

	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write waiver file: %w", err)
	}

	return nil
}
