package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/coding-agent/cli/internal/llm"
)

// This example demonstrates how to use the Ollama provider for local LLM inference
// Prerequisites:
// 1. Install Ollama: https://ollama.ai/
// 2. Pull a model: ollama pull llama2
// 3. Start Ollama: ollama serve (runs on port 11434 by default)

func main() {
	fmt.Println("Ollama Provider Example")
	fmt.Println("=======================")

	// Configure Ollama provider
	config := llm.Config{
		Provider:     "ollama",
		Model:        "llama2", // You can also use: codellama, mistral, mixtral, phi, etc.
		BaseURL:      "http://localhost:11434",
		MaxTokens:    1024,
		Temperature:  0.7,
		Timeout:      60 * time.Second, // Longer timeout for local models
		CacheEnabled: true,
		CacheDir:     "/tmp/llm-cache",
	}

	// Create LLM manager
	manager, err := llm.NewManager(config)
	if err != nil {
		log.Fatalf("Failed to create LLM manager: %v", err)
	}
	defer manager.Close()

	// Check if Ollama is available
	if !manager.IsAvailable() {
		log.Fatal("Ollama is not running. Please start Ollama with: ollama serve")
	}
	fmt.Println("✓ Ollama is running and available")

	// Example 1: SQL Injection vulnerability
	fmt.Println("Example 1: SQL Injection")
	fmt.Println("------------------------")
	sqlInjectionRequest := llm.RemediationRequest{
		CWEID:          "CWE-89",
		CWEDescription: "SQL Injection",
		CodeSnippet:    `query = "SELECT * FROM users WHERE id = " + user_input`,
		FilePath:       "app.py",
		LineNumber:     42,
		Severity:       "high",
		RuleID:         "B608",
		Message:        "SQL injection vulnerability detected",
	}

	// Estimate cost (should be 0.0 for local models)
	cost, err := manager.EstimateCost(sqlInjectionRequest)
	if err != nil {
		log.Fatalf("Failed to estimate cost: %v", err)
	}
	fmt.Printf("Estimated cost: $%.4f (local models are free!)\n\n", cost)

	// Generate remediation
	ctx := context.Background()
	fmt.Println("Generating remediation guidance...")
	resp, err := manager.GenerateRemediation(ctx, sqlInjectionRequest)
	if err != nil {
		log.Fatalf("Failed to generate remediation: %v", err)
	}

	// Display results
	fmt.Printf("\nExplanation:\n%s\n\n", resp.Explanation)
	fmt.Println("Remediation Steps:")
	for i, step := range resp.RemediationSteps {
		fmt.Printf("%d. %s\n", i+1, step)
	}
	if resp.ExampleFix != "" {
		fmt.Printf("\nExample Fix:\n%s\n", resp.ExampleFix)
	}
	fmt.Printf("\nConfidence: %.2f\n", resp.Confidence)
	fmt.Printf("Cached: %v\n", resp.Cached)
	fmt.Printf("Generated at: %s\n\n", resp.GeneratedAt.Format(time.RFC3339))

	// Example 2: Cross-Site Scripting (XSS)
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("Example 2: Cross-Site Scripting (XSS)")
	fmt.Println(strings.Repeat("=", 50))
	xssRequest := llm.RemediationRequest{
		CWEID:          "CWE-79",
		CWEDescription: "Cross-site Scripting (XSS)",
		CodeSnippet:    `html = "<div>" + user_input + "</div>"`,
		FilePath:       "app.py",
		LineNumber:     10,
		Severity:       "medium",
		RuleID:         "B201",
		Message:        "Potential XSS vulnerability",
	}

	fmt.Println("Generating remediation guidance...")
	resp2, err := manager.GenerateRemediation(ctx, xssRequest)
	if err != nil {
		log.Fatalf("Failed to generate remediation: %v", err)
	}

	fmt.Printf("\nExplanation:\n%s\n\n", resp2.Explanation)
	fmt.Println("Remediation Steps:")
	for i, step := range resp2.RemediationSteps {
		fmt.Printf("%d. %s\n", i+1, step)
	}
	fmt.Printf("\nCached: %v\n", resp2.Cached)

	// Example 3: Demonstrate caching
	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("Example 3: Caching Demonstration")
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println("Making the same request again to demonstrate caching...")

	start := time.Now()
	resp3, err := manager.GenerateRemediation(ctx, sqlInjectionRequest)
	duration := time.Since(start)

	if err != nil {
		log.Fatalf("Failed to generate remediation: %v", err)
	}

	fmt.Printf("Response time: %v\n", duration)
	fmt.Printf("Cached: %v\n", resp3.Cached)
	if resp3.Cached {
		fmt.Println("✓ Response was served from cache (much faster!)")
	}

	fmt.Println("\n" + strings.Repeat("=", 50))
	fmt.Println("Example completed successfully!")
	fmt.Println(strings.Repeat("=", 50))
}
