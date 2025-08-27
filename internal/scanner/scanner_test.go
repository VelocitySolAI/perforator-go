package scanner

import (
	"context"
	"os"
	"testing"
	"time"

	"perforator-go/internal/api"
	"perforator-go/internal/config"
	"perforator-go/internal/dump"
	"perforator-go/internal/s3"
)

func TestNew(t *testing.T) {
	cfg := &config.Config{
		Workers:   10,
		Timeout:   5 * time.Second,
		RateLimit: 50,
	}

	scanner := New(cfg)

	if scanner.config != cfg {
		t.Error("Expected config to be set")
	}
	if scanner.s3Enum == nil {
		t.Error("Expected S3 enumerator to be initialized")
	}
	if scanner.dumpAnalyzer == nil {
		t.Error("Expected dump analyzer to be initialized")
	}
	if scanner.apiValidator == nil {
		t.Error("Expected API validator to be initialized")
	}
}

func TestScanRequest(t *testing.T) {
	req := &ScanRequest{
		Targets:     []string{"https://example.com"},
		Mode:        "full",
		DumpFiles:   []string{"test.dump"},
		APIKeys:     map[string]string{"github": "token123"},
		BucketNames: []string{"test-bucket"},
	}

	if len(req.Targets) != 1 {
		t.Errorf("Expected 1 target, got %d", len(req.Targets))
	}
	if req.Mode != "full" {
		t.Errorf("Expected mode 'full', got '%s'", req.Mode)
	}
	if len(req.APIKeys) != 1 {
		t.Errorf("Expected 1 API key, got %d", len(req.APIKeys))
	}
}

func TestScanResult(t *testing.T) {
	result := &ScanResult{
		StartTime: time.Now(),
		Summary:   &ScanSummary{},
	}

	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	if result.Summary == nil {
		t.Error("Expected summary to be initialized")
	}
	if result.Duration < 0 {
		t.Error("Expected positive duration")
	}
}

func TestScanS3Only(t *testing.T) {
	cfg := &config.Config{
		Workers:   5,
		Timeout:   2 * time.Second,
		RateLimit: 10,
		Verbose:   false,
	}

	scanner := New(cfg)
	ctx := context.Background()

	req := &ScanRequest{
		Targets: []string{"https://example.com"},
		Mode:    "s3",
	}

	result, err := scanner.Scan(ctx, req)
	if err != nil {
		t.Fatalf("S3-only scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected scan result")
	}
	if result.Request != req {
		t.Error("Expected request to be preserved in result")
	}
	if result.Summary == nil {
		t.Error("Expected summary to be generated")
	}
	if result.Duration == 0 {
		t.Error("Expected non-zero duration")
	}
}

func TestScanDumpOnly(t *testing.T) {
	// Create a temporary test file
	tmpFile, err := os.CreateTemp("", "test_dump_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "password: secret123\nemail: test@example.com\n"
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	cfg := &config.Config{
		Workers:   5,
		Timeout:   2 * time.Second,
		RateLimit: 10,
		Verbose:   false,
	}

	scanner := New(cfg)
	ctx := context.Background()

	req := &ScanRequest{
		DumpFiles: []string{tmpFile.Name()},
		Mode:      "dump",
	}

	result, err := scanner.Scan(ctx, req)
	if err != nil {
		t.Fatalf("Dump-only scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected scan result")
	}
	if len(result.DumpResults) == 0 {
		t.Error("Expected dump results")
	}
	if result.Summary.CredentialsFound == 0 {
		t.Error("Expected credentials to be found in summary")
	}
}

func TestScanAPIOnly(t *testing.T) {
	cfg := &config.Config{
		Workers:   5,
		Timeout:   2 * time.Second,
		RateLimit: 10,
		Verbose:   false,
	}

	scanner := New(cfg)
	ctx := context.Background()

	req := &ScanRequest{
		APIKeys: map[string]string{
			"aws": "AKIAIOSFODNN7EXAMPLE", // Valid format
		},
		Mode: "api",
	}

	result, err := scanner.Scan(ctx, req)
	if err != nil {
		t.Fatalf("API-only scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected scan result")
	}
	if len(result.APIResults) == 0 {
		t.Error("Expected API results")
	}
}

func TestScanFullMode(t *testing.T) {
	// Create a temporary test file
	tmpFile, err := os.CreateTemp("", "test_dump_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "password: secret123\n"
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	cfg := &config.Config{
		Workers:   5,
		Timeout:   2 * time.Second,
		RateLimit: 10,
		Verbose:   false,
	}

	scanner := New(cfg)
	ctx := context.Background()

	req := &ScanRequest{
		Targets:   []string{"https://example.com"},
		DumpFiles: []string{tmpFile.Name()},
		APIKeys: map[string]string{
			"aws": "AKIAIOSFODNN7EXAMPLE",
		},
		Mode: "full",
	}

	result, err := scanner.Scan(ctx, req)
	if err != nil {
		t.Fatalf("Full scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected scan result")
	}

	// Should have results from all components
	if len(result.S3Results) == 0 {
		t.Error("Expected S3 results in full mode")
	}
	if len(result.DumpResults) == 0 {
		t.Error("Expected dump results in full mode")
	}
	if len(result.APIResults) == 0 {
		t.Error("Expected API results in full mode")
	}
}

func TestGenerateSummary(t *testing.T) {
	cfg := &config.Config{
		Workers:   5,
		Timeout:   2 * time.Second,
		RateLimit: 10,
	}

	scanner := New(cfg)
	
	result := &ScanResult{
		Request: &ScanRequest{
			Targets: []string{"target1", "target2"},
		},
		S3Results: []s3.BucketResult{
			{
				Name:       "bucket1",
				Accessible: true,
				Objects: []s3.Object{
					{Key: "file1.txt", Sensitive: true, RiskLevel: "HIGH"},
					{Key: "secret.env", Sensitive: true, RiskLevel: "CRITICAL"},
				},
			},
			{
				Name:       "bucket2",
				Accessible: false,
			},
		},
		DumpResults: []dump.AnalysisResult{
			{
				Credentials: []dump.Credential{
					{Type: "password", Value: "secret"},
					{Type: "api_key", Value: "key123"},
				},
			},
		},
		APIResults: []api.ValidationResult{
			{Service: "github", Valid: true},
			{Service: "aws", Valid: false},
		},
		Summary: &ScanSummary{},
	}

	scanner.generateSummary(result)

	summary := result.Summary
	if summary.TotalTargets != 2 {
		t.Errorf("Expected 2 total targets, got %d", summary.TotalTargets)
	}
	if summary.AccessibleBuckets != 1 {
		t.Errorf("Expected 1 accessible bucket, got %d", summary.AccessibleBuckets)
	}
	if summary.SensitiveFiles != 2 {
		t.Errorf("Expected 2 sensitive files, got %d", summary.SensitiveFiles)
	}
	if summary.CredentialsFound != 2 {
		t.Errorf("Expected 2 credentials found, got %d", summary.CredentialsFound)
	}
	if summary.ValidAPIKeys != 1 {
		t.Errorf("Expected 1 valid API key, got %d", summary.ValidAPIKeys)
	}
	if summary.CriticalFindings != 3 { // 1 CRITICAL file + 2 credentials
		t.Errorf("Expected 3 critical findings, got %d", summary.CriticalFindings)
	}
	if summary.HighRiskFindings != 2 { // 1 HIGH risk file + 1 valid API key
		t.Errorf("Expected 2 high risk findings, got %d", summary.HighRiskFindings)
	}
}

func TestScanWithEmptyRequest(t *testing.T) {
	cfg := &config.Config{
		Workers:   5,
		Timeout:   2 * time.Second,
		RateLimit: 10,
		Verbose:   false,
	}

	scanner := New(cfg)
	ctx := context.Background()

	req := &ScanRequest{
		Mode: "full",
		// All arrays empty
	}

	result, err := scanner.Scan(ctx, req)
	if err != nil {
		t.Fatalf("Empty scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected scan result")
	}
	if result.Summary.TotalTargets != 0 {
		t.Error("Expected 0 total targets for empty request")
	}
}

func TestContextCancellation(t *testing.T) {
	cfg := &config.Config{
		Workers:   5,
		Timeout:   10 * time.Second, // Long timeout
		RateLimit: 10,
		Verbose:   false,
	}

	scanner := New(cfg)
	
	// Create context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	req := &ScanRequest{
		Targets: []string{"https://example.com"},
		Mode:    "s3",
	}

	result, err := scanner.Scan(ctx, req)
	
	// Should handle context cancellation gracefully
	if err != nil && err != context.DeadlineExceeded {
		t.Errorf("Unexpected error: %v", err)
	}

	// Result should still be returned
	if result == nil {
		t.Error("Expected result even with context cancellation")
	}
}

func TestScanSummaryInitialization(t *testing.T) {
	summary := &ScanSummary{}
	
	// All fields should be zero-initialized
	if summary.TotalTargets != 0 {
		t.Error("Expected TotalTargets to be 0")
	}
	if summary.AccessibleBuckets != 0 {
		t.Error("Expected AccessibleBuckets to be 0")
	}
	if summary.SensitiveFiles != 0 {
		t.Error("Expected SensitiveFiles to be 0")
	}
	if summary.CredentialsFound != 0 {
		t.Error("Expected CredentialsFound to be 0")
	}
	if summary.ValidAPIKeys != 0 {
		t.Error("Expected ValidAPIKeys to be 0")
	}
	if summary.CriticalFindings != 0 {
		t.Error("Expected CriticalFindings to be 0")
	}
	if summary.HighRiskFindings != 0 {
		t.Error("Expected HighRiskFindings to be 0")
	}
}

func TestScanModeValidation(t *testing.T) {
	cfg := &config.Config{
		Workers:   5,
		Timeout:   2 * time.Second,
		RateLimit: 10,
		Verbose:   false,
	}

	scanner := New(cfg)
	ctx := context.Background()

	validModes := []string{"s3", "dump", "api", "full"}
	
	for _, mode := range validModes {
		req := &ScanRequest{
			Targets: []string{"https://example.com"},
			Mode:    mode,
		}

		result, err := scanner.Scan(ctx, req)
		if err != nil {
			t.Errorf("Scan with mode '%s' failed: %v", mode, err)
		}
		if result == nil {
			t.Errorf("Expected result for mode '%s'", mode)
		}
	}
}

func TestProgressBarWithVerbose(t *testing.T) {
	cfg := &config.Config{
		Workers:   5,
		Timeout:   2 * time.Second,
		RateLimit: 10,
		Verbose:   true, // Enable verbose mode
	}

	scanner := New(cfg)
	ctx := context.Background()

	req := &ScanRequest{
		Targets: []string{"https://example.com"},
		Mode:    "s3",
	}

	result, err := scanner.Scan(ctx, req)
	if err != nil {
		t.Fatalf("Verbose scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected scan result")
	}
}

func TestConcurrentScanning(t *testing.T) {
	// Create multiple temporary dump files
	var dumpFiles []string
	for i := 0; i < 3; i++ {
		tmpFile, err := os.CreateTemp("", "test_concurrent_*.txt")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		content := "password: secret123\nemail: test@example.com\n"
		if _, err := tmpFile.WriteString(content); err != nil {
			t.Fatalf("Failed to write to temp file: %v", err)
		}
		tmpFile.Close()
		dumpFiles = append(dumpFiles, tmpFile.Name())
	}

	cfg := &config.Config{
		Workers:   10,
		Timeout:   5 * time.Second,
		RateLimit: 50,
		Verbose:   false,
	}

	scanner := New(cfg)
	ctx := context.Background()

	req := &ScanRequest{
		DumpFiles: dumpFiles,
		Mode:      "dump",
	}

	start := time.Now()
	result, err := scanner.Scan(ctx, req)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Concurrent scan failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected scan result")
	}

	if len(result.DumpResults) != len(dumpFiles) {
		t.Errorf("Expected %d dump results, got %d", len(dumpFiles), len(result.DumpResults))
	}

	// With concurrency, should be faster than sequential processing
	if duration > 2*time.Second {
		t.Errorf("Concurrent processing took too long: %v", duration)
	}
}
