package output

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"perforator-go/internal/api"
	"perforator-go/internal/dump"
	"perforator-go/internal/s3"
	"perforator-go/internal/scanner"
)

func TestNew(t *testing.T) {
	formats := []string{"json", "xml", "csv", "console"}
	
	for _, format := range formats {
		formatter := New(format)
		if formatter.format != format {
			t.Errorf("Expected format '%s', got '%s'", format, formatter.format)
		}
	}
}

func TestWriteJSON(t *testing.T) {
	formatter := New("json")
	result := createTestScanResult()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := formatter.Write(result)
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify it's valid JSON
	var jsonResult scanner.ScanResult
	if err := json.Unmarshal([]byte(output), &jsonResult); err != nil {
		t.Errorf("Output is not valid JSON: %v", err)
	}

	// Verify content
	if jsonResult.Summary.TotalTargets != result.Summary.TotalTargets {
		t.Error("JSON output doesn't match original data")
	}
}

func TestWriteXML(t *testing.T) {
	formatter := New("xml")
	result := createTestScanResult()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := formatter.Write(result)
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("WriteXML failed: %v", err)
	}

	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify it contains XML declaration
	if !strings.Contains(output, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>") {
		t.Error("XML output missing declaration")
	}

	// Verify it's valid XML by attempting to unmarshal
	var xmlResult scanner.ScanResult
	// Remove XML declaration for unmarshaling
	xmlContent := strings.SplitN(output, "\n", 2)[1]
	if err := xml.Unmarshal([]byte(xmlContent), &xmlResult); err != nil {
		t.Errorf("Output is not valid XML: %v", err)
	}
}

func TestWriteCSV(t *testing.T) {
	formatter := New("csv")
	result := createTestScanResult()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := formatter.Write(result)
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("WriteCSV failed: %v", err)
	}

	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify CSV header
	if !strings.Contains(output, "Type,Target,Status,Risk Level,Details") {
		t.Error("CSV output missing header")
	}

	// Verify CSV content
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) < 2 { // Header + at least one data line
		t.Error("CSV output should have header and data lines")
	}

	// Check for expected data types
	if !strings.Contains(output, "S3,") {
		t.Error("CSV output missing S3 data")
	}
	if !strings.Contains(output, "Credential,") {
		t.Error("CSV output missing credential data")
	}
	if !strings.Contains(output, "API,") {
		t.Error("CSV output missing API data")
	}
}

func TestWriteConsole(t *testing.T) {
	formatter := New("console")
	result := createTestScanResult()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := formatter.Write(result)
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("WriteConsole failed: %v", err)
	}

	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Verify console output contains expected sections
	expectedSections := []string{
		"PERFORATOR-GO SCAN RESULTS",
		"SCAN SUMMARY",
		"S3 ENUMERATION RESULTS",
		"DUMP ANALYSIS RESULTS",
		"API KEY VALIDATION RESULTS",
		"RECOMMENDATIONS",
	}

	for _, section := range expectedSections {
		if !strings.Contains(output, section) {
			t.Errorf("Console output missing section: %s", section)
		}
	}
}

func TestFormatCount(t *testing.T) {
	testCases := []struct {
		count    int
		expected string
	}{
		{0, "0"},     // Should be green (we can't test color easily)
		{5, "5"},     // Should be yellow
		{100, "100"}, // Should be yellow
	}

	for _, tc := range testCases {
		result := formatCount(tc.count)
		// Remove ANSI color codes for testing
		cleanResult := removeANSI(result)
		if cleanResult != tc.expected {
			t.Errorf("formatCount(%d): expected '%s', got '%s'", tc.count, tc.expected, cleanResult)
		}
	}
}

func TestFormatCritical(t *testing.T) {
	testCases := []struct {
		count    int
		expected string
	}{
		{0, "0"},   // Should be green
		{1, "1"},   // Should be red
		{10, "10"}, // Should be red
	}

	for _, tc := range testCases {
		result := formatCritical(tc.count)
		cleanResult := removeANSI(result)
		if cleanResult != tc.expected {
			t.Errorf("formatCritical(%d): expected '%s', got '%s'", tc.count, tc.expected, cleanResult)
		}
	}
}

func TestFormatHigh(t *testing.T) {
	testCases := []struct {
		count    int
		expected string
	}{
		{0, "0"},   // Should be green
		{1, "1"},   // Should be yellow
		{10, "10"}, // Should be yellow
	}

	for _, tc := range testCases {
		result := formatHigh(tc.count)
		cleanResult := removeANSI(result)
		if cleanResult != tc.expected {
			t.Errorf("formatHigh(%d): expected '%s', got '%s'", tc.count, tc.expected, cleanResult)
		}
	}
}

func TestGetRiskColor(t *testing.T) {
	testCases := []struct {
		risk     string
		expected string
	}{
		{"CRITICAL", "CRITICAL"},
		{"HIGH", "HIGH"},
		{"MEDIUM", "MEDIUM"},
		{"LOW", "LOW"},
		{"UNKNOWN", "UNKNOWN"},
	}

	for _, tc := range testCases {
		result := getRiskColor(tc.risk)
		cleanResult := removeANSI(result)
		if cleanResult != tc.expected {
			t.Errorf("getRiskColor('%s'): expected '%s', got '%s'", tc.risk, tc.expected, cleanResult)
		}
	}
}

func TestMaskValue(t *testing.T) {
	testCases := []struct {
		value    string
		expected string
	}{
		{"short", "******"},
		{"123456", "******"},
		{"1234567", "123****"},
		{"secret123", "sec***123"},
		{"very_long_secret_value", "ver***lue"},
	}

	for _, tc := range testCases {
		result := maskValue(tc.value)
		if result != tc.expected {
			t.Errorf("maskValue('%s'): expected '%s', got '%s'", tc.value, tc.expected, result)
		}
	}
}

func TestWriteDefaultFormat(t *testing.T) {
	formatter := New("unknown_format")
	result := createTestScanResult()

	// Capture stdout
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := formatter.Write(result)
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Fatalf("Write with unknown format failed: %v", err)
	}

	// Read captured output
	var buf bytes.Buffer
	io.Copy(&buf, r)
	output := buf.String()

	// Should default to console format
	if !strings.Contains(output, "PERFORATOR-GO SCAN RESULTS") {
		t.Error("Unknown format should default to console output")
	}
}

func TestEmptyResults(t *testing.T) {
	formatter := New("console")
	result := &scanner.ScanResult{
		Summary:   &scanner.ScanSummary{},
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Duration:  time.Second,
	}

	// Should not panic with empty results
	err := formatter.Write(result)
	if err != nil {
		t.Errorf("Write with empty results failed: %v", err)
	}
}

func TestLargeResultSet(t *testing.T) {
	formatter := New("json")
	result := createTestScanResult()

	// Add many results to test performance
	for i := 0; i < 100; i++ {
		result.S3Results = append(result.S3Results, s3.BucketResult{
			Name:       "bucket" + string(rune(i)),
			Accessible: i%2 == 0,
			Objects: []s3.Object{
				{Key: "file1.txt", Size: 1024, Sensitive: true, RiskLevel: "HIGH"},
			},
		})
	}

	err := formatter.Write(result)
	if err != nil {
		t.Errorf("Write with large result set failed: %v", err)
	}
}

// Helper functions
func createTestScanResult() *scanner.ScanResult {
	return &scanner.ScanResult{
		Request: &scanner.ScanRequest{
			Targets: []string{"https://example.com"},
			Mode:    "full",
		},
		S3Results: []s3.BucketResult{
			{
				Name:       "test-bucket",
				Accessible: true,
				StatusCode: 200,
				Objects: []s3.Object{
					{Key: "file1.txt", Size: 1024, Sensitive: false, RiskLevel: "MEDIUM"},
					{Key: "secret.env", Size: 512, Sensitive: true, RiskLevel: "CRITICAL"},
				},
			},
		},
		DumpResults: []dump.AnalysisResult{
			{
				FilePath: "/tmp/test.dump",
				FileSize: 2048,
				FileType: "text",
				Credentials: []dump.Credential{
					{Type: "password", Value: "secret123", Line: 10},
					{Type: "api_key", Value: "sk-1234567890", Line: 15},
				},
				Emails:        []string{"test@example.com"},
				IPs:           []string{"192.168.1.1"},
				Domains:       []string{"example.com"},
				AIXArtifacts:  []dump.AIXArtifact{{Type: "privkey_pag", Value: "privkey.pag", Line: 20}},
				ProcessingTime: time.Second,
			},
		},
		APIResults: []api.ValidationResult{
			{Service: "github", Valid: true, Key: "ghp_****1234", Permissions: []string{"repo", "user"}, Metadata: nil},
			{Service: "aws", Valid: false, Key: "AKIA****5678", Error: "Invalid credentials", Metadata: nil},
		},
		Summary: &scanner.ScanSummary{
			TotalTargets:      1,
			AccessibleBuckets: 1,
			SensitiveFiles:    1,
			CredentialsFound:  2,
			ValidAPIKeys:      1,
			CriticalFindings:  3,
			HighRiskFindings:  1,
		},
		StartTime: time.Now().Add(-time.Minute),
		EndTime:   time.Now(),
		Duration:  time.Minute,
	}
}

// removeANSI removes ANSI color codes from string for testing
func removeANSI(str string) string {
	// Simple regex to remove ANSI escape sequences
	// This is a basic implementation for testing
	result := str
	for strings.Contains(result, "\x1b[") {
		start := strings.Index(result, "\x1b[")
		end := strings.Index(result[start:], "m")
		if end == -1 {
			break
		}
		result = result[:start] + result[start+end+1:]
	}
	return result
}
