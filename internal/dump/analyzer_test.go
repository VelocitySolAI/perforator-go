package dump

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	workers := 10
	analyzer := New(workers)

	if analyzer.workers != workers {
		t.Errorf("Expected workers %d, got %d", workers, analyzer.workers)
	}

	if len(analyzer.credentialPatterns) == 0 {
		t.Error("Expected credential patterns to be initialized")
	}

	if analyzer.emailPattern == nil {
		t.Error("Expected email pattern to be initialized")
	}

	if analyzer.ipPattern == nil {
		t.Error("Expected IP pattern to be initialized")
	}

	if analyzer.domainPattern == nil {
		t.Error("Expected domain pattern to be initialized")
	}

	if len(analyzer.aixPatterns) == 0 {
		t.Error("Expected AIX patterns to be initialized")
	}
}

func TestAnalyzeFile(t *testing.T) {
	// Create a temporary test file
	content := `
password: secret123
api_key: sk-1234567890abcdef
email: test@example.com
IP: 192.168.1.1
domain: example.com
AIX system dump
privkey.pag file found
`
	
	tmpFile, err := os.CreateTemp("", "test_dump_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	analyzer := New(5)
	ctx := context.Background()

	result, err := analyzer.AnalyzeFile(ctx, tmpFile.Name())
	if err != nil {
		t.Fatalf("AnalyzeFile failed: %v", err)
	}

	if result.FilePath != tmpFile.Name() {
		t.Errorf("Expected file path %s, got %s", tmpFile.Name(), result.FilePath)
	}

	if result.FileSize == 0 {
		t.Error("Expected non-zero file size")
	}

	if result.FileType != "text" {
		t.Errorf("Expected file type 'text', got %s", result.FileType)
	}

	if len(result.Credentials) == 0 {
		t.Error("Expected to find credentials")
	}

	if len(result.Emails) == 0 {
		t.Error("Expected to find emails")
	}

	if len(result.IPs) == 0 {
		t.Error("Expected to find IPs")
	}

	if len(result.Domains) == 0 {
		t.Error("Expected to find domains")
	}

	if len(result.AIXArtifacts) == 0 {
		t.Error("Expected to find AIX artifacts")
	}

	if result.ProcessingTime == 0 {
		t.Error("Expected non-zero processing time")
	}
}

func TestAnalyzeFileNotFound(t *testing.T) {
	analyzer := New(5)
	ctx := context.Background()

	result, err := analyzer.AnalyzeFile(ctx, "/nonexistent/file.txt")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	if result.Error == "" {
		t.Error("Expected error message in result")
	}
}

func TestDetectFileType(t *testing.T) {
	testCases := []struct {
		header   []byte
		expected string
	}{
		{[]byte{0x1f, 0x8b, 0x08}, "gzip"},
		{[]byte{'B', 'Z', 'h'}, "bzip2"},
		{[]byte("pax header"), "pax"},
		{[]byte("regular text"), "text"},
		{[]byte{}, "unknown"},
	}

	for _, tc := range testCases {
		// Create temp file with specific header
		tmpFile, err := os.CreateTemp("", "test_type_*.dat")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		defer os.Remove(tmpFile.Name())

		if len(tc.header) > 0 {
			tmpFile.Write(tc.header)
		}
		tmpFile.Close()

		result := detectFileType(tmpFile.Name())
		if result != tc.expected {
			t.Errorf("detectFileType with header %v: expected %s, got %s", tc.header, tc.expected, result)
		}
	}
}

func TestProcessLine(t *testing.T) {
	analyzer := New(5)
	
	// Create channels for collecting results
	credChan := make(chan Credential, 10)
	emailChan := make(chan string, 10)
	ipChan := make(chan string, 10)
	domainChan := make(chan string, 10)
	aixChan := make(chan AIXArtifact, 10)

	testLine := `password: secret123, api_key: sk-abcdef, email: user@test.com, IP: 10.0.0.1, domain: test.example.com, privkey.pag found`
	
	analyzer.processLine(testLine, 1, credChan, emailChan, ipChan, domainChan, aixChan)

	// Close channels to stop receiving
	close(credChan)
	close(emailChan)
	close(ipChan)
	close(domainChan)
	close(aixChan)

	// Check credentials
	credCount := 0
	for range credChan {
		credCount++
	}
	if credCount == 0 {
		t.Error("Expected to find credentials in test line")
	}

	// Check emails
	emailCount := 0
	for range emailChan {
		emailCount++
	}
	if emailCount == 0 {
		t.Error("Expected to find emails in test line")
	}

	// Check IPs
	ipCount := 0
	for range ipChan {
		ipCount++
	}
	if ipCount == 0 {
		t.Error("Expected to find IPs in test line")
	}

	// Check domains
	domainCount := 0
	for range domainChan {
		domainCount++
	}
	if domainCount == 0 {
		t.Error("Expected to find domains in test line")
	}

	// Check AIX artifacts
	aixCount := 0
	for range aixChan {
		aixCount++
	}
	if aixCount == 0 {
		t.Error("Expected to find AIX artifacts in test line")
	}
}

func TestCredentialPatterns(t *testing.T) {
	analyzer := New(5)
	
	testCases := []struct {
		line     string
		expected bool
	}{
		{`password: "secret123"`, true},
		{`api_key = "sk-1234567890"`, true},
		{`secret: hidden_value`, true},
		{`token: bearer_token_here`, true},
		{`access_key: AKIAIOSFODNN7EXAMPLE`, true},
		{`private_key: "-----BEGIN PRIVATE KEY-----"`, true},
		{`authorization: "Bearer token123"`, true},
		{`normal text without credentials`, false},
	}

	for _, tc := range testCases {
		found := false
		for _, pattern := range analyzer.credentialPatterns {
			if pattern.MatchString(tc.line) {
				found = true
				break
			}
		}
		
		if found != tc.expected {
			t.Errorf("Credential pattern matching for '%s': expected %v, got %v", tc.line, tc.expected, found)
		}
	}
}

func TestEmailPattern(t *testing.T) {
	analyzer := New(5)
	
	testCases := []struct {
		text     string
		expected []string
	}{
		{"Contact us at support@example.com", []string{"support@example.com"}},
		{"Multiple emails: user1@test.com, user2@domain.org", []string{"user1@test.com", "user2@domain.org"}},
		{"Invalid email: not-an-email", []string{}},
		{"Edge case: test@sub.domain.co.uk", []string{"test@sub.domain.co.uk"}},
	}

	for _, tc := range testCases {
		matches := analyzer.emailPattern.FindAllString(tc.text, -1)
		
		if len(matches) != len(tc.expected) {
			t.Errorf("Email pattern for '%s': expected %d matches, got %d", tc.text, len(tc.expected), len(matches))
			continue
		}

		for i, expected := range tc.expected {
			if i < len(matches) && matches[i] != expected {
				t.Errorf("Email pattern for '%s': expected '%s', got '%s'", tc.text, expected, matches[i])
			}
		}
	}
}

func TestIPPattern(t *testing.T) {
	analyzer := New(5)
	
	testCases := []struct {
		text     string
		expected []string
	}{
		{"Server IP: 192.168.1.1", []string{"192.168.1.1"}},
		{"Multiple IPs: 10.0.0.1, 172.16.0.1", []string{"10.0.0.1", "172.16.0.1"}},
		{"Invalid IP: 999.999.999.999", []string{"999.999.999.999"}}, // Pattern doesn't validate ranges
		{"No IPs here", []string{}},
	}

	for _, tc := range testCases {
		matches := analyzer.ipPattern.FindAllString(tc.text, -1)
		
		if len(matches) != len(tc.expected) {
			t.Errorf("IP pattern for '%s': expected %d matches, got %d", tc.text, len(tc.expected), len(matches))
			continue
		}

		for i, expected := range tc.expected {
			if i < len(matches) && matches[i] != expected {
				t.Errorf("IP pattern for '%s': expected '%s', got '%s'", tc.text, expected, matches[i])
			}
		}
	}
}

func TestDomainPattern(t *testing.T) {
	analyzer := New(5)
	
	testCases := []struct {
		text     string
		expected []string
	}{
		{"Visit example.com", []string{"example.com"}},
		{"Multiple domains: test.org, sub.domain.net", []string{"test.org", "sub.domain.net"}},
		{"Complex: api.v2.service.example.co.uk", []string{"api.v2.service.example.co.uk"}},
		{"No domains here: just text", []string{}},
	}

	for _, tc := range testCases {
		matches := analyzer.domainPattern.FindAllString(tc.text, -1)
		
		if len(matches) != len(tc.expected) {
			t.Errorf("Domain pattern for '%s': expected %d matches, got %d", tc.text, len(tc.expected), len(matches))
			continue
		}

		for i, expected := range tc.expected {
			if i < len(matches) && matches[i] != expected {
				t.Errorf("Domain pattern for '%s': expected '%s', got '%s'", tc.text, expected, matches[i])
			}
		}
	}
}

func TestAIXPatterns(t *testing.T) {
	analyzer := New(5)
	
	testCases := []struct {
		text         string
		expectedType string
		shouldMatch  bool
	}{
		{"AIX server01 7 1 00F84C0C4C00", "aix_version", true},
		{"Dump Date: Mon Jan 1 00:00:00 2024", "dump_date", true},
		{"System: production", "system_name", true},
		{"Found privkey.pag file", "dbm_files", true},
		{"Located pwdhist.pag", "dbm_files", true},
		{"Config in passwd.etc", "passwd_etc", true},
		{"SSH config found: ssh_config", "ssh_config", true},
		{"Database file: users.pag", "dbm_files", true},
		{"Regular text without AIX artifacts", "", false},
	}

	for _, tc := range testCases {
		found := false
		foundType := ""
		
		for artifactType, pattern := range analyzer.aixPatterns {
			if pattern.MatchString(tc.text) {
				found = true
				foundType = artifactType
				break
			}
		}
		
		if found != tc.shouldMatch {
			t.Errorf("AIX pattern matching for '%s': expected %v, got %v", tc.text, tc.shouldMatch, found)
		}
		
		if tc.shouldMatch && foundType != tc.expectedType {
			t.Errorf("AIX pattern type for '%s': expected '%s', got '%s'", tc.text, tc.expectedType, foundType)
		}
	}
}

func TestTruncateContext(t *testing.T) {
	testCases := []struct {
		text     string
		maxLen   int
		expected string
	}{
		{"short text", 20, "short text"},
		{"this is a very long text that should be truncated", 20, "this is a very long ..."},
		{"exact length", 12, "exact length"},
		{"", 10, ""},
	}

	for _, tc := range testCases {
		result := truncateContext(tc.text, tc.maxLen)
		if result != tc.expected {
			t.Errorf("truncateContext('%s', %d): expected '%s', got '%s'", tc.text, tc.maxLen, tc.expected, result)
		}
	}
}

func TestContextCancellation(t *testing.T) {
	// Create a test file with some content
	content := strings.Repeat("password: secret123\nemail: test@example.com\n", 1000)
	
	tmpFile, err := os.CreateTemp("", "test_cancel_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	analyzer := New(5)
	
	// Create context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	result, err := analyzer.AnalyzeFile(ctx, tmpFile.Name())
	
	// Should handle context cancellation gracefully
	if err != nil && err != context.DeadlineExceeded {
		t.Errorf("Unexpected error: %v", err)
	}

	// Result should still be returned
	if result == nil {
		t.Error("Expected result even with context cancellation")
	}
}

func TestMultiCloser(t *testing.T) {
	// Create mock closers
	closed1 := false
	closed2 := false
	
	closer1 := &mockCloser{closed: &closed1}
	closer2 := &mockCloser{closed: &closed2}
	
	mc := &multiCloser{
		Reader:  strings.NewReader("test"),
		closers: []io.Closer{closer1, closer2},
	}
	
	err := mc.Close()
	if err != nil {
		t.Errorf("multiCloser.Close() failed: %v", err)
	}
	
	if !closed1 || !closed2 {
		t.Error("Expected all closers to be closed")
	}
}

// Mock closer for testing
type mockCloser struct {
	closed *bool
}

func (mc *mockCloser) Close() error {
	*mc.closed = true
	return nil
}

func (mc *mockCloser) Read(p []byte) (n int, err error) {
	return 0, nil
}
