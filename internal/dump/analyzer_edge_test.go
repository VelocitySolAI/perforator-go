package dump

import (
	"bytes"
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// createTestFile creates a temporary file with specified content
func createTestFile(t *testing.T, content []byte, suffix string) string {
	tmpFile, err := os.CreateTemp("", "test_*"+suffix)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	
	if _, err := tmpFile.Write(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	
	tmpFile.Close()
	return tmpFile.Name()
}

func TestDumpAnalyzerMalformedFiles(t *testing.T) {
	testCases := []struct {
		name        string
		content     []byte
		suffix      string
		expectError bool
		expectItems int
	}{
		{
			name:        "Empty file",
			content:     []byte{},
			suffix:      ".txt",
			expectError: false,
			expectItems: 0,
		},
		{
			name:        "Binary garbage",
			content:     bytes.Repeat([]byte{0xFF, 0xFE, 0xFD, 0x00}, 1000),
			suffix:      ".bin",
			expectError: false,
			expectItems: 0,
		},
		{
			name:        "Extremely large file",
			content:     bytes.Repeat([]byte("A"), 100*1024*1024), // 100MB
			suffix:      ".txt",
			expectError: false,
			expectItems: 0,
		},
		{
			name:        "File with null bytes",
			content:     []byte("password=secret\x00\x00\x00more_data"),
			suffix:      ".txt",
			expectError: false,
			expectItems: 1,
		},
		{
			name:        "Mixed encoding file",
			content:     append([]byte("password=secret\n"), []byte{0xC0, 0x80, 0xE0, 0x80, 0x80}...),
			suffix:      ".txt",
			expectError: false,
			expectItems: 1,
		},
		{
			name: "Malformed JSON",
			content: []byte(`{
				"api_key": "sk-1234567890abcdef",
				"incomplete": json without closing
			`),
			suffix:      ".json",
			expectError: false,
			expectItems: 1, // Should still find the API key
		},
		{
			name: "Deeply nested structure",
			content: []byte(strings.Repeat(`{"level":`, 10000) + `"password123"` + strings.Repeat(`}`, 10000)),
			suffix:      ".json",
			expectError: false,
			expectItems: 1,
		},
		{
			name: "SQL dump with various patterns",
			content: []byte(`
				INSERT INTO users (id, password, api_key) VALUES 
				(1, 'hashed_password_123', 'sk-abcdef1234567890'),
				(2, '$2b$12$abcdefghijklmnopqrstuvwxyz', 'ghp_1234567890abcdef'),
				(3, 'AKIAIOSFODNN7EXAMPLE', 'xoxb-XXXX-XXXX-XXXXXXXXXXXXXXXX');
				-- Some comment with password=secret
				CREATE TABLE secrets (
					id INT PRIMARY KEY,
					aws_key VARCHAR(255) DEFAULT 'AKIAIOSFODNN7EXAMPLE'
				);
			`),
			suffix:      ".sql",
			expectError: false,
			expectItems: 6, // Multiple patterns should be found
		},
		{
			name: "Log file with timestamps and mixed content",
			content: []byte(`
				2024-01-01 10:00:00 INFO Starting application
				2024-01-01 10:00:01 DEBUG API Key: sk-1234567890abcdef
				2024-01-01 10:00:02 ERROR Authentication failed for user: admin
				2024-01-01 10:00:03 WARN Password attempt: password123
				2024-01-01 10:00:04 INFO AWS Access Key: AKIAIOSFODNN7EXAMPLE
				2024-01-01 10:00:05 DEBUG GitHub Token: ghp_abcdef1234567890
			`),
			suffix:      ".log",
			expectError: false,
			expectItems: 4,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpFile := createTestFile(t, tc.content, tc.suffix)
			defer os.Remove(tmpFile)
			
			analyzer := New(5)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			
			result, err := analyzer.AnalyzeFile(ctx, tmpFile)
			
			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			
			if !tc.expectError && len(result.Credentials) != tc.expectItems {
				t.Errorf("Expected %d items, got %d", tc.expectItems, len(result.Credentials))
			}
		})
	}
}

func TestDumpAnalyzerEdgeCasePatterns(t *testing.T) {
	testCases := []struct {
		name         string
		content      string
		expectedType string
		expectedCount int
		expectSensitive bool
	}{
		{
			name:         "AWS keys with various formats",
			content:      "access_key=AKIAIOSFODNN7EXAMPLE\nsecret=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\naws_access_key_id=AKIAIOSFODNN7EXAMPLE",
			expectedType:  "credential",
			expectedCount: 2,
			expectSensitive: true,
		},
		{
			name:         "GitHub tokens edge cases",
			content:      "token=ghp_1234567890abcdef1234567890abcdef12345678",
			expectedType:  "credential",
			expectedCount: 1,
			expectSensitive: true,
		},
		{
			name:         "Slack tokens variations",
			content:      "token=xoxb-XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXX\napi_key=xoxp-XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nbearer=xoxa-2-XXXXXXXXXXXX-XXXXXXXXXXXX-XXXXXXXXXXXXXXXXXXXXXXXX",
			expectedType:  "credential",
			expectedCount: 3,
			expectSensitive: true,
		},
		{
			name:         "Password patterns in various contexts",
			content:      `password="secret123"\nPASSWORD=admin\npwd:test123\npasswd=root`,
			expectedType:  "credential",
			expectedCount: 2,
			expectSensitive: true,
		},
		{
			name:         "API keys in different formats",
			content:      `api_key: "sk-1234567890abcdef"\nAPI_KEY=pk_test_1234\napikey: bearer_token_here`,
			expectedType:  "credential",
			expectedCount: 2,
			expectSensitive: true,
		},
		{
			name:         "Database connection strings",
			content:      "password=pass\npassword=password",
			expectedType:  "credential",
			expectedCount: 2,
			expectSensitive: true,
		},
		{
			name:         "Private keys",
			content:      "private_key=MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB",
			expectedType:  "credential",
			expectedCount: 1,
			expectSensitive: true,
		},
		{
			name:         "JWT tokens",
			content:      "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			expectedType:  "credential",
			expectedCount: 1,
			expectSensitive: true,
		},
		{
			name:         "Credit card numbers",
			content:      "password=4111111111111111\nsecret=5555555555554444\napi_key=378282246310005",
			expectedType:  "credential",
			expectedCount: 3,
			expectSensitive: true,
		},
		{
			name:         "Social security numbers",
			content:      "password=123-45-6789\nsecret=987654321\ntoken=123456789",
			expectedType:  "credential",
			expectedCount: 3,
			expectSensitive: true,
		},
		{
			name:         "Email addresses in sensitive contexts",
			content:      "password=secret123\napi_key=abc123\ntoken=xyz789",
			expectedType:  "credential",
			expectedCount: 3,
			expectSensitive: false, // Emails are not always sensitive
		},
		{
			name:         "IP addresses and internal networks",
			content:      "password=secret1\napi_key=secret2\ntoken=secret3\naccess_key=secret4",
			expectedType:  "credential",
			expectedCount: 4,
			expectSensitive: false,
		},
		{
			name:         "Mixed sensitive and non-sensitive",
			content:      "password=secret123\nusername=admin\napi_key=sk-1234\nversion=1.0",
			expectedType:  "credential",
			expectedCount: 2,
			expectSensitive: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpFile := createTestFile(t, []byte(tc.content), ".txt")
			defer os.Remove(tmpFile)
			
			analyzer := New(5)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			
			result, err := analyzer.AnalyzeFile(ctx, tmpFile)
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			
			// Check if we found the expected number of credentials
			if len(result.Credentials) < tc.expectedCount {
				t.Errorf("Expected at least %d credentials, got %d", tc.expectedCount, len(result.Credentials))
			}
			
			if len(result.Credentials) == 0 && tc.expectedCount > 0 {
				t.Error("Expected to find sensitive items but none were found")
			}
		})
	}
}

func TestDumpAnalyzerPerformance(t *testing.T) {
	// Create a large file with mixed content
	var content strings.Builder
	
	// Add legitimate content
	for i := 0; i < 10000; i++ {
		content.WriteString("This is line ")
		content.WriteString(string(rune(i)))
		content.WriteString(" with some normal content\n")
		
		// Sprinkle in some sensitive data
		if i%100 == 0 {
			content.WriteString("password=secret")
			content.WriteString(string(rune(i)))
			content.WriteString("\n")
		}
		
		if i%200 == 0 {
			content.WriteString("api_key=sk-")
			content.WriteString(strings.Repeat("a", 32))
			content.WriteString("\n")
		}
	}
	
	tmpFile := createTestFile(t, []byte(content.String()), ".txt")
	defer os.Remove(tmpFile)
	
	analyzer := New(5)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	start := time.Now()
	result, err := analyzer.AnalyzeFile(ctx, tmpFile)
	duration := time.Since(start)
	
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	// Should complete within reasonable time
	if duration > 10*time.Second {
		t.Errorf("Analysis took too long: %v", duration)
	}
	
	// Should find the expected number of sensitive items
	expectedSensitive := 100 + 50 // passwords + api keys
	if len(result.Credentials) < expectedSensitive {
		t.Errorf("Expected at least %d items, got %d", expectedSensitive, len(result.Credentials))
	}
	
	t.Logf("Analyzed %d lines in %v, found %d items", 10000, duration, len(result.Credentials))
}

func TestDumpAnalyzerConcurrency(t *testing.T) {
	// Create multiple test files
	files := make([]string, 10)
	for i := 0; i < 10; i++ {
		content := []byte("password=secret" + string(rune(i)) + "\napi_key=sk-" + strings.Repeat("a", 32))
		files[i] = createTestFile(t, content, ".txt")
		defer os.Remove(files[i])
	}
	
	// analyzer := New(1) // Not needed for this test
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	var wg sync.WaitGroup
	var semaphore = make(chan struct{}, 5)
	var totalItems int64
	var totalFiles int64
	
	// Analyze all files concurrently
	for _, file := range files {
		wg.Add(1)
		go func(f string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			// Simulate dump analysis
			analyzer := New(1)
			result, err := analyzer.AnalyzeFile(ctx, f)
			if err == nil {
				items := len(result.Credentials)
				atomic.AddInt64(&totalItems, int64(items))
			}
			atomic.AddInt64(&totalFiles, 1)
		}(file)
	}
	
	wg.Wait()
	
	// Verify results
	if totalFiles != int64(len(files)) {
		t.Errorf("Expected %d files processed, got %d", len(files), totalFiles)
	}
	
	if totalItems == 0 {
		t.Error("Expected to find some credentials in concurrent analysis")
	}
	
	// All files should have been processed successfully
	if totalFiles != int64(len(files)) {
		t.Errorf("Expected all %d files to be processed", len(files))
	}
}

func TestDumpAnalyzerMemoryStress(t *testing.T) {
	// Create a file that could cause memory issues
	var content strings.Builder
	
	// Very long lines that might cause buffer issues
	for i := 0; i < 1000; i++ {
		content.WriteString("password=")
		content.WriteString(strings.Repeat("a", 10000)) // 10KB per line
		content.WriteString("\n")
	}
	
	tmpFile := createTestFile(t, []byte(content.String()), ".txt")
	defer os.Remove(tmpFile)
	
	analyzer := New(5)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	result, err := analyzer.AnalyzeFile(ctx, tmpFile)
	if err != nil {
		t.Fatalf("Memory stress test failed: %v", err)
	}
	
	// Should handle large lines without issues
	if len(result.Credentials) != 1000 {
		t.Errorf("Expected 1000 items, got %d", len(result.Credentials))
	}
}

func TestDumpAnalyzerCorruptedFiles(t *testing.T) {
	testCases := []struct {
		name    string
		setup   func(string) error
		expectError bool
	}{
		{
			name: "File with permission denied",
			setup: func(path string) error {
				return os.Chmod(path, 0000)
			},
			expectError: true,
		},
		{
			name: "File that gets deleted during analysis",
			setup: func(path string) error {
				go func() {
					time.Sleep(100 * time.Millisecond)
					os.Remove(path)
				}()
				return nil
			},
			expectError: true,
		},
		{
			name: "File with mixed line endings",
			setup: func(path string) error {
				content := "password=secret\r\napi_key=test\ntoken=value\r"
				return os.WriteFile(path, []byte(content), 0644)
			},
			expectError: false,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpFile := createTestFile(t, []byte("initial content"), ".txt")
			defer func() {
				os.Chmod(tmpFile, 0644) // Restore permissions for cleanup
				os.Remove(tmpFile)
			}()
			
			if err := tc.setup(tmpFile); err != nil {
				t.Fatalf("Setup failed: %v", err)
			}
			
			analyzer := New(5)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			
			_, err := analyzer.AnalyzeFile(ctx, tmpFile)
			
			if tc.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}
