package s3

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	workers := 10
	timeout := 5 * time.Second
	rateLimit := 50

	enum := New(workers, timeout, rateLimit)

	if enum.workers != workers {
		t.Errorf("Expected workers %d, got %d", workers, enum.workers)
	}
	if enum.timeout != timeout {
		t.Errorf("Expected timeout %v, got %v", timeout, enum.timeout)
	}
	if enum.client.Timeout != timeout {
		t.Errorf("Expected client timeout %v, got %v", timeout, enum.client.Timeout)
	}
}

func TestEnumerateBuckets(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/accessible") {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	enum := New(5, 2*time.Second, 10)
	bucketNames := []string{"accessible", "notfound", "test"}

	ctx := context.Background()
	results, err := enum.EnumerateBuckets(ctx, server.URL, bucketNames)

	if err != nil {
		t.Fatalf("EnumerateBuckets failed: %v", err)
	}

	if len(results) != len(bucketNames) {
		t.Errorf("Expected %d results, got %d", len(bucketNames), len(results))
	}

	// Check accessible bucket
	found := false
	for _, result := range results {
		if result.Name == "accessible" && result.Accessible {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected 'accessible' bucket to be marked as accessible")
	}
}

func TestEnumerateBucketsWithDefaultNames(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	enum := New(5, 1*time.Second, 10)
	ctx := context.Background()
	
	// Test with empty bucket names (should use defaults)
	results, err := enum.EnumerateBuckets(ctx, server.URL, nil)

	if err != nil {
		t.Fatalf("EnumerateBuckets with default names failed: %v", err)
	}

	defaultNames := getCommonBucketNames()
	if len(results) != len(defaultNames) {
		t.Errorf("Expected %d results, got %d", len(defaultNames), len(results))
	}
}

func TestCheckBucket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "HEAD" {
			w.WriteHeader(http.StatusOK)
		} else if r.Method == "GET" && strings.Contains(r.URL.RawQuery, "list-type=2") {
			// Return XML response
			xml := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Name>test-bucket</Name>
    <Contents>
        <Key>test.txt</Key>
        <Size>1024</Size>
        <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    </Contents>
    <Contents>
        <Key>secret.env</Key>
        <Size>512</Size>
        <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    </Contents>
</ListBucketResult>`
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(xml))
		}
	}))
	defer server.Close()

	enum := New(5, 2*time.Second, 10)
	ctx := context.Background()
	
	result := enum.checkBucket(ctx, server.URL, "test-bucket")

	if !result.Accessible {
		t.Error("Expected bucket to be accessible")
	}
	if result.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, result.StatusCode)
	}
	if len(result.Objects) != 2 {
		t.Errorf("Expected 2 objects, got %d", len(result.Objects))
	}

	// Check sensitive file detection
	foundSensitive := false
	for _, obj := range result.Objects {
		if obj.Key == "secret.env" && obj.Sensitive {
			foundSensitive = true
			break
		}
	}
	if !foundSensitive {
		t.Error("Expected secret.env to be marked as sensitive")
	}
}

func TestParseS3Response(t *testing.T) {
	enum := New(5, 2*time.Second, 10)
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Name>test-bucket</Name>
    <Contents>
        <Key>file1.txt</Key>
        <Size>1024</Size>
        <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    </Contents>
    <Contents>
        <Key>config.json</Key>
        <Size>512</Size>
        <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    </Contents>
</ListBucketResult>`

	objects, err := enum.parseS3Response(xml, "https://example.com/bucket")
	if err != nil {
		t.Fatalf("parseS3Response failed: %v", err)
	}

	if len(objects) != 2 {
		t.Errorf("Expected 2 objects, got %d", len(objects))
	}

	// Check sensitive file detection
	configFound := false
	for _, obj := range objects {
		if obj.Key == "config.json" {
			configFound = true
			if !obj.Sensitive {
				t.Error("Expected config.json to be marked as sensitive")
			}
			if obj.RiskLevel != "HIGH" {
				t.Errorf("Expected HIGH risk level, got %s", obj.RiskLevel)
			}
		}
	}
	if !configFound {
		t.Error("config.json not found in parsed objects")
	}
}

func TestBruteForceObjects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, ".env") {
			w.Header().Set("Content-Length", "256")
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	enum := New(5, 1*time.Second, 20)
	ctx := context.Background()
	
	objects := enum.bruteForceObjects(ctx, server.URL)

	// Should find at least one .env file
	envFound := false
	for _, obj := range objects {
		if strings.Contains(obj.Key, ".env") {
			envFound = true
			if !obj.Sensitive {
				t.Error("Expected .env file to be marked as sensitive")
			}
			if obj.Size != 256 {
				t.Errorf("Expected size 256, got %d", obj.Size)
			}
		}
	}
	if !envFound {
		t.Error("Expected to find .env file in brute force results")
	}
}

func TestIsSensitiveFile(t *testing.T) {
	testCases := []struct {
		filename  string
		sensitive bool
	}{
		{".env", true},
		{"config.json", true},
		{"secret.txt", true},
		{"id_rsa", true},
		{"password.txt", true},
		{"backup.sql", true},
		{"normal.txt", false},
		{"readme.md", false},
		{"index.html", false},
	}

	for _, tc := range testCases {
		result := isSensitiveFile(tc.filename)
		if result != tc.sensitive {
			t.Errorf("isSensitiveFile(%s) = %v, expected %v", tc.filename, result, tc.sensitive)
		}
	}
}

func TestAssessRiskLevel(t *testing.T) {
	testCases := []struct {
		filename string
		risk     string
	}{
		{"id_rsa", "CRITICAL"},
		{"private.key", "CRITICAL"},
		{".env", "CRITICAL"},
		{"secret.txt", "CRITICAL"},
		{"password.txt", "CRITICAL"},
		{"config.json", "HIGH"},
		{"database.sql", "HIGH"},
		{"backup.zip", "HIGH"},
		{"normal.txt", "MEDIUM"},
		{"readme.md", "MEDIUM"},
	}

	for _, tc := range testCases {
		result := assessRiskLevel(tc.filename)
		if result != tc.risk {
			t.Errorf("assessRiskLevel(%s) = %s, expected %s", tc.filename, result, tc.risk)
		}
	}
}

func TestGetCommonBucketNames(t *testing.T) {
	names := getCommonBucketNames()
	
	if len(names) == 0 {
		t.Error("Expected non-empty list of common bucket names")
	}

	// Check for some expected names
	expectedNames := []string{"assets", "uploads", "backups", "config", "admin"}
	for _, expected := range expectedNames {
		found := false
		for _, name := range names {
			if name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected to find '%s' in common bucket names", expected)
		}
	}
}

func TestGetSensitiveFileNames(t *testing.T) {
	names := getSensitiveFileNames()
	
	if len(names) == 0 {
		t.Error("Expected non-empty list of sensitive file names")
	}

	// Check for some expected names
	expectedNames := []string{".env", "config.json", "id_rsa", "secrets.json"}
	for _, expected := range expectedNames {
		found := false
		for _, name := range names {
			if name == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected to find '%s' in sensitive file names", expected)
		}
	}
}

func TestContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	enum := New(5, 1*time.Second, 10)
	
	// Create context that cancels quickly
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	bucketNames := []string{"test1", "test2", "test3"}
	results, err := enum.EnumerateBuckets(ctx, server.URL, bucketNames)

	// Should handle context cancellation gracefully
	if err != nil && err != context.DeadlineExceeded {
		t.Errorf("Unexpected error: %v", err)
	}

	// Results should still be returned (may be partial)
	if results == nil {
		t.Error("Expected results even with context cancellation")
	}
}
