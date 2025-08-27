package s3

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// MockS3Server provides various edge case scenarios for testing
type MockS3Server struct {
	server          *httptest.Server
	requestCount    int64
	delayMs         int
	failureRate     float64
	malformedXML    bool
	rateLimitAfter  int
	customResponses map[string]string
}

func NewMockS3Server() *MockS3Server {
	mock := &MockS3Server{
		customResponses: make(map[string]string),
	}
	
	mock.server = httptest.NewServer(http.HandlerFunc(mock.handler))
	return mock
}

func (m *MockS3Server) Close() {
	m.server.Close()
}

func (m *MockS3Server) URL() string {
	return m.server.URL
}

func (m *MockS3Server) SetDelay(ms int) {
	m.delayMs = ms
}

func (m *MockS3Server) SetFailureRate(rate float64) {
	m.failureRate = rate
}

func (m *MockS3Server) SetMalformedXML(enabled bool) {
	m.malformedXML = enabled
}

func (m *MockS3Server) SetRateLimit(after int) {
	m.rateLimitAfter = after
}

func (m *MockS3Server) SetCustomResponse(path, response string) {
	m.customResponses[path] = response
}

func (m *MockS3Server) handler(w http.ResponseWriter, r *http.Request) {
	count := atomic.AddInt64(&m.requestCount, 1)
	
	// Add artificial delay if configured
	if m.delayMs > 0 {
		time.Sleep(time.Duration(m.delayMs) * time.Millisecond)
	}
	
	// Rate limiting simulation
	if m.rateLimitAfter > 0 && int(count) > m.rateLimitAfter {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>SlowDown</Code>
    <Message>Please reduce your request rate</Message>
</Error>`))
		return
	}
	
	// Custom response override
	if response, exists := m.customResponses[r.URL.Path]; exists {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(response))
		return
	}
	
	// Simulate random failures
	if m.failureRate > 0 && float64(count%100)/100.0 < m.failureRate {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>InternalError</Code>
    <Message>We encountered an internal error. Please try again.</Message>
</Error>`))
		return
	}
	
	// Handle different bucket scenarios
	bucketName := strings.TrimPrefix(r.URL.Path, "/")
	if bucketName == "" {
		bucketName = r.Host
	}
	
	switch {
	case strings.Contains(bucketName, "timeout"):
		// Simulate timeout by sleeping longer than expected
		time.Sleep(30 * time.Second)
		
	case strings.Contains(bucketName, "forbidden"):
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>AccessDenied</Code>
    <Message>Access Denied</Message>
</Error>`))
		
	case strings.Contains(bucketName, "notfound"):
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
    <Code>NoSuchBucket</Code>
    <Message>The specified bucket does not exist</Message>
</Error>`))
		
	case strings.Contains(bucketName, "malformed"):
		w.WriteHeader(http.StatusOK)
		if m.malformedXML {
			w.Write([]byte(`<ListBucketResult><Contents><Key>test.txt</Key><Size>invalid</Size></Contents>`))
		} else {
			w.Write([]byte(`not xml at all`))
		}
		
	case strings.Contains(bucketName, "empty"):
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Name>` + bucketName + `</Name>
    <IsTruncated>false</IsTruncated>
</ListBucketResult>`))
		
	case strings.Contains(bucketName, "large"):
		// Generate large response with many objects
		w.WriteHeader(http.StatusOK)
		response := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Name>` + bucketName + `</Name>
    <IsTruncated>false</IsTruncated>`
		
		for i := 0; i < 10000; i++ {
			response += fmt.Sprintf(`
    <Contents>
        <Key>file_%d.txt</Key>
        <Size>%d</Size>
        <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    </Contents>`, i, i*1024)
		}
		response += `
</ListBucketResult>`
		w.Write([]byte(response))
		
	case strings.Contains(bucketName, "sensitive"):
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Name>` + bucketName + `</Name>
    <IsTruncated>false</IsTruncated>
    <Contents>
        <Key>passwords.txt</Key>
        <Size>1024</Size>
        <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    </Contents>
    <Contents>
        <Key>secrets/api_keys.json</Key>
        <Size>2048</Size>
        <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    </Contents>
    <Contents>
        <Key>backup/database.sql</Key>
        <Size>1048576</Size>
        <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    </Contents>
</ListBucketResult>`))
		
	default:
		// Default successful response
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Name>` + bucketName + `</Name>
    <IsTruncated>false</IsTruncated>
    <Contents>
        <Key>test.txt</Key>
        <Size>1024</Size>
        <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    </Contents>
</ListBucketResult>`))
	}
}

// Edge case tests
func TestS3EdgeCases(t *testing.T) {
	testCases := []struct {
		name           string
		bucketName     string
		setupMock      func(*MockS3Server)
		expectError    bool
		expectObjects  int
		expectSensitive bool
	}{
		{
			name:        "Timeout handling",
			bucketName:  "timeout-bucket",
			setupMock:   func(m *MockS3Server) { m.SetDelay(100) },
			expectError: true,
		},
		{
			name:        "Rate limiting",
			bucketName:  "test-bucket",
			setupMock:   func(m *MockS3Server) { m.SetRateLimit(2) },
			expectError: false, // Should retry and succeed
		},
		{
			name:        "Malformed XML response",
			bucketName:  "malformed-bucket",
			setupMock:   func(m *MockS3Server) { m.SetMalformedXML(true) },
			expectError: true,
		},
		{
			name:        "Non-XML response",
			bucketName:  "malformed-bucket",
			setupMock:   func(m *MockS3Server) { m.SetMalformedXML(false) },
			expectError: true,
		},
		{
			name:          "Empty bucket",
			bucketName:    "empty-bucket",
			setupMock:     func(m *MockS3Server) {},
			expectError:   false,
			expectObjects: 0,
		},
		{
			name:          "Large response",
			bucketName:    "large-bucket",
			setupMock:     func(m *MockS3Server) {},
			expectError:   false,
			expectObjects: 10000,
		},
		{
			name:            "Sensitive files detection",
			bucketName:      "sensitive-bucket",
			setupMock:       func(m *MockS3Server) {},
			expectError:     false,
			expectObjects:   3,
			expectSensitive: true,
		},
		{
			name:        "Forbidden access",
			bucketName:  "forbidden-bucket",
			setupMock:   func(m *MockS3Server) {},
			expectError: false, // Should handle gracefully
		},
		{
			name:        "Bucket not found",
			bucketName:  "notfound-bucket",
			setupMock:   func(m *MockS3Server) {},
			expectError: false, // Should handle gracefully
		},
		{
			name:        "Random failures",
			bucketName:  "test-bucket",
			setupMock:   func(m *MockS3Server) { m.SetFailureRate(0.3) },
			expectError: false, // Should retry and eventually succeed
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := NewMockS3Server()
			defer mock.Close()
			
			tc.setupMock(mock)
			
			enumerator := New(5, 2*time.Second, 10)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			
			results, _ := enumerator.EnumerateBuckets(ctx, mock.URL(), []string{tc.bucketName})
			if len(results) == 0 {
				return
			}
			result := results[0]
			
			if tc.expectError && result.Accessible {
				t.Errorf("Expected error but bucket was accessible")
			}
			
			if !tc.expectError && tc.expectObjects > 0 && len(result.Objects) != tc.expectObjects {
				t.Errorf("Expected %d objects, got %d", tc.expectObjects, len(result.Objects))
			}
			
			if tc.expectSensitive {
				sensitiveCount := 0
				for _, obj := range result.Objects {
					if obj.Sensitive {
						sensitiveCount++
					}
				}
				if sensitiveCount == 0 {
					t.Error("Expected to find sensitive files but none were detected")
				}
			}
		})
	}
}

func TestS3ConcurrencyEdgeCases(t *testing.T) {
	mock := NewMockS3Server()
	defer mock.Close()
	
	// Test high concurrency with rate limiting
	mock.SetRateLimit(10)
	mock.SetDelay(50)
	
	enumerator := New(20, 1*time.Second, 10) // High concurrency
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	buckets := make([]string, 50)
	for i := 0; i < 50; i++ {
		buckets[i] = fmt.Sprintf("test-bucket-%d", i)
	}
	
	results, _ := enumerator.EnumerateBuckets(ctx, mock.URL(), buckets)
	
	// Should handle rate limiting gracefully
	successCount := 0
	for _, result := range results {
		if result.Accessible || result.StatusCode == http.StatusForbidden || result.StatusCode == http.StatusNotFound {
			successCount++
		}
	}
	
	// Should have reasonable success rate (at least 20% due to intentional failures)
	bucketCount := len(buckets)
	successRate := float64(successCount) / float64(bucketCount)
	if successRate < 0.2 {
		t.Errorf("Too many failures: only %d out of %d succeeded", successCount, bucketCount)
	}
}

func TestS3MemoryStress(t *testing.T) {
	mock := NewMockS3Server()
	defer mock.Close()
	
	// Create a response with extremely large object list
	largeResponse := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Name>stress-bucket</Name>
    <IsTruncated>false</IsTruncated>`
	
	for i := 0; i < 100000; i++ {
		largeResponse += fmt.Sprintf(`
    <Contents>
        <Key>very_long_filename_that_takes_up_memory_%d_with_lots_of_extra_characters.txt</Key>
        <Size>%d</Size>
        <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    </Contents>`, i, i*1024)
	}
	largeResponse += `
</ListBucketResult>`
	
	mock.SetCustomResponse("/stress-bucket", largeResponse)
	
	enumerator := New(1, 30*time.Second, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	results, _ := enumerator.EnumerateBuckets(ctx, mock.URL(), []string{"stress-bucket"})
	if len(results) == 0 {
		t.Error("Expected at least one result")
		return
	}
	result := results[0]
	
	if !result.Accessible {
		t.Error("Expected bucket to be accessible despite large response")
	}
	
	if len(result.Objects) != 100000 {
		t.Errorf("Expected 100000 objects, got %d", len(result.Objects))
	}
}

func TestS3MaliciousPayloads(t *testing.T) {
	testCases := []struct {
		name     string
		payload  string
		expectError bool
	}{
		{
			name: "XML bomb attempt",
			payload: `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<ListBucketResult>&lol2;</ListBucketResult>`,
			expectError: true,
		},
		{
			name: "Extremely nested XML",
			payload: strings.Repeat("<Contents>", 10000) + "<Key>test</Key>" + strings.Repeat("</Contents>", 10000),
			expectError: true,
		},
		{
			name: "Invalid UTF-8 sequences",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Contents>
        <Key>` + string([]byte{0xFF, 0xFE, 0xFD}) + `</Key>
    </Contents>
</ListBucketResult>`,
			expectError: true,
		},
		{
			name: "Null bytes in XML",
			payload: `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Contents>
        <Key>test` + string([]byte{0x00}) + `file</Key>
    </Contents>
</ListBucketResult>`,
			expectError: true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := NewMockS3Server()
			defer mock.Close()
			
			// Set up mock server to return malicious payload with 200 status
			mock.SetCustomResponse("/malicious-bucket?list-type=2&max-keys=1000", tc.payload)
			mock.SetCustomResponse("/malicious-bucket?max-keys=1000", tc.payload)
			mock.SetCustomResponse("/malicious-bucket", tc.payload)
			
			enumerator := New(1, 5*time.Second, 5)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			
			results, _ := enumerator.EnumerateBuckets(ctx, mock.URL(), []string{"malicious-bucket"})
			if len(results) == 0 {
				return
			}
			result := results[0]
			
			// Check if the advanced algorithms detected the malicious payload
			if tc.expectError {
				if result.Accessible && len(result.Objects) > 0 {
					t.Error("Expected malicious payload to be rejected by advanced XML detection")
				} else if result.Error == "" {
					t.Error("Expected error message from advanced XML bomb detection")
				}
			}
		})
	}
}
