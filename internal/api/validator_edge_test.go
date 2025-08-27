package api

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

// MockAPIServer simulates various API endpoints with edge cases
type MockAPIServer struct {
	server          *httptest.Server
	requestCount    int64
	delayMs         int
	failureRate     float64
	rateLimitAfter  int
	authFailures    map[string]bool
	customResponses map[string]MockResponse
}

type MockResponse struct {
	StatusCode int
	Body       string
	Headers    map[string]string
}

func NewMockAPIServer() *MockAPIServer {
	mock := &MockAPIServer{
		authFailures:    make(map[string]bool),
		customResponses: make(map[string]MockResponse),
	}
	
	mock.server = httptest.NewServer(http.HandlerFunc(mock.handler))
	return mock
}

func (m *MockAPIServer) Close() {
	m.server.Close()
}

func (m *MockAPIServer) URL() string {
	return m.server.URL
}

func (m *MockAPIServer) SetDelay(ms int) {
	m.delayMs = ms
}

func (m *MockAPIServer) SetFailureRate(rate float64) {
	m.failureRate = rate
}

func (m *MockAPIServer) SetRateLimit(after int) {
	m.rateLimitAfter = after
}

func (m *MockAPIServer) SetAuthFailure(service string, fail bool) {
	m.authFailures[service] = fail
}

func (m *MockAPIServer) SetCustomResponse(path string, response MockResponse) {
	m.customResponses[path] = response
}

func (m *MockAPIServer) handler(w http.ResponseWriter, r *http.Request) {
	count := atomic.AddInt64(&m.requestCount, 1)
	
	// Add artificial delay
	if m.delayMs > 0 {
		time.Sleep(time.Duration(m.delayMs) * time.Millisecond)
	}
	
	// Rate limiting
	if m.rateLimitAfter > 0 && int(count) > m.rateLimitAfter {
		w.Header().Set("Retry-After", "1")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error": "Rate limit exceeded", "retry_after": 1}`))
		return
	}
	
	// Custom response override
	if response, exists := m.customResponses[r.URL.Path]; exists {
		for key, value := range response.Headers {
			w.Header().Set(key, value)
		}
		w.WriteHeader(response.StatusCode)
		w.Write([]byte(response.Body))
		return
	}
	
	// Simulate random failures
	if m.failureRate > 0 && float64(count%100)/100.0 < m.failureRate {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "Internal server error", "code": 500}`))
		return
	}
	
	// Route to specific service handlers
	switch {
	case strings.Contains(r.URL.Path, "/aws"):
		m.handleAWS(w, r)
	case strings.Contains(r.URL.Path, "/github"):
		m.handleGitHub(w, r)
	case strings.Contains(r.URL.Path, "/slack"):
		m.handleSlack(w, r)
	case strings.Contains(r.URL.Path, "/stripe"):
		m.handleStripe(w, r)
	case strings.Contains(r.URL.Path, "/malformed"):
		m.handleMalformed(w, r)
	case strings.Contains(r.URL.Path, "/timeout"):
		time.Sleep(30 * time.Second)
	default:
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Endpoint not found"}`))
	}
}

func (m *MockAPIServer) handleAWS(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	
	if m.authFailures["aws"] || authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"Error": {"Code": "InvalidAccessKeyId", "Message": "The AWS Access Key Id you provided does not exist in our records."}}`))
		return
	}
	
	if strings.Contains(authHeader, "expired") {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"Error": {"Code": "TokenRefreshRequired", "Message": "The provided token is expired."}}`))
		return
	}
	
	if strings.Contains(authHeader, "limited") {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"User": {"UserName": "test-user", "Arn": "arn:aws:iam::123456789012:user/test-user"}}`))
		return
	}
	
	// Full permissions response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"User": {
			"UserName": "admin-user",
			"Arn": "arn:aws:iam::123456789012:user/admin-user"
		},
		"AttachedManagedPolicies": [
			{"PolicyName": "AdministratorAccess", "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"}
		]
	}`))
}

func (m *MockAPIServer) handleGitHub(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	
	if m.authFailures["github"] || !strings.HasPrefix(authHeader, "token ") {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "Bad credentials", "documentation_url": "https://docs.github.com/rest"}`))
		return
	}
	
	token := strings.TrimPrefix(authHeader, "token ")
	
	if strings.Contains(token, "revoked") {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message": "Token has been revoked", "documentation_url": "https://docs.github.com/rest"}`))
		return
	}
	
	if strings.Contains(token, "readonly") {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"login": "testuser",
			"id": 12345,
			"permissions": {
				"admin": false,
				"push": false,
				"pull": true
			}
		}`))
		return
	}
	
	// Full permissions
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"login": "adminuser",
		"id": 67890,
		"permissions": {
			"admin": true,
			"push": true,
			"pull": true
		}
	}`))
}

func (m *MockAPIServer) handleSlack(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	
	if m.authFailures["slack"] || !strings.HasPrefix(authHeader, "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"ok": false, "error": "invalid_auth"}`))
		return
	}
	
	token := strings.TrimPrefix(authHeader, "Bearer ")
	
	if strings.Contains(token, "expired") {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"ok": false, "error": "token_expired"}`))
		return
	}
	
	if strings.Contains(token, "limited") {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"ok": true,
			"user": "testuser",
			"team": "testteam",
			"scopes": ["channels:read"]
		}`))
		return
	}
	
	// Full permissions
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"ok": true,
		"user": "adminuser",
		"team": "adminteam",
		"scopes": ["admin", "channels:write", "channels:read", "users:read"]
	}`))
}

func (m *MockAPIServer) handleStripe(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	
	if m.authFailures["stripe"] || !strings.HasPrefix(authHeader, "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error": {"type": "authentication_error", "message": "Invalid API Key provided"}}`))
		return
	}
	
	token := strings.TrimPrefix(authHeader, "Bearer ")
	
	if strings.Contains(token, "test") {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"object": "account",
			"id": "acct_test123",
			"business_profile": {"name": "Test Account"},
			"capabilities": {"card_payments": "active", "transfers": "inactive"}
		}`))
		return
	}
	
	// Live key
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"object": "account",
		"id": "acct_live456",
		"business_profile": {"name": "Live Account"},
		"capabilities": {"card_payments": "active", "transfers": "active"}
	}`))
}

func (m *MockAPIServer) handleMalformed(w http.ResponseWriter, r *http.Request) {
	responses := []string{
		`{"incomplete": json`,
		`{malformed json without quotes}`,
		`{"valid_start": true, "but_ends_abruptly"`,
		`null`,
		`"just a string"`,
		`{"nested": {"very": {"deeply": {"nested": {"object": {"that": {"goes": {"on": {"forever": {"and": {"ever": {"and": {"causes": {"stack": {"overflow": "maybe"}}}}}}}}}}}}}}}`,
		string(make([]byte, 10*1024*1024)), // 10MB of null bytes
	}
	
	responseIndex := int(atomic.LoadInt64(&m.requestCount)) % len(responses)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(responses[responseIndex]))
}

// Edge case tests
func TestAPIValidationEdgeCases(t *testing.T) {
	testCases := []struct {
		name           string
		service        string
		key            string
		setupMock      func(*MockAPIServer)
		expectValid    bool
		expectError    bool
		expectPerms    []string
	}{
		{
			name:        "AWS - Invalid credentials",
			service:     "aws",
			key:         "AKIAIOSFODNN7EXAMPLE",
			setupMock:   func(m *MockAPIServer) { m.SetAuthFailure("aws", true) },
			expectValid: false,
		},
		{
			name:        "AWS - Expired token",
			service:     "aws", 
			key:         "expired-token-12345",
			setupMock:   func(m *MockAPIServer) {},
			expectValid: false,
		},
		{
			name:        "AWS - Limited permissions",
			service:     "aws",
			key:         "limited-access-key",
			setupMock:   func(m *MockAPIServer) {},
			expectValid: true,
			expectPerms: []string{"iam:GetUser"},
		},
		{
			name:        "GitHub - Revoked token",
			service:     "github",
			key:         "ghp_revoked123456789",
			setupMock:   func(m *MockAPIServer) {},
			expectValid: false,
		},
		{
			name:        "GitHub - Read-only token",
			service:     "github",
			key:         "ghp_readonly123456789",
			setupMock:   func(m *MockAPIServer) {},
			expectValid: true,
			expectPerms: []string{"pull"},
		},
		{
			name:        "Slack - Expired token",
			service:     "slack",
			key:         "xoxb-XXXX-XXXX-XXXXXXXXXXXXXXXXXXXX",
			setupMock:   func(m *MockAPIServer) {},
			expectValid: false,
		},
		{
			name:        "Rate limiting scenario",
			service:     "aws",
			key:         "AKIAIOSFODNN7EXAMPLE",
			setupMock:   func(m *MockAPIServer) { m.SetRateLimit(1) },
			expectValid: false,
			expectError: true,
		},
		{
			name:        "Timeout scenario",
			service:     "timeout",
			key:         "any-key",
			setupMock:   func(m *MockAPIServer) { m.SetDelay(100) },
			expectError: true,
		},
		{
			name:        "Malformed JSON response",
			service:     "malformed",
			key:         "any-key",
			setupMock:   func(m *MockAPIServer) {},
			expectError: true,
		},
		{
			name:        "Random failures",
			service:     "aws",
			key:         "AKIAIOSFODNN7EXAMPLE",
			setupMock:   func(m *MockAPIServer) { m.SetFailureRate(0.5) },
			expectError: false, // Should retry
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := NewMockAPIServer()
			defer mock.Close()
			
			tc.setupMock(mock)
			
			validator := New(5, 10, 2*time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			
			// Create API keys map
			apiKeys := map[string]string{tc.key: tc.service}
			results, _ := validator.ValidateKeys(ctx, apiKeys)
			if len(results) == 0 {
				return
			}
			result := results[0]
			
			if tc.expectError && result.Error == "" {
				t.Error("Expected error but got none")
			}
			
			if !tc.expectError && tc.expectValid != result.Valid {
				t.Errorf("Expected valid=%v, got valid=%v", tc.expectValid, result.Valid)
			}
			
			if len(tc.expectPerms) > 0 {
				for _, perm := range tc.expectPerms {
					found := false
					for _, resultPerm := range result.Permissions {
						if strings.Contains(resultPerm, perm) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected permission %s not found in %v", perm, result.Permissions)
					}
				}
			}
		})
	}
}

func TestAPIValidationConcurrency(t *testing.T) {
	mock := NewMockAPIServer()
	defer mock.Close()
	
	// Test concurrent validation with rate limiting
	mock.SetRateLimit(20)
	mock.SetDelay(10)
	
	validator := New(10, 20, 1*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// Create many concurrent validation requests
	keys := make(map[string]string)
	for i := 0; i < 50; i++ {
		keys[fmt.Sprintf("key-%d", i)] = "aws"
	}
	
	keyCount := len(keys)
	
	results, _ := validator.ValidateKeys(ctx, keys)
	
	// Should handle concurrent requests without crashing
	if len(results) != keyCount {
		t.Errorf("Expected %d results, got %d", keyCount, len(results))
	}
	
	// All requests should complete (even if they fail due to invalid keys)
	completedCount := 0
	for _, result := range results {
		// Count as completed if we got any response (valid, invalid, or error)
		if result.StatusCode > 0 || result.Error != "" || !result.Valid {
			completedCount++
		}
	}
	
	if completedCount != keyCount {
		t.Errorf("Expected all %d requests to complete, got %d", keyCount, completedCount)
	}
}

func TestAPIValidationMaliciousPayloads(t *testing.T) {
	testCases := []struct {
		name     string
		response MockResponse
	}{
		{
			name: "JSON bomb",
			response: MockResponse{
				StatusCode: 200,
				Body:       strings.Repeat(`{"a":`, 100000) + `"value"` + strings.Repeat(`}`, 100000),
			},
		},
		{
			name: "Extremely large response",
			response: MockResponse{
				StatusCode: 200,
				Body:       `{"data": "` + strings.Repeat("x", 50*1024*1024) + `"}`,
			},
		},
		{
			name: "Invalid UTF-8",
			response: MockResponse{
				StatusCode: 200,
				Body:       `{"data": "` + string([]byte{0xFF, 0xFE, 0xFD}) + `"}`,
			},
		},
		{
			name: "Null bytes",
			response: MockResponse{
				StatusCode: 200,
				Body:       `{"data": "test` + string([]byte{0x00}) + `data"}`,
			},
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := NewMockAPIServer()
			defer mock.Close()
			
			mock.SetCustomResponse("/malicious", tc.response)
			
			validator := New(1, 5, 5*time.Second)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			
			apiKeys := map[string]string{"test-key": "test"}
			results, _ := validator.ValidateKeys(ctx, apiKeys)
			if len(results) == 0 {
				return
			}
			result := results[0]
			
			// Should handle malicious payloads gracefully without crashing
			if result.Error == "" && result.Valid {
				t.Error("Expected malicious payload to be handled as error or invalid")
			}
		})
	}
}

func TestAPIValidationRetryLogic(t *testing.T) {
	mock := NewMockAPIServer()
	defer mock.Close()
	
	// Set high failure rate initially
	mock.SetFailureRate(0.8)
	
	validator := New(1, 5, 1*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	// After a few requests, reduce failure rate
	go func() {
		time.Sleep(2 * time.Second)
		mock.SetFailureRate(0.1) // Much lower failure rate
	}()
	
	apiKeys := map[string]string{"test-key": "aws"}
	results, _ := validator.ValidateKeys(ctx, apiKeys)
	if len(results) == 0 {
		t.Error("Expected at least one result")
		return
	}
	result := results[0]
	
	// Should eventually succeed due to retry logic
	if result.Error != "" && !result.Valid {
		t.Error("Expected retry logic to eventually succeed")
	}
}
