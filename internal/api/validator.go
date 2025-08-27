package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// ValidationResult represents API key validation result
type ValidationResult struct {
	Service     string            `json:"service" xml:"service"`
	Key         string            `json:"key,omitempty" xml:"key,omitempty"`
	Valid       bool              `json:"valid" xml:"valid"`
	StatusCode  int               `json:"status_code" xml:"status_code"`
	Response    string            `json:"response,omitempty" xml:"response,omitempty"`
	Permissions []string          `json:"permissions,omitempty" xml:"permissions>permission,omitempty"`
	Error       string            `json:"error,omitempty" xml:"error,omitempty"`
	TestTime    time.Time         `json:"test_time" xml:"test_time"`
	Metadata    map[string]string `json:"metadata,omitempty" xml:"-"`
}

// Validator handles API key validation with connection pooling
type Validator struct {
	client      *http.Client
	rateLimiter *rate.Limiter
	workers     int
}

// New creates a new API validator with optimized HTTP client
func New(workers int, rateLimit int, timeout time.Duration) *Validator {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        50,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
		},
	}

	return &Validator{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Limit(rateLimit), rateLimit),
		workers:     workers,
	}
}

// ValidateKeys validates multiple API keys concurrently
func (v *Validator) ValidateKeys(ctx context.Context, apiKeys map[string]string) ([]ValidationResult, error) {
	if len(apiKeys) == 0 {
		return nil, nil
	}

	results := make([]ValidationResult, 0, len(apiKeys))
	var mu sync.Mutex

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(v.workers)

	for service, key := range apiKeys {
		service, key := service, key // capture loop variables
		g.Go(func() error {
			result := v.validateKey(ctx, service, key)
			
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
			
			return nil
		})
	}

	return results, g.Wait()
}

// validateKey validates a single API key based on service type
func (v *Validator) validateKey(ctx context.Context, service, key string) ValidationResult {
	result := ValidationResult{
		Service:  service,
		Key:      maskKey(key),
		TestTime: time.Now(),
		Metadata: make(map[string]string),
	}

	// Rate limiting
	if err := v.rateLimiter.Wait(ctx); err != nil {
		result.Error = fmt.Sprintf("rate limit error: %v", err)
		return result
	}

	switch strings.ToLower(service) {
	case "amplitude":
		return v.validateAmplitude(ctx, key, result)
	case "yandex", "yandex-metrika":
		return v.validateYandex(ctx, key, result)
	case "smartcaptcha", "yandex-captcha":
		return v.validateSmartCaptcha(ctx, key, result)
	case "github":
		return v.validateGitHub(ctx, key, result)
	case "aws":
		return v.validateAWS(ctx, key, result)
	case "google", "gcp":
		return v.validateGoogle(ctx, key, result)
	default:
		return v.validateGeneric(ctx, service, key, result)
	}
}

// validateAmplitude validates Amplitude API keys
func (v *Validator) validateAmplitude(ctx context.Context, key string, result ValidationResult) ValidationResult {
	// Try server-side API first
	req, err := http.NewRequestWithContext(ctx, "GET", "https://amplitude.com/api/2/export", nil)
	if err != nil {
		result.Error = fmt.Sprintf("request creation failed: %v", err)
		return result
	}
	
	req.SetBasicAuth(key, "")
	req.Header.Set("User-Agent", "Perforator-Go/2.0")
	
	// Add test parameters
	q := req.URL.Query()
	q.Add("start", "20240101T00")
	q.Add("end", "20240101T01")
	req.URL.RawQuery = q.Encode()

	resp, err := v.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Valid = resp.StatusCode != 401 && resp.StatusCode != 403

	if result.Valid {
		result.Permissions = []string{"export", "analytics"}
		result.Metadata["endpoint"] = "server-side"
	}

	// If server-side fails, try client-side API
	if !result.Valid {
		return v.validateAmplitudeClient(ctx, key, result)
	}

	return result
}

// validateAmplitudeClient validates Amplitude client-side API
func (v *Validator) validateAmplitudeClient(ctx context.Context, key string, result ValidationResult) ValidationResult {
	testEvent := map[string]interface{}{
		"api_key": key,
		"events": []map[string]interface{}{
			{
				"user_id":    "perforator_test",
				"event_type": "validation_test",
				"time":       time.Now().Unix() * 1000,
			},
		},
	}

	jsonData, err := json.Marshal(testEvent)
	if err != nil {
		result.Error = fmt.Sprintf("JSON marshal failed: %v", err)
		return result
	}

	req, err := http.NewRequestWithContext(ctx, "POST", "https://api2.amplitude.com/2/httpapi", strings.NewReader(string(jsonData)))
	if err != nil {
		result.Error = fmt.Sprintf("request creation failed: %v", err)
		return result
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Perforator-Go/2.0")

	resp, err := v.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Valid = resp.StatusCode == 200

	if result.Valid {
		result.Permissions = []string{"events", "tracking"}
		result.Metadata["endpoint"] = "client-side"
	}

	return result
}

// validateYandex validates Yandex Metrika API keys
func (v *Validator) validateYandex(ctx context.Context, key string, result ValidationResult) ValidationResult {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api-metrika.yandex.net/management/v1/counters", nil)
	if err != nil {
		result.Error = fmt.Sprintf("request creation failed: %v", err)
		return result
	}

	req.Header.Set("Authorization", fmt.Sprintf("OAuth %s", key))
	req.Header.Set("User-Agent", "Perforator-Go/2.0")

	resp, err := v.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Valid = resp.StatusCode == 200

	if result.Valid {
		result.Permissions = []string{"counters", "analytics"}
	}

	return result
}

// validateSmartCaptcha validates Yandex SmartCaptcha keys
func (v *Validator) validateSmartCaptcha(ctx context.Context, key string, result ValidationResult) ValidationResult {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://smartcaptcha.yandexcloud.net/backend.636bb879d1085041b.html", nil)
	if err != nil {
		result.Error = fmt.Sprintf("request creation failed: %v", err)
		return result
	}

	q := req.URL.Query()
	q.Add("sitekey", key)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("User-Agent", "Perforator-Go/2.0")

	resp, err := v.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Valid = resp.StatusCode == 200

	return result
}

// validateGitHub validates GitHub API tokens
func (v *Validator) validateGitHub(ctx context.Context, key string, result ValidationResult) ValidationResult {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.github.com/user", nil)
	if err != nil {
		result.Error = fmt.Sprintf("request creation failed: %v", err)
		return result
	}

	req.Header.Set("Authorization", fmt.Sprintf("token %s", key))
	req.Header.Set("User-Agent", "Perforator-Go/2.0")

	resp, err := v.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Valid = resp.StatusCode == 200

	if result.Valid {
		// Check scopes from response headers
		if scopes := resp.Header.Get("X-OAuth-Scopes"); scopes != "" {
			result.Permissions = strings.Split(scopes, ", ")
		}
	}

	return result
}

// validateAWS validates AWS access keys (basic check)
func (v *Validator) validateAWS(ctx context.Context, key string, result ValidationResult) ValidationResult {
	// AWS validation requires more complex setup with secret key
	// This is a basic format validation
	if len(key) == 20 && strings.HasPrefix(key, "AKIA") {
		result.Valid = true
		result.StatusCode = 200
		result.Metadata["format"] = "valid"
		result.Response = "Key format appears valid (full validation requires secret key)"
	} else {
		result.Valid = false
		result.StatusCode = 400
		result.Error = "Invalid AWS access key format"
	}

	return result
}

// validateGoogle validates Google API keys
func (v *Validator) validateGoogle(ctx context.Context, key string, result ValidationResult) ValidationResult {
	// Try Google API key validation endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s", key), nil)
	if err != nil {
		result.Error = fmt.Sprintf("request creation failed: %v", err)
		return result
	}

	req.Header.Set("User-Agent", "Perforator-Go/2.0")

	resp, err := v.client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	result.Valid = resp.StatusCode == 200

	return result
}

// validateGeneric performs generic API key validation
func (v *Validator) validateGeneric(ctx context.Context, service, key string, result ValidationResult) ValidationResult {
	result.Error = fmt.Sprintf("validation not implemented for service: %s", service)
	result.StatusCode = 0
	result.Valid = false
	return result
}

// maskKey masks sensitive parts of API key for logging
func maskKey(key string) string {
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	return key[:4] + strings.Repeat("*", len(key)-8) + key[len(key)-4:]
}
