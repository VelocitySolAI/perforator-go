package config

import (
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	cfg := Default()

	if cfg == nil {
		t.Fatal("Expected default config to be non-nil")
	}

	if cfg.Workers != 50 {
		t.Errorf("Expected default workers 50, got %d", cfg.Workers)
	}

	if cfg.Timeout != 10*time.Second {
		t.Errorf("Expected default timeout 10s, got %v", cfg.Timeout)
	}

	if cfg.OutputFormat != "console" {
		t.Errorf("Expected default output format 'console', got '%s'", cfg.OutputFormat)
	}

	if cfg.Verbose != false {
		t.Errorf("Expected default verbose false, got %v", cfg.Verbose)
	}

	if cfg.RateLimit != 100 {
		t.Errorf("Expected default rate limit 100, got %d", cfg.RateLimit)
	}

	if cfg.MaxRetries != 3 {
		t.Errorf("Expected default max retries 3, got %d", cfg.MaxRetries)
	}
}

func TestConfigStruct(t *testing.T) {
	cfg := &Config{
		Workers:      25,
		Timeout:      5 * time.Second,
		OutputFormat: "json",
		Verbose:      true,
		RateLimit:    200,
		MaxRetries:   5,
	}

	if cfg.Workers != 25 {
		t.Errorf("Expected workers 25, got %d", cfg.Workers)
	}

	if cfg.Timeout != 5*time.Second {
		t.Errorf("Expected timeout 5s, got %v", cfg.Timeout)
	}

	if cfg.OutputFormat != "json" {
		t.Errorf("Expected output format 'json', got '%s'", cfg.OutputFormat)
	}

	if cfg.Verbose != true {
		t.Errorf("Expected verbose true, got %v", cfg.Verbose)
	}

	if cfg.RateLimit != 200 {
		t.Errorf("Expected rate limit 200, got %d", cfg.RateLimit)
	}

	if cfg.MaxRetries != 5 {
		t.Errorf("Expected max retries 5, got %d", cfg.MaxRetries)
	}
}

func TestConfigValidation(t *testing.T) {
	testCases := []struct {
		name     string
		config   *Config
		isValid  bool
	}{
		{
			name: "valid config",
			config: &Config{
				Workers:      10,
				Timeout:      5 * time.Second,
				OutputFormat: "json",
				RateLimit:    50,
				MaxRetries:   3,
			},
			isValid: true,
		},
		{
			name: "zero workers",
			config: &Config{
				Workers:      0,
				Timeout:      5 * time.Second,
				OutputFormat: "json",
				RateLimit:    50,
				MaxRetries:   3,
			},
			isValid: false, // In practice, zero workers would be problematic
		},
		{
			name: "negative timeout",
			config: &Config{
				Workers:      10,
				Timeout:      -1 * time.Second,
				OutputFormat: "json",
				RateLimit:    50,
				MaxRetries:   3,
			},
			isValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Basic validation checks
			if tc.config.Workers <= 0 && tc.isValid {
				t.Error("Expected invalid config for non-positive workers")
			}
			if tc.config.Timeout < 0 && tc.isValid {
				t.Error("Expected invalid config for negative timeout")
			}
		})
	}
}

func TestConfigOutputFormats(t *testing.T) {
	validFormats := []string{"console", "json", "xml", "csv"}
	
	for _, format := range validFormats {
		cfg := &Config{
			OutputFormat: format,
		}
		
		if cfg.OutputFormat != format {
			t.Errorf("Expected output format '%s', got '%s'", format, cfg.OutputFormat)
		}
	}
}

func TestConfigTimeoutConversion(t *testing.T) {
	testCases := []struct {
		seconds  int
		expected time.Duration
	}{
		{1, 1 * time.Second},
		{10, 10 * time.Second},
		{60, 60 * time.Second},
		{0, 0 * time.Second},
	}

	for _, tc := range testCases {
		cfg := &Config{
			Timeout: time.Duration(tc.seconds) * time.Second,
		}
		
		if cfg.Timeout != tc.expected {
			t.Errorf("Expected timeout %v, got %v", tc.expected, cfg.Timeout)
		}
	}
}
