package config

import (
	"time"
)

// Config holds the application configuration
type Config struct {
	Workers      int           `yaml:"workers" json:"workers"`
	Timeout      time.Duration `yaml:"timeout" json:"timeout"`
	OutputFormat string        `yaml:"output_format" json:"output_format"`
	Verbose      bool          `yaml:"verbose" json:"verbose"`
	RateLimit    int           `yaml:"rate_limit" json:"rate_limit"`
	MaxRetries   int           `yaml:"max_retries" json:"max_retries"`
}

// Default returns a configuration with sensible defaults
func Default() *Config {
	return &Config{
		Workers:      50,
		Timeout:      10 * time.Second,
		OutputFormat: "console",
		Verbose:      false,
		RateLimit:    100, // requests per second
		MaxRetries:   3,
	}
}
