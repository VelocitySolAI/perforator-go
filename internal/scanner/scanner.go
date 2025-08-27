package scanner

import (
	"context"
	"fmt"
	"time"

	"perforator-go/internal/api"
	"perforator-go/internal/config"
	"perforator-go/internal/dump"
	"perforator-go/internal/s3"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/sync/errgroup"
)

// ScanRequest represents a scan request
type ScanRequest struct {
	Targets     []string          `json:"targets" xml:"targets>target"`
	Mode        string            `json:"mode" xml:"mode"`
	DumpFiles   []string          `json:"dump_files" xml:"dump_files>dump_file"`
	APIKeys     map[string]string `json:"api_keys" xml:"-"`
	BucketNames []string          `json:"bucket_names" xml:"bucket_names>bucket_name"`
}

// ScanResult represents the complete scan results
type ScanResult struct {
	Request       *ScanRequest              `json:"request" xml:"request"`
	S3Results     []s3.BucketResult         `json:"s3_results,omitempty" xml:"s3_results>bucket,omitempty"`
	DumpResults   []dump.AnalysisResult     `json:"dump_results,omitempty" xml:"dump_results>dump,omitempty"`
	APIResults    []api.ValidationResult    `json:"api_results,omitempty" xml:"api_results>api,omitempty"`
	Summary       *ScanSummary              `json:"summary" xml:"summary"`
	StartTime     time.Time                 `json:"start_time" xml:"start_time"`
	EndTime       time.Time                 `json:"end_time" xml:"end_time"`
	Duration      time.Duration             `json:"duration" xml:"duration"`
}

// ScanSummary provides high-level scan statistics
type ScanSummary struct {
	TotalTargets        int `json:"total_targets"`
	AccessibleBuckets   int `json:"accessible_buckets"`
	SensitiveFiles      int `json:"sensitive_files"`
	CredentialsFound    int `json:"credentials_found"`
	ValidAPIKeys        int `json:"valid_api_keys"`
	CriticalFindings    int `json:"critical_findings"`
	HighRiskFindings    int `json:"high_risk_findings"`
}

// Scanner orchestrates all scanning components
type Scanner struct {
	config        *config.Config
	s3Enum        *s3.Enumerator
	dumpAnalyzer  *dump.Analyzer
	apiValidator  *api.Validator
}

// New creates a new scanner instance
func New(cfg *config.Config) *Scanner {
	return &Scanner{
		config:        cfg,
		s3Enum:        s3.New(cfg.Workers, cfg.Timeout, cfg.RateLimit),
		dumpAnalyzer:  dump.New(cfg.Workers),
		apiValidator:  api.New(cfg.Workers, cfg.RateLimit, cfg.Timeout),
	}
}

// Scan performs the complete security assessment
func (s *Scanner) Scan(ctx context.Context, req *ScanRequest) (*ScanResult, error) {
	result := &ScanResult{
		Request:   req,
		StartTime: time.Now(),
		Summary:   &ScanSummary{},
	}

	defer func() {
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
	}()

	// Progress tracking
	var totalTasks int
	if req.Mode == "full" || req.Mode == "s3" {
		totalTasks += len(req.Targets)
	}
	if req.Mode == "full" || req.Mode == "dump" {
		totalTasks += len(req.DumpFiles)
	}
	if req.Mode == "full" || req.Mode == "api" {
		totalTasks += len(req.APIKeys)
	}

	var bar *progressbar.ProgressBar
	if !s.config.Verbose {
		bar = progressbar.NewOptions(totalTasks,
			progressbar.OptionSetDescription("🔍 Scanning"),
			progressbar.OptionSetPredictTime(true),
			progressbar.OptionShowCount(),
			progressbar.OptionSetRenderBlankState(true),
		)
	}

	// Use errgroup for concurrent execution of different scan types
	g, ctx := errgroup.WithContext(ctx)

	// S3 enumeration
	if (req.Mode == "full" || req.Mode == "s3") && len(req.Targets) > 0 {
		g.Go(func() error {
			return s.scanS3(ctx, req.Targets, req.BucketNames, result, bar)
		})
	}

	// Dump analysis
	if (req.Mode == "full" || req.Mode == "dump") && len(req.DumpFiles) > 0 {
		g.Go(func() error {
			return s.scanDumps(ctx, req.DumpFiles, result, bar)
		})
	}

	// API validation
	if (req.Mode == "full" || req.Mode == "api") && len(req.APIKeys) > 0 {
		g.Go(func() error {
			return s.scanAPIs(ctx, req.APIKeys, result, bar)
		})
	}

	if err := g.Wait(); err != nil {
		return result, err
	}

	if bar != nil {
		bar.Finish()
	}

	// Generate summary
	s.generateSummary(result)

	return result, nil
}

// scanS3 performs S3 bucket enumeration
func (s *Scanner) scanS3(ctx context.Context, targets, bucketNames []string, result *ScanResult, bar *progressbar.ProgressBar) error {
	for _, target := range targets {
		buckets, err := s.s3Enum.EnumerateBuckets(ctx, target, bucketNames)
		if err != nil {
			if s.config.Verbose {
				fmt.Printf("❌ S3 scan failed for %s: %v\n", target, err)
			}
			continue
		}

		result.S3Results = append(result.S3Results, buckets...)

		if s.config.Verbose {
			accessible := 0
			for _, bucket := range buckets {
				if bucket.Accessible {
					accessible++
				}
			}
			fmt.Printf("✅ S3 scan completed for %s: %d/%d buckets accessible\n", 
				target, accessible, len(buckets))
		}

		if bar != nil {
			bar.Add(1)
		}
	}

	return nil
}

// scanDumps performs dump file analysis
func (s *Scanner) scanDumps(ctx context.Context, dumpFiles []string, result *ScanResult, bar *progressbar.ProgressBar) error {
	// Process dump files concurrently
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(s.config.Workers)

	resultChan := make(chan dump.AnalysisResult, len(dumpFiles))

	for _, dumpFile := range dumpFiles {
		dumpFile := dumpFile
		g.Go(func() error {
			analysis, err := s.dumpAnalyzer.AnalyzeFile(ctx, dumpFile)
			if err != nil {
				if s.config.Verbose {
					fmt.Printf("❌ Dump analysis failed for %s: %v\n", dumpFile, err)
				}
				return nil
			}

			resultChan <- *analysis

			if s.config.Verbose {
				fmt.Printf("✅ Dump analysis completed for %s: %d credentials, %d AIX artifacts\n",
					dumpFile, len(analysis.Credentials), len(analysis.AIXArtifacts))
			}

			if bar != nil {
				bar.Add(1)
			}

			return nil
		})
	}

	go func() {
		g.Wait()
		close(resultChan)
	}()

	for analysis := range resultChan {
		result.DumpResults = append(result.DumpResults, analysis)
	}

	return g.Wait()
}

// scanAPIs performs API key validation
func (s *Scanner) scanAPIs(ctx context.Context, apiKeys map[string]string, result *ScanResult, bar *progressbar.ProgressBar) error {
	validations, err := s.apiValidator.ValidateKeys(ctx, apiKeys)
	if err != nil {
		return fmt.Errorf("API validation failed: %w", err)
	}

	result.APIResults = validations

	if s.config.Verbose {
		valid := 0
		for _, validation := range validations {
			if validation.Valid {
				valid++
			}
		}
		fmt.Printf("✅ API validation completed: %d/%d keys valid\n", valid, len(validations))
	}

	if bar != nil {
		bar.Add(len(apiKeys))
	}

	return nil
}

// generateSummary creates a summary of scan results
func (s *Scanner) generateSummary(result *ScanResult) {
	summary := result.Summary

	// S3 statistics
	for _, bucket := range result.S3Results {
		if bucket.Accessible {
			summary.AccessibleBuckets++
		}
		for _, obj := range bucket.Objects {
			if obj.Sensitive {
				summary.SensitiveFiles++
			}
			if obj.RiskLevel == "CRITICAL" {
				summary.CriticalFindings++
			} else if obj.RiskLevel == "HIGH" {
				summary.HighRiskFindings++
			}
		}
	}

	// Dump analysis statistics
	for _, analysis := range result.DumpResults {
		summary.CredentialsFound += len(analysis.Credentials)
		// Consider credentials as critical findings
		summary.CriticalFindings += len(analysis.Credentials)
	}

	// API validation statistics
	for _, validation := range result.APIResults {
		if validation.Valid {
			summary.ValidAPIKeys++
			// Valid API keys are high risk findings
			summary.HighRiskFindings++
		}
	}

	summary.TotalTargets = len(result.Request.Targets)
}
