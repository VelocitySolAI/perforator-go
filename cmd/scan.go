package cmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"perforator-go/internal/scanner"
	"perforator-go/internal/config"
	outputpkg "perforator-go/internal/output"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	targets     []string
	scanMode    string
	dumpFiles   []string
	apiKeys     []string
	bucketNames []string
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run comprehensive security scan",
	Long: `Run a comprehensive security assessment with concurrent processing.

Supports multiple scan modes:
• s3      - S3 bucket enumeration only
• dump    - Dump file analysis only  
• api     - API key validation only
• full    - Complete assessment (default)

Examples:
  perforator-go scan --target https://s3.example.com --mode s3
  perforator-go scan --target https://api.example.com --dump ./dump.bz2 --mode full
  perforator-go scan --target https://storage.example.com --api-key amplitude:key123 --workers 100`,
	RunE: runScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringSliceVarP(&targets, "target", "T", []string{}, "target URLs (can specify multiple)")
	scanCmd.Flags().StringVarP(&scanMode, "mode", "m", "full", "scan mode (s3, dump, api, full)")
	scanCmd.Flags().StringSliceVar(&dumpFiles, "dump", []string{}, "dump files to analyze")
	scanCmd.Flags().StringSliceVar(&apiKeys, "api-key", []string{}, "API keys to validate (format: service:key)")
	scanCmd.Flags().StringSliceVar(&bucketNames, "bucket", []string{}, "specific bucket names to target")

	scanCmd.MarkFlagRequired("target")
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Parse configuration
	cfg := &config.Config{
		Workers:     viper.GetInt("workers"),
		Timeout:     time.Duration(viper.GetInt("timeout")) * time.Second,
		OutputFormat: viper.GetString("output"),
		Verbose:     verbose,
	}

	// Parse API keys
	apiKeyMap := make(map[string]string)
	for _, keyPair := range apiKeys {
		parts := strings.SplitN(keyPair, ":", 2)
		if len(parts) == 2 {
			apiKeyMap[parts[0]] = parts[1]
		}
	}

	// Initialize scanner
	s := scanner.New(cfg)

	// Create scan request
	req := &scanner.ScanRequest{
		Targets:     targets,
		Mode:        scanMode,
		DumpFiles:   dumpFiles,
		APIKeys:     apiKeyMap,
		BucketNames: bucketNames,
	}

	if cfg.Verbose {
		fmt.Printf("🚀 Starting %s scan with %d workers\n", 
			color.YellowString(strings.ToUpper(scanMode)), cfg.Workers)
		fmt.Printf("📊 Targets: %d | Timeout: %v\n", len(targets), cfg.Timeout)
	}

	// Run scan
	results, err := s.Scan(ctx, req)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Output results
	outputter := outputpkg.New(cfg.OutputFormat)
	return outputter.Write(results)
}
