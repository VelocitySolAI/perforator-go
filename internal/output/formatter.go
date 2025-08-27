package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"

	"perforator-go/internal/scanner"

	"github.com/fatih/color"
)

// Formatter handles different output formats
type Formatter struct {
	format string
}

// New creates a new output formatter
func New(format string) *Formatter {
	return &Formatter{format: format}
}

// Write outputs the scan results in the specified format
func (f *Formatter) Write(result *scanner.ScanResult) error {
	switch strings.ToLower(f.format) {
	case "json":
		return f.writeJSON(result)
	case "xml":
		return f.writeXML(result)
	case "csv":
		return f.writeCSV(result)
	default:
		return f.writeConsole(result)
	}
}

// writeJSON outputs results in JSON format
func (f *Formatter) writeJSON(result *scanner.ScanResult) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

// writeXML outputs results in XML format
func (f *Formatter) writeXML(result *scanner.ScanResult) error {
	output, err := xml.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n%s\n", output)
	return nil
}

// writeCSV outputs results in CSV format
func (f *Formatter) writeCSV(result *scanner.ScanResult) error {
	fmt.Println("Type,Target,Status,Risk Level,Details")
	
	// S3 results
	for _, bucket := range result.S3Results {
		status := "Inaccessible"
		if bucket.Accessible {
			status = "Accessible"
		}
		fmt.Printf("S3,%s,%s,HIGH,Bucket enumeration\n", bucket.Name, status)
		
		for _, obj := range bucket.Objects {
			fmt.Printf("S3Object,%s,%s,%s,%s\n", obj.Key, "Found", obj.RiskLevel, obj.URL)
		}
	}
	
	// Dump results
	for _, dump := range result.DumpResults {
		for _, cred := range dump.Credentials {
			fmt.Printf("Credential,%s,Found,CRITICAL,%s\n", cred.Type, cred.Value)
		}
	}
	
	// API results
	for _, api := range result.APIResults {
		status := "Invalid"
		risk := "LOW"
		if api.Valid {
			status = "Valid"
			risk = "HIGH"
		}
		fmt.Printf("API,%s,%s,%s,%s\n", api.Service, status, risk, api.Key)
	}
	
	return nil
}

// writeConsole outputs results in formatted console output
func (f *Formatter) writeConsole(result *scanner.ScanResult) error {
	fmt.Println()
	fmt.Println(color.CyanString(strings.Repeat("=", 80)))
	fmt.Println(color.CyanString("🎯 PERFORATOR-GO SCAN RESULTS"))
	fmt.Println(color.CyanString(strings.Repeat("=", 80)))
	
	// Summary
	fmt.Printf("\n📊 %s\n", color.YellowString("SCAN SUMMARY"))
	fmt.Printf("   Duration: %v\n", result.Duration.Round(time.Second))
	fmt.Printf("   Targets: %d\n", result.Summary.TotalTargets)
	fmt.Printf("   Accessible Buckets: %s\n", formatCount(result.Summary.AccessibleBuckets))
	fmt.Printf("   Sensitive Files: %s\n", formatCount(result.Summary.SensitiveFiles))
	fmt.Printf("   Credentials Found: %s\n", formatCount(result.Summary.CredentialsFound))
	fmt.Printf("   Valid API Keys: %s\n", formatCount(result.Summary.ValidAPIKeys))
	fmt.Printf("   Critical Findings: %s\n", formatCritical(result.Summary.CriticalFindings))
	fmt.Printf("   High Risk Findings: %s\n", formatHigh(result.Summary.HighRiskFindings))
	
	// S3 Results
	if len(result.S3Results) > 0 {
		fmt.Printf("\n🪣 %s\n", color.YellowString("S3 ENUMERATION RESULTS"))
		for _, bucket := range result.S3Results {
			if bucket.Accessible {
				fmt.Printf("   ✅ %s (Status: %d, Objects: %d)\n", 
					color.GreenString(bucket.Name), bucket.StatusCode, len(bucket.Objects))
				
				// Show sensitive objects
				for _, obj := range bucket.Objects {
					if obj.Sensitive {
						riskColorStr := getRiskColor(obj.RiskLevel)
						fmt.Printf("      🔥 %s %s (%d bytes)\n", 
							riskColorStr, obj.Key, obj.Size)
					}
				}
			} else {
				fmt.Printf("   ❌ %s (Status: %d)\n", 
					color.RedString(bucket.Name), bucket.StatusCode)
			}
		}
	}
	
	// Dump Analysis Results
	if len(result.DumpResults) > 0 {
		fmt.Printf("\n🔍 %s\n", color.YellowString("DUMP ANALYSIS RESULTS"))
		for _, dump := range result.DumpResults {
			fmt.Printf("   📄 %s (%s, %d bytes)\n", 
				color.CyanString(dump.FilePath), dump.FileType, dump.FileSize)
			
			if len(dump.Credentials) > 0 {
				fmt.Printf("      🔑 Credentials: %s\n", 
					color.RedString(fmt.Sprintf("%d found", len(dump.Credentials))))
				for i, cred := range dump.Credentials {
					if i >= 5 { // Limit display
						fmt.Printf("      ... and %d more\n", len(dump.Credentials)-5)
						break
					}
					fmt.Printf("         • %s: %s (line %d)\n", 
						cred.Type, maskValue(cred.Value), cred.Line)
				}
			}
			
			if len(dump.AIXArtifacts) > 0 {
				fmt.Printf("      🖥️  AIX Artifacts: %d found\n", len(dump.AIXArtifacts))
			}
			
			if len(dump.Emails) > 0 {
				fmt.Printf("      📧 Emails: %d found\n", len(dump.Emails))
			}
		}
	}
	
	// API Validation Results
	if len(result.APIResults) > 0 {
		fmt.Printf("\n🔑 %s\n", color.YellowString("API KEY VALIDATION RESULTS"))
		for _, api := range result.APIResults {
			if api.Valid {
				fmt.Printf("   ✅ %s: %s (%s)\n", 
					color.GreenString(api.Service), api.Key, 
					strings.Join(api.Permissions, ", "))
			} else {
				fmt.Printf("   ❌ %s: %s (Invalid)\n", 
					color.RedString(api.Service), api.Key)
			}
		}
	}
	
	// Recommendations
	fmt.Printf("\n💡 %s\n", color.YellowString("RECOMMENDATIONS"))
	if result.Summary.CriticalFindings > 0 {
		fmt.Printf("   🚨 %s: %d critical findings require immediate attention\n", 
			color.RedString("URGENT"), result.Summary.CriticalFindings)
	}
	if result.Summary.AccessibleBuckets > 0 {
		fmt.Printf("   🔒 Implement proper access controls on S3 buckets\n")
	}
	if result.Summary.CredentialsFound > 0 {
		fmt.Printf("   🔄 Rotate all exposed credentials immediately\n")
	}
	if result.Summary.ValidAPIKeys > 0 {
		fmt.Printf("   🔐 Review and rotate valid API keys if compromised\n")
	}
	
	fmt.Println(color.CyanString(strings.Repeat("=", 80)))
	return nil
}

// Helper functions
func formatCount(count int) string {
	if count == 0 {
		return color.GreenString("0")
	}
	return color.YellowString(fmt.Sprintf("%d", count))
}

func formatCritical(count int) string {
	if count == 0 {
		return color.GreenString("0")
	}
	return color.RedString(fmt.Sprintf("%d", count))
}

func formatHigh(count int) string {
	if count == 0 {
		return color.GreenString("0")
	}
	return color.YellowString(fmt.Sprintf("%d", count))
}

func getRiskColor(risk string) string {
	switch risk {
	case "CRITICAL":
		return color.RedString(risk)
	case "HIGH":
		return color.YellowString(risk)
	case "MEDIUM":
		return color.BlueString(risk)
	default:
		return color.WhiteString(risk)
	}
}

func maskValue(value string) string {
	if len(value) <= 6 {
		return strings.Repeat("*", 6)
	}
	if len(value) == 7 {
		return value[:3] + strings.Repeat("*", 4)
	}
	if len(value) <= 10 {
		return value[:3] + strings.Repeat("*", 3) + value[len(value)-3:]
	}
	return value[:3] + strings.Repeat("*", 3) + value[len(value)-3:]
}
