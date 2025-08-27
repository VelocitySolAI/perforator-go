package performance

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// StressTestConfig defines parameters for stress testing
type StressTestConfig struct {
	MaxConcurrency    int
	RequestCount      int
	PayloadSizeKB     int
	TestDurationSec   int
	MemoryLimitMB     int
	ErrorRate         float64
	ResponseDelayMs   int
}

// StressTestResult contains metrics from stress testing
type StressTestResult struct {
	TotalRequests     int64
	SuccessfulReqs    int64
	FailedReqs        int64
	AvgResponseTimeMs int64
	MaxResponseTimeMs int64
	MinResponseTimeMs int64
	TotalDurationMs   int64
	PeakMemoryMB      int64
	ErrorRate         float64
	ThroughputRPS     float64
}

// StressTestServer simulates high-load scenarios
type StressTestServer struct {
	server          *httptest.Server
	requestCount    int64
	totalLatency    int64
	maxLatency      int64
	minLatency      int64
	config          StressTestConfig
	payloadCache    []byte
	mu              sync.RWMutex
}

func NewStressTestServer(config StressTestConfig) *StressTestServer {
	stress := &StressTestServer{
		config:     config,
		minLatency: int64(^uint64(0) >> 1), // Max int64
	}
	
	// Pre-generate large payload to avoid repeated allocation
	stress.payloadCache = stress.generateLargePayload(config.PayloadSizeKB)
	
	stress.server = httptest.NewServer(http.HandlerFunc(stress.handler))
	return stress
}

func (s *StressTestServer) Close() {
	s.server.Close()
}

func (s *StressTestServer) URL() string {
	return s.server.URL
}

func (s *StressTestServer) generateLargePayload(sizeKB int) []byte {
	size := sizeKB * 1024
	payload := make([]byte, size)
	
	// Fill with realistic JSON-like data
	template := `{"id": %d, "data": "%s", "timestamp": "2024-01-01T00:00:00Z", "sensitive": "%s"}`
	
	pos := 0
	id := 0
	for pos < size-200 { // Leave room for final entry
		data := strings.Repeat("x", 50+rand.Intn(100))
		sensitive := fmt.Sprintf("secret_%d_%s", id, strings.Repeat("a", 20))
		entry := fmt.Sprintf(template, id, data, sensitive)
		
		if pos+len(entry) >= size {
			break
		}
		
		copy(payload[pos:], entry)
		pos += len(entry)
		if pos < size-1 {
			payload[pos] = ','
			pos++
		}
		id++
	}
	
	return payload
}

func (s *StressTestServer) handler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	count := atomic.AddInt64(&s.requestCount, 1)
	
	// Simulate processing delay
	if s.config.ResponseDelayMs > 0 {
		time.Sleep(time.Duration(s.config.ResponseDelayMs) * time.Millisecond)
	}
	
	// Simulate random errors
	if s.config.ErrorRate > 0 && rand.Float64() < s.config.ErrorRate {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "simulated error"}`))
		return
	}
	
	// Track latency
	latency := time.Since(start).Milliseconds()
	atomic.AddInt64(&s.totalLatency, latency)
	
	s.mu.Lock()
	if latency > s.maxLatency {
		s.maxLatency = latency
	}
	if latency < s.minLatency {
		s.minLatency = latency
	}
	s.mu.Unlock()
	
	// Return large payload
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	// Simulate different response types based on path
	switch {
	case strings.Contains(r.URL.Path, "/s3"):
		s.handleS3Response(w, count)
	case strings.Contains(r.URL.Path, "/api"):
		s.handleAPIResponse(w, count)
	case strings.Contains(r.URL.Path, "/large"):
		w.Write(s.payloadCache)
	default:
		w.Write([]byte(`{"status": "ok", "request_id": ` + fmt.Sprintf("%d", count) + `}`))
	}
}

func (s *StressTestServer) handleS3Response(w http.ResponseWriter, requestID int64) {
	// Generate S3-like XML response with many objects
	response := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
    <Name>stress-test-bucket</Name>
    <IsTruncated>false</IsTruncated>`
	
	objectCount := 100 + rand.Intn(900) // 100-1000 objects
	for i := 0; i < objectCount; i++ {
		response += fmt.Sprintf(`
    <Contents>
        <Key>file_%d_%d.txt</Key>
        <Size>%d</Size>
        <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    </Contents>`, requestID, i, rand.Intn(1000000))
	}
	
	response += `
</ListBucketResult>`
	w.Write([]byte(response))
}

func (s *StressTestServer) handleAPIResponse(w http.ResponseWriter, requestID int64) {
	// Generate API validation response with detailed permissions
	permissions := []string{"read", "write", "admin", "delete", "create", "update", "list", "execute"}
	selectedPerms := make([]string, rand.Intn(len(permissions))+1)
	for i := range selectedPerms {
		selectedPerms[i] = permissions[rand.Intn(len(permissions))]
	}
	
	response := fmt.Sprintf(`{
		"valid": true,
		"user_id": %d,
		"permissions": %q,
		"metadata": {
			"last_used": "2024-01-01T00:00:00Z",
			"created": "2023-01-01T00:00:00Z",
			"scope": "full_access"
		},
		"rate_limit": {
			"remaining": %d,
			"reset": %d
		}
	}`, requestID, selectedPerms, rand.Intn(1000), time.Now().Unix()+3600)
	
	w.Write([]byte(response))
}

func (s *StressTestServer) GetStats() StressTestResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	totalReqs := atomic.LoadInt64(&s.requestCount)
	totalLatency := atomic.LoadInt64(&s.totalLatency)
	
	var avgLatency int64
	if totalReqs > 0 {
		avgLatency = totalLatency / totalReqs
	}
	
	return StressTestResult{
		TotalRequests:     totalReqs,
		AvgResponseTimeMs: avgLatency,
		MaxResponseTimeMs: s.maxLatency,
		MinResponseTimeMs: s.minLatency,
	}
}

func TestS3EnumeratorStress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}
	
	config := StressTestConfig{
		MaxConcurrency:  50,
		RequestCount:    1000,
		PayloadSizeKB:   100,
		TestDurationSec: 30,
		ErrorRate:       0.1,
		ResponseDelayMs: 10,
	}
	
	server := NewStressTestServer(config)
	defer server.Close()
	
	// Monitor memory usage
	var peakMemory int64
	memoryMonitor := time.NewTicker(100 * time.Millisecond)
	defer memoryMonitor.Stop()
	
	go func() {
		for range memoryMonitor.C {
			var m runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&m)
			currentMB := int64(m.Alloc / 1024 / 1024)
			if currentMB > peakMemory {
				atomic.StoreInt64(&peakMemory, currentMB)
			}
		}
	}()
	
	// Create many bucket names for concurrent testing
	buckets := make([]string, config.RequestCount)
	for i := 0; i < config.RequestCount; i++ {
		buckets[i] = fmt.Sprintf("stress-bucket-%d", i)
	}
	
	// Test with timeout context
	_, cancel := context.WithTimeout(context.Background(), time.Duration(config.TestDurationSec)*time.Second)
	defer cancel()
	
	start := time.Now()
	
	// Simulate S3 enumeration with high concurrency
	semaphore := make(chan struct{}, config.MaxConcurrency)
	var wg sync.WaitGroup
	var successCount, errorCount int64
	
	for _, bucket := range buckets {
		wg.Add(1)
		go func(bucketName string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			// Simulate S3 enumeration request
			resp, err := http.Get(server.URL() + "/s3/" + bucketName)
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				return
			}
			defer resp.Body.Close()
			
			if resp.StatusCode == http.StatusOK {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&errorCount, 1)
			}
		}(bucket)
	}
	
	wg.Wait()
	duration := time.Since(start)
	
	// Collect results
	stats := server.GetStats()
	finalPeakMemory := atomic.LoadInt64(&peakMemory)
	
	result := StressTestResult{
		TotalRequests:     stats.TotalRequests,
		SuccessfulReqs:    successCount,
		FailedReqs:        errorCount,
		AvgResponseTimeMs: stats.AvgResponseTimeMs,
		MaxResponseTimeMs: stats.MaxResponseTimeMs,
		MinResponseTimeMs: stats.MinResponseTimeMs,
		TotalDurationMs:   duration.Milliseconds(),
		PeakMemoryMB:      finalPeakMemory,
		ThroughputRPS:     float64(stats.TotalRequests) / duration.Seconds(),
	}
	
	// Validate performance metrics
	if result.ThroughputRPS < 10 {
		t.Errorf("Throughput too low: %.2f RPS", result.ThroughputRPS)
	}
	
	if result.PeakMemoryMB > 500 { // 500MB limit
		t.Errorf("Memory usage too high: %d MB", result.PeakMemoryMB)
	}
	
	if result.AvgResponseTimeMs > 1000 { // 1 second average
		t.Errorf("Average response time too high: %d ms", result.AvgResponseTimeMs)
	}
	
	errorRate := float64(result.FailedReqs) / float64(result.TotalRequests)
	if errorRate > 0.2 { // Allow up to 20% errors in stress test
		t.Errorf("Error rate too high: %.2f%%", errorRate*100)
	}
	
	t.Logf("Stress Test Results:")
	t.Logf("  Total Requests: %d", result.TotalRequests)
	t.Logf("  Successful: %d", result.SuccessfulReqs)
	t.Logf("  Failed: %d", result.FailedReqs)
	t.Logf("  Throughput: %.2f RPS", result.ThroughputRPS)
	t.Logf("  Avg Response Time: %d ms", result.AvgResponseTimeMs)
	t.Logf("  Max Response Time: %d ms", result.MaxResponseTimeMs)
	t.Logf("  Peak Memory: %d MB", result.PeakMemoryMB)
	t.Logf("  Total Duration: %d ms", result.TotalDurationMs)
}

func TestAPIValidatorStress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}
	
	config := StressTestConfig{
		MaxConcurrency:  30,
		RequestCount:    500,
		PayloadSizeKB:   50,
		TestDurationSec: 20,
		ErrorRate:       0.15,
		ResponseDelayMs: 20,
	}
	
	server := NewStressTestServer(config)
	defer server.Close()
	
	// Generate many API keys for testing
	apiKeys := make(map[string]string)
	for i := 0; i < config.RequestCount; i++ {
		apiKeys[fmt.Sprintf("key_%d_%s", i, strings.Repeat("a", 32))] = "test"
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.TestDurationSec)*time.Second)
	defer cancel()
	
	start := time.Now()
	
	// Simulate concurrent API validation
	semaphore := make(chan struct{}, config.MaxConcurrency)
	var wg sync.WaitGroup
	var successCount, errorCount int64
	
	for key := range apiKeys {
		wg.Add(1)
		go func(apiKey string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			// Simulate API validation request
			req, _ := http.NewRequestWithContext(ctx, "GET", server.URL()+"/api/validate", nil)
			req.Header.Set("Authorization", "Bearer "+apiKey)
			
			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				atomic.AddInt64(&errorCount, 1)
				return
			}
			defer resp.Body.Close()
			
			if resp.StatusCode == http.StatusOK {
				atomic.AddInt64(&successCount, 1)
			} else {
				atomic.AddInt64(&errorCount, 1)
			}
		}(key)
	}
	
	wg.Wait()
	duration := time.Since(start)
	
	stats := server.GetStats()
	throughput := float64(stats.TotalRequests) / duration.Seconds()
	
	// Validate API stress test results
	if throughput < 5 {
		t.Errorf("API validation throughput too low: %.2f RPS", throughput)
	}
	
	if stats.AvgResponseTimeMs > 2000 {
		t.Errorf("API validation response time too high: %d ms", stats.AvgResponseTimeMs)
	}
	
	t.Logf("API Stress Test Results:")
	t.Logf("  Throughput: %.2f RPS", throughput)
	t.Logf("  Avg Response Time: %d ms", stats.AvgResponseTimeMs)
	t.Logf("  Success Rate: %.2f%%", float64(successCount)/float64(stats.TotalRequests)*100)
}

func TestDumpAnalyzerStress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping stress test in short mode")
	}
	
	// Create temporary directory for stress test files
	tempDir, err := os.MkdirTemp("", "dump_stress_test_")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)
	
	// Generate large files with various patterns
	fileCount := 50
	fileSizeMB := 10
	
	files := make([]string, fileCount)
	for i := 0; i < fileCount; i++ {
		content := generateLargeDumpContent(fileSizeMB, i)
		filePath := filepath.Join(tempDir, fmt.Sprintf("dump_%d.txt", i))
		
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
		files[i] = filePath
	}
	
	// Test with timeout context
	_, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	
	start := time.Now()
	
	// Analyze files concurrently
	semaphore := make(chan struct{}, 10) // Limit concurrency for file I/O
	var wg sync.WaitGroup
	var totalItems, totalFiles int64
	
	for _, file := range files {
		wg.Add(1)
		go func(filePath string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			// Simulate dump analysis
			// In real implementation, this would call analyzer.AnalyzeFile
			items := analyzeDumpFile(filePath)
			atomic.AddInt64(&totalItems, int64(items))
			atomic.AddInt64(&totalFiles, 1)
		}(file)
	}
	
	wg.Wait()
	duration := time.Since(start)
	
	// Validate dump analysis performance
	filesPerSecond := float64(totalFiles) / duration.Seconds()
	itemsPerSecond := float64(totalItems) / duration.Seconds()
	
	if filesPerSecond < 1 {
		t.Errorf("File analysis rate too low: %.2f files/sec", filesPerSecond)
	}
	
	if duration > 45*time.Second {
		t.Errorf("Dump analysis took too long: %v", duration)
	}
	
	t.Logf("Dump Analysis Stress Test Results:")
	t.Logf("  Files Analyzed: %d", totalFiles)
	t.Logf("  Total Items Found: %d", totalItems)
	t.Logf("  Files/Second: %.2f", filesPerSecond)
	t.Logf("  Items/Second: %.2f", itemsPerSecond)
	t.Logf("  Total Duration: %v", duration)
}

func generateLargeDumpContent(sizeMB, seed int) string {
	var content strings.Builder
	targetSize := sizeMB * 1024 * 1024
	
	patterns := []string{
		"password=%s\n",
		"api_key=%s\n",
		"secret=%s\n",
		"token=%s\n",
		"AWS_ACCESS_KEY=%s\n",
		"github_token=%s\n",
		"database_url=postgresql://user:%s@host:5432/db\n",
		"private_key=-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n",
	}
	
	rand.Seed(int64(seed))
	
	for content.Len() < targetSize {
		// Add normal content
		for i := 0; i < 100; i++ {
			content.WriteString(fmt.Sprintf("Line %d: This is normal content with some data %d\n", i, rand.Intn(10000)))
		}
		
		// Add sensitive patterns
		for _, pattern := range patterns {
			if rand.Float64() < 0.1 { // 10% chance for each pattern
				sensitiveValue := fmt.Sprintf("sensitive_%d_%s", seed, strings.Repeat("x", 20+rand.Intn(30)))
				content.WriteString(fmt.Sprintf(pattern, sensitiveValue))
			}
		}
		
		// Add some structured data
		content.WriteString(fmt.Sprintf(`{
			"id": %d,
			"user": "user_%d",
			"config": {
				"api_key": "sk_%s",
				"database": {
					"password": "db_pass_%d"
				}
			}
		}`, rand.Intn(10000), seed, strings.Repeat("a", 32), rand.Intn(1000)))
		content.WriteString("\n")
	}
	
	return content.String()
}

func analyzeDumpFile(filePath string) int {
	// Simplified analysis simulation
	content, err := os.ReadFile(filePath)
	if err != nil {
		return 0
	}
	
	// Count potential sensitive patterns
	text := string(content)
	patterns := []string{"password=", "api_key=", "secret=", "token=", "private_key="}
	
	count := 0
	for _, pattern := range patterns {
		count += strings.Count(strings.ToLower(text), pattern)
	}
	
	return count
}

func TestMemoryLeakDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory leak test in short mode")
	}
	
	// Force garbage collection and get baseline
	runtime.GC()
	runtime.GC()
	var m1 runtime.MemStats
	runtime.ReadMemStats(&m1)
	baselineAlloc := m1.Alloc
	
	// Run multiple iterations of operations
	iterations := 100
	for i := 0; i < iterations; i++ {
		// Simulate various operations that might leak memory
		data := make([]byte, 1024*1024) // 1MB allocation
		_ = string(data)                // Convert to string (potential leak)
		
		// Simulate processing
		for j := 0; j < 1000; j++ {
			_ = fmt.Sprintf("test_%d_%d", i, j)
		}
		
		// Force GC every 10 iterations
		if i%10 == 0 {
			runtime.GC()
		}
	}
	
	// Final garbage collection and memory check
	runtime.GC()
	runtime.GC()
	var m2 runtime.MemStats
	runtime.ReadMemStats(&m2)
	finalAlloc := m2.Alloc
	
	// Check for significant memory increase
	memoryIncrease := int64(finalAlloc - baselineAlloc)
	memoryIncreaseMB := memoryIncrease / 1024 / 1024
	
	if memoryIncreaseMB > 50 { // Allow up to 50MB increase
		t.Errorf("Potential memory leak detected: %d MB increase", memoryIncreaseMB)
	}
	
	t.Logf("Memory Leak Test Results:")
	t.Logf("  Baseline Memory: %d MB", baselineAlloc/1024/1024)
	t.Logf("  Final Memory: %d MB", finalAlloc/1024/1024)
	t.Logf("  Memory Increase: %d MB", memoryIncreaseMB)
	t.Logf("  Iterations: %d", iterations)
}
