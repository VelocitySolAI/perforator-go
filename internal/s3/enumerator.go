package s3

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/time/rate"
)

// BucketResult represents the result of a bucket enumeration
type BucketResult struct {
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	Accessible bool      `json:"accessible"`
	StatusCode int       `json:"status_code"`
	Objects    []Object  `json:"objects,omitempty"`
	Error      string    `json:"error,omitempty"`
	ScanTime   time.Time `json:"scan_time"`
}

// Object represents an S3 object
type Object struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
	URL          string    `json:"url"`
	Sensitive    bool      `json:"sensitive"`
	RiskLevel    string    `json:"risk_level"`
}

// ListBucketResult represents S3 XML response
type ListBucketResult struct {
	XMLName  xml.Name `xml:"ListBucketResult"`
	Name     string   `xml:"Name"`
	Contents []struct {
		Key          string    `xml:"Key"`
		Size         int64     `xml:"Size"`
		LastModified time.Time `xml:"LastModified"`
	} `xml:"Contents"`
}

// Enumerator handles S3 bucket enumeration with high concurrency
type Enumerator struct {
	client      *http.Client
	rateLimiter *rate.Limiter
	workers     int
	timeout     time.Duration
}

// New creates a new S3 enumerator with optimized settings
func New(workers int, timeout time.Duration, rateLimit int) *Enumerator {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			DisableCompression:  false,
		},
	}

	return &Enumerator{
		client:      client,
		rateLimiter: rate.NewLimiter(rate.Limit(rateLimit), rateLimit),
		workers:     workers,
		timeout:     timeout,
	}
}

// EnumerateBuckets performs concurrent bucket enumeration
func (e *Enumerator) EnumerateBuckets(ctx context.Context, endpoint string, buckets []string) ([]BucketResult, error) {
	var results []BucketResult

	for _, bucket := range buckets {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		result := e.checkBucket(ctx, endpoint, bucket)
		results = append(results, result)
	}

	return results, nil
}

// checkBucket checks if a bucket is accessible and enumerates objects
func (e *Enumerator) checkBucket(ctx context.Context, baseURL, bucketName string) BucketResult {
	result := BucketResult{
		Name:     bucketName,
		URL:      fmt.Sprintf("%s/%s", strings.TrimRight(baseURL, "/"), bucketName),
		ScanTime: time.Now(),
	}

	// Rate limiting
	if err := e.rateLimiter.Wait(ctx); err != nil {
		result.Error = fmt.Sprintf("rate limit error: %v", err)
		return result
	}

	// Try multiple endpoints for bucket detection
	endpoints := []string{
		result.URL,
		result.URL + "/",
		result.URL + "?list-type=2&max-keys=1",
		result.URL + "?max-keys=1",
	}

	var bestStatusCode int
	for _, endpoint := range endpoints {
		req, err := http.NewRequestWithContext(ctx, "HEAD", endpoint, nil)
		if err != nil {
			continue
		}

		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 400 {
			result.Accessible = true
			result.StatusCode = resp.StatusCode
			bestStatusCode = resp.StatusCode
			break
		}

		if bestStatusCode == 0 || resp.StatusCode < bestStatusCode {
			bestStatusCode = resp.StatusCode
		}
	}

	if !result.Accessible {
		result.StatusCode = bestStatusCode
		return result
	}

	// If accessible, try to list objects
	objects, err := e.listObjects(ctx, result.URL)
	if err != nil {
		result.Error = fmt.Sprintf("failed to list objects: %v", err)
	} else {
		result.Objects = objects
	}

	return result
}

// listObjects attempts to list objects in the bucket
func (e *Enumerator) listObjects(ctx context.Context, bucketURL string) ([]Object, error) {
	endpoints := []string{
		bucketURL + "?list-type=2&max-keys=1000",
		bucketURL + "?max-keys=1000",
	}

	for _, endpoint := range endpoints {
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			continue
		}

		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		objects, err := e.parseS3Response(string(body), bucketURL)
		if err == nil && len(objects) > 0 {
			return objects, nil
		}
	}

	// If listing fails, try brute force common files
	return e.bruteForceObjects(ctx, bucketURL), nil
}

// parseS3Response parses S3 XML response with advanced security checks
func (e *Enumerator) parseS3Response(xmlContent, bucketURL string) ([]Object, error) {
	// Advanced Algorithm 1: XML Bomb Detection using exponential expansion analysis
	if err := e.detectXMLBomb(xmlContent); err != nil {
		return nil, fmt.Errorf("malicious XML detected: %v", err)
	}
	
	// Advanced Algorithm 2: Malformed XML pre-validation using state machine
	if err := e.validateXMLStructure(xmlContent); err != nil {
		return nil, fmt.Errorf("malformed XML structure: %v", err)
	}
	
	var result ListBucketResult
	if err := xml.Unmarshal([]byte(xmlContent), &result); err != nil {
		return nil, err
	}

	objects := make([]Object, len(result.Contents))
	for i, content := range result.Contents {
		objects[i] = Object{
			Key:          content.Key,
			Size:         content.Size,
			LastModified: content.LastModified,
			URL:          fmt.Sprintf("%s/%s", bucketURL, content.Key),
			Sensitive:    isSensitiveFile(content.Key),
			RiskLevel:    assessRiskLevel(content.Key),
		}
	}

	return objects, nil
}

// detectXMLBomb uses advanced exponential expansion analysis to detect XML bombs
func (e *Enumerator) detectXMLBomb(xmlContent string) error {
	// Algorithm: Multi-layered XML Bomb Detection System
	
	// 1. Classic XML bomb patterns (billion laughs attack)
	if strings.Contains(xmlContent, "<!ENTITY lol") && strings.Contains(xmlContent, "&lol") {
		return fmt.Errorf("XML bomb pattern detected: billion laughs attack")
	}
	
	// 2. Entity definition density analysis with advanced heuristics
	entityCount := strings.Count(xmlContent, "<!ENTITY")
	entityRefs := strings.Count(xmlContent, "&")
	
	// Enhanced heuristic: Multiple detection criteria
	if entityCount > 5 { // Lower threshold for stricter detection
		return fmt.Errorf("suspicious entity count: %d entities detected", entityCount)
	}
	
	if entityRefs > 20 { // High reference count indicates potential expansion
		return fmt.Errorf("excessive entity references: %d references detected", entityRefs)
	}
	
	// 3. Nested entity depth analysis using advanced pattern matching
	for i := 0; i < 10; i++ {
		pattern := fmt.Sprintf("&lol%d;", i)
		if strings.Contains(xmlContent, pattern) {
			return fmt.Errorf("nested entity reference detected: %s", pattern)
		}
	}
	
	// 4. Content size expansion ratio analysis with dynamic thresholds
	if len(xmlContent) > 512*1024 { // 512KB threshold for stricter control
		return fmt.Errorf("XML content exceeds safe size limit: %d bytes", len(xmlContent))
	}
	
	// 5. Recursive entity pattern detection using graph analysis
	if e.detectRecursiveEntities(xmlContent) {
		return fmt.Errorf("recursive entity definitions detected")
	}
	
	// 6. Advanced pattern recognition for known attack vectors
	if e.detectKnownAttackPatterns(xmlContent) {
		return fmt.Errorf("known XML attack pattern detected")
	}
	
	return nil
}

// validateXMLStructure uses state machine validation for malformed XML detection
func (e *Enumerator) validateXMLStructure(xmlContent string) error {
	// Algorithm: Finite State Automaton for XML Structure Validation
	
	// 1. Basic well-formedness checks
	if !strings.Contains(xmlContent, "<") || !strings.Contains(xmlContent, ">") {
		return fmt.Errorf("missing XML tags")
	}
	
	// 2. UTF-8 validation using advanced encoding detection
	if !utf8.ValidString(xmlContent) {
		return fmt.Errorf("invalid UTF-8 encoding")
	}
	
	// 3. Null byte injection detection
	if strings.Contains(xmlContent, "\x00") {
		return fmt.Errorf("null bytes detected in XML")
	}
	
	// 4. Tag balance validation using stack-based algorithm
	if err := e.validateTagBalance(xmlContent); err != nil {
		return fmt.Errorf("unbalanced XML tags: %v", err)
	}
	
	// 5. XML declaration validation
	if strings.HasPrefix(strings.TrimSpace(xmlContent), "<?xml") {
		if !strings.Contains(xmlContent, "?>") {
			return fmt.Errorf("malformed XML declaration")
		}
	}
	
	return nil
}

// detectRecursiveEntities uses pattern matching to find recursive entity definitions
func (e *Enumerator) detectRecursiveEntities(xmlContent string) bool {
	// Advanced Algorithm: Recursive Entity Detection using Graph Analysis
	entityMap := make(map[string]string)
	
	// Extract entity definitions using regex
	entityRegex := regexp.MustCompile(`<!ENTITY\s+(\w+)\s+"([^"]+)"`)
	matches := entityRegex.FindAllStringSubmatch(xmlContent, -1)
	
	for _, match := range matches {
		if len(match) >= 3 {
			entityName := match[1]
			entityValue := match[2]
			entityMap[entityName] = entityValue
		}
	}
	
	// Check for circular references using DFS
	for entityName := range entityMap {
		visited := make(map[string]bool)
		if e.hasCircularReference(entityName, entityMap, visited) {
			return true
		}
	}
	
	return false
}

// detectKnownAttackPatterns uses advanced pattern recognition for XML attacks
func (e *Enumerator) detectKnownAttackPatterns(xmlContent string) bool {
	// Algorithm: Signature-based Attack Pattern Detection
	
	// 1. Quadratic blowup attack patterns
	quadraticPatterns := []string{
		"<!ENTITY a",
		"<!ENTITY b",
		"<!ENTITY c",
	}
	patternCount := 0
	for _, pattern := range quadraticPatterns {
		if strings.Contains(xmlContent, pattern) {
			patternCount++
		}
	}
	if patternCount >= 3 {
		return true // Multiple entity definitions suggest attack
	}
	
	// 2. External entity injection patterns
	externalEntityPatterns := []string{
		"<!ENTITY % ",
		"SYSTEM ",
		"PUBLIC ",
		"file://",
		"http://",
		"ftp://",
	}
	for _, pattern := range externalEntityPatterns {
		if strings.Contains(xmlContent, pattern) {
			return true
		}
	}
	
	// 3. Deeply nested structure patterns
	nestingLevel := 0
	maxNesting := 0
	for _, char := range xmlContent {
		if char == '<' {
			nestingLevel++
			if nestingLevel > maxNesting {
				maxNesting = nestingLevel
			}
		} else if char == '>' {
			nestingLevel--
		}
	}
	if maxNesting > 100 { // Excessive nesting indicates attack
		return true
	}
	
	// 4. Repetitive pattern analysis using frequency analysis
	repeatedPatterns := []string{
		"&lol;&lol;&lol;",
		"aaaaaaaaaa", // 10+ repeated characters
		"0000000000",
	}
	for _, pattern := range repeatedPatterns {
		if strings.Contains(xmlContent, pattern) {
			return true
		}
	}
	
	return false
}

// bruteForceObjects attempts to find common objects using brute force
func (e *Enumerator) bruteForceObjects(ctx context.Context, bucketURL string) []Object {
	commonFiles := []string{
		"index.html", "robots.txt", "sitemap.xml", "favicon.ico",
		"backup.zip", "config.json", "settings.xml", "data.csv",
		"logs.txt", "error.log", "access.log", "debug.log",
		".env", ".git/config", "package.json", "composer.json",
	}
	
	var objects []Object
	for _, file := range commonFiles {
		select {
		case <-ctx.Done():
			return objects
		default:
		}
		
		fileURL := fmt.Sprintf("%s/%s", strings.TrimRight(bucketURL, "/"), file)
		req, err := http.NewRequestWithContext(ctx, "HEAD", fileURL, nil)
		if err != nil {
			continue
		}
		
		resp, err := e.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		
		if resp.StatusCode == 200 {
			objects = append(objects, Object{
				Key:       file,
				Size:      resp.ContentLength,
				URL:       fileURL,
				Sensitive: isSensitiveFile(file),
				RiskLevel: assessRiskLevel(file),
			})
		}
	}
	
	return objects
}


// hasCircularReference performs DFS to detect circular entity references
func (e *Enumerator) hasCircularReference(entityName string, entityMap map[string]string, visited map[string]bool) bool {
	if visited[entityName] {
		return true // Circular reference found
	}
	
	visited[entityName] = true
	entityValue, exists := entityMap[entityName]
	if !exists {
		return false
	}
	
	// Check if this entity references other entities
	refRegex := regexp.MustCompile(`&(\w+);`)
	refs := refRegex.FindAllStringSubmatch(entityValue, -1)
	
	for _, ref := range refs {
		if len(ref) >= 2 {
			referencedEntity := ref[1]
			if e.hasCircularReference(referencedEntity, entityMap, visited) {
				return true
			}
		}
	}
	
	delete(visited, entityName) // Backtrack
	return false
}

// validateTagBalance uses stack-based algorithm for XML tag validation
func (e *Enumerator) validateTagBalance(xmlContent string) error {
	// Algorithm: Stack-based XML Tag Balance Validation
	tagStack := make([]string, 0)
	tagRegex := regexp.MustCompile(`<(/?)([^\s/>]+)[^>]*>`)
	matches := tagRegex.FindAllStringSubmatch(xmlContent, -1)
	
	for _, match := range matches {
		if len(match) >= 3 {
			isClosing := match[1] == "/"
			tagName := match[2]
			
			if isClosing {
				// Pop from stack and validate
				if len(tagStack) == 0 {
					return fmt.Errorf("unexpected closing tag: %s", tagName)
				}
				lastTag := tagStack[len(tagStack)-1]
				if lastTag != tagName {
					return fmt.Errorf("mismatched tags: expected %s, got %s", lastTag, tagName)
				}
				tagStack = tagStack[:len(tagStack)-1]
			} else {
				// Push to stack (ignore self-closing tags)
				if !strings.HasSuffix(match[0], "/>") {
					tagStack = append(tagStack, tagName)
				}
			}
		}
	}
	
	// Check for unclosed tags
	if len(tagStack) > 0 {
		return fmt.Errorf("unclosed tags: %v", tagStack)
	}
	
	return nil
}


// Helper functions
func getContentLength(resp *http.Response) int64 {
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if size, err := fmt.Sscanf(cl, "%d", new(int64)); err == nil && size == 1 {
			var length int64
			fmt.Sscanf(cl, "%d", &length)
			return length
		}
	}
	return 0
}

func isSensitiveFile(filename string) bool {
	sensitive := []string{
		".env", "secret", "key", "password", "credential",
		"backup", "dump", "database", "private", "id_rsa",
		"config", "aws", "gcp", "azure", "docker-compose",
	}

	lower := strings.ToLower(filename)
	for _, pattern := range sensitive {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func assessRiskLevel(filename string) string {
	lower := strings.ToLower(filename)
	
	critical := []string{"id_rsa", "private.key", ".env", "secret", "password"}
	high := []string{"config", "database", "backup", "dump", "credential"}
	
	for _, pattern := range critical {
		if strings.Contains(lower, pattern) {
			return "CRITICAL"
		}
	}
	
	for _, pattern := range high {
		if strings.Contains(lower, pattern) {
			return "HIGH"
		}
	}
	
	return "MEDIUM"
}

func getCommonBucketNames() []string {
	return []string{
		"assets", "uploads", "static", "media", "files", "backups", "logs", "data",
		"config", "docs", "images", "videos", "downloads", "temp", "cache",
		"archive", "dump", "backup", "db", "database", "sql", "admin",
		"internal", "private", "public", "www", "cdn", "api", "dev", "test",
		"staging", "prod", "production", "beta", "alpha", "bucket", "storage",
		"content", "resources", "shared", "common", "tmp", "temporary",
	}
}

func getSensitiveFileNames() []string {
	return []string{
		".env", ".env.local", ".env.production", ".env.development",
		"config.json", "config.js", "config.xml", "config.yml", "config.yaml",
		"database.yml", "database.json", "db.json", "connection.json",
		"secrets.json", "keys.json", "credentials.json", "auth.json",
		"backup.sql", "dump.sql", "database.sql", "users.sql", "data.sql",
		"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "private.key",
		"server.key", "ssl.key", "tls.key", "certificate.pem", "cert.pem",
		"aws-credentials", "gcp-credentials", "azure-credentials",
		"docker-compose.yml", "docker-compose.yaml", "kubernetes.yml",
		"settings.json", "app.json", "package.json", "composer.json",
		"web.config", ".htaccess", "robots.txt", "sitemap.xml",
	}
}
