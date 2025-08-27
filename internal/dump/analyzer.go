package dump

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

// AnalysisResult represents the result of dump file analysis
type AnalysisResult struct {
	FilePath      string            `json:"file_path"`
	FileSize      int64             `json:"file_size"`
	FileType      string            `json:"file_type"`
	Credentials   []Credential      `json:"credentials"`
	Emails        []string          `json:"emails"`
	IPs           []string          `json:"ips"`
	Domains       []string          `json:"domains"`
	AIXArtifacts  []AIXArtifact     `json:"aix_artifacts"`
	ProcessingTime time.Duration    `json:"processing_time"`
	Error         string            `json:"error,omitempty"`
}

// Credential represents a found credential
type Credential struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Context string `json:"context"`
	Line    int    `json:"line"`
}

// AIXArtifact represents AIX-specific system artifacts
type AIXArtifact struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Context string `json:"context"`
	Line    int    `json:"line"`
}

// Analyzer handles memory-efficient dump file analysis
type Analyzer struct {
	credentialPatterns []*regexp.Regexp
	emailPattern       *regexp.Regexp
	ipPattern          *regexp.Regexp
	domainPattern      *regexp.Regexp
	aixPatterns        map[string]*regexp.Regexp
	workers            int
}

// New creates a new dump analyzer with compiled regex patterns
func New(workers int) *Analyzer {
	credentialPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)password["\s]*[:=]["\s]*([^\s"']+)`),
		regexp.MustCompile(`(?i)secret["\s]*[:=]["\s]*([^\s"']+)`),
		regexp.MustCompile(`(?i)api[_-]?key["\s]*[:=]["\s]*([^\s"']+)`),
		regexp.MustCompile(`(?i)token["\s]*[:=]["\s]*([^\s"']+)`),
		regexp.MustCompile(`(?i)access[_-]?key["\s]*[:=]["\s]*([^\s"']+)`),
		regexp.MustCompile(`(?i)private[_-]?key["\s]*[:=]["\s]*([^\s"']+)`),
		regexp.MustCompile(`(?i)bearer["\s]*[:=]["\s]*([^\s"']+)`),
		regexp.MustCompile(`(?i)authorization["\s]*[:=]["\s]*([^\s"']+)`),
	}

	aixPatterns := map[string]*regexp.Regexp{
		"aix_version":  regexp.MustCompile(`AIX\s+[\w\-]+\s+\d+\s+\d+\s+[\w\d]+`),
		"dump_date":    regexp.MustCompile(`Dump Date:\s*(.+)`),
		"system_name":  regexp.MustCompile(`System:\s*(\w+)`),
		"privkey_pag":  regexp.MustCompile(`privkey\.pag`),
		"pwdhist_pag":  regexp.MustCompile(`pwdhist\.pag`),
		"passwd_etc":   regexp.MustCompile(`passwd\.etc`),
		"ssh_config":   regexp.MustCompile(`ssh_config|sshd_config`),
		"dbm_files":    regexp.MustCompile(`\.pag|\.dir`),
	}

	return &Analyzer{
		credentialPatterns: credentialPatterns,
		emailPattern:       regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
		ipPattern:          regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
		domainPattern:      regexp.MustCompile(`\b[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z]{2,}\b`),
		aixPatterns:        aixPatterns,
		workers:            workers,
	}
}

// AnalyzeFile performs memory-efficient analysis using advanced buffer management
func (a *Analyzer) AnalyzeFile(ctx context.Context, filePath string) (*AnalysisResult, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	// Advanced Algorithm: Adaptive Buffer Management
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %v", err)
	}

	result := &AnalysisResult{
		FilePath:    filePath,
		Credentials: []Credential{},
		Emails:      []string{},
		IPs:         []string{},
		Domains:     []string{},
		AIXArtifacts: []AIXArtifact{},
	}

	// Use advanced streaming algorithm for large files
	if fileInfo.Size() > 100*1024*1024 { // 100MB threshold
		return a.analyzeLargeFile(ctx, file, result)
	}

	scanner := bufio.NewScanner(file)
	// Advanced Algorithm: Dynamic Buffer Sizing
	bufferSize := a.calculateOptimalBufferSize(fileInfo.Size())
	buf := make([]byte, 0, bufferSize)
	scanner.Buffer(buf, bufferSize)
	lineNum := 0

	// Create channels for concurrent processing
	credChan := make(chan Credential, 100)
	emailChan := make(chan string, 100)
	ipChan := make(chan string, 100)
	domainChan := make(chan string, 100)
	aixChan := make(chan AIXArtifact, 100)
	
	// Start result collector goroutine
	go a.collectResults(credChan, emailChan, ipChan, domainChan, aixChan, result)
	
	for scanner.Scan() {
		line := scanner.Text()
		a.processLineWithChannels(line, lineNum, credChan, emailChan, ipChan, domainChan, aixChan)
		lineNum++
	}
	
	// Close channels
	close(credChan)
	close(emailChan)
	close(ipChan)
	close(domainChan)
	close(aixChan)

	result.FileSize = fileInfo.Size()
	result.FileType = detectFileType(filePath)
	return result, scanner.Err()
}

// analyzeLargeFile uses advanced streaming algorithms for large files
func (a *Analyzer) analyzeLargeFile(ctx context.Context, file *os.File, result *AnalysisResult) (*AnalysisResult, error) {
	fileInfo, _ := file.Stat()
	result.FileSize = fileInfo.Size()
	result.FileType = detectFileType(file.Name())

	// Advanced Algorithm: Chunked Streaming Analysis
	chunkSize := 1024 * 1024 // 1MB chunks
	buffer := make([]byte, chunkSize)
	lineBuffer := make([]byte, 0, chunkSize*2)
	lineNum := 0
	
	// Create channels for concurrent processing
	credChan := make(chan Credential, 100)
	emailChan := make(chan string, 100)
	ipChan := make(chan string, 100)
	domainChan := make(chan string, 100)
	aixChan := make(chan AIXArtifact, 100)
	
	// Start result collector
	go a.collectResults(credChan, emailChan, ipChan, domainChan, aixChan, result)
	
	for {
		n, err := file.Read(buffer)
		if n == 0 {
			break
		}
		
		// Process chunk with line boundary detection
		lineBuffer = append(lineBuffer, buffer[:n]...)
		lines := strings.Split(string(lineBuffer), "\n")
		
		// Process complete lines
		for i := 0; i < len(lines)-1; i++ {
			a.processLine(lines[i], lineNum, credChan, emailChan, ipChan, domainChan, aixChan)
			lineNum++
		}
		
		// Keep incomplete line for next iteration
		lineBuffer = []byte(lines[len(lines)-1])
		
		if err != nil {
			break
		}
	}
	
	// Process final line
	if len(lineBuffer) > 0 {
		a.processLine(string(lineBuffer), lineNum, credChan, emailChan, ipChan, domainChan, aixChan)
	}
	
	// Close channels
	close(credChan)
	close(emailChan)
	close(ipChan)
	close(domainChan)
	close(aixChan)
	
	return result, nil
}

// calculateOptimalBufferSize uses advanced heuristics for buffer sizing
func (a *Analyzer) calculateOptimalBufferSize(fileSize int64) int {
	// Algorithm: Adaptive Buffer Sizing based on file size
	if fileSize < 1024*1024 { // < 1MB
		return 64 * 1024 // 64KB
	} else if fileSize < 10*1024*1024 { // < 10MB
		return 256 * 1024 // 256KB
	} else if fileSize < 100*1024*1024 { // < 100MB
		return 1024 * 1024 // 1MB
	}
	return 4 * 1024 * 1024 // 4MB for very large files
}

// collectResults collects results from processing channels
func (a *Analyzer) collectResults(credChan <-chan Credential, emailChan <-chan string, ipChan <-chan string, domainChan <-chan string, aixChan <-chan AIXArtifact, result *AnalysisResult) {
	for {
		select {
		case cred, ok := <-credChan:
			if !ok {
				credChan = nil
			} else {
				result.Credentials = append(result.Credentials, cred)
			}
		case email, ok := <-emailChan:
			if !ok {
				emailChan = nil
			} else {
				result.Emails = append(result.Emails, email)
			}
		case ip, ok := <-ipChan:
			if !ok {
				ipChan = nil
			} else {
				result.IPs = append(result.IPs, ip)
			}
		case domain, ok := <-domainChan:
			if !ok {
				domainChan = nil
			} else {
				result.Domains = append(result.Domains, domain)
			}
		case aix, ok := <-aixChan:
			if !ok {
				aixChan = nil
			} else {
				result.AIXArtifacts = append(result.AIXArtifacts, aix)
			}
		}
		
		// Exit when all channels are closed
		if credChan == nil && emailChan == nil && ipChan == nil && domainChan == nil && aixChan == nil {
			break
		}
	}
}

// openFile opens and decompresses files based on type
func (a *Analyzer) openFile(filePath string) (io.ReadCloser, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	fileType := detectFileType(filePath)
	
	switch fileType {
	case "bzip2":
		return &readCloser{
			Reader: bzip2.NewReader(file),
			Closer: file,
		}, nil
	case "gzip":
		gzReader, err := gzip.NewReader(file)
		if err != nil {
			file.Close()
			return nil, err
		}
		return &multiCloser{
			Reader: gzReader,
			closers: []io.Closer{gzReader, file},
		}, nil
	default:
		return file, nil
	}
}

// processStream processes the file stream with concurrent pattern matching
func (a *Analyzer) processStream(ctx context.Context, reader io.Reader, result *AnalysisResult) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 1MB max line size

	// Channels for collecting results
	credChan := make(chan Credential, 1000)
	emailChan := make(chan string, 1000)
	ipChan := make(chan string, 1000)
	domainChan := make(chan string, 1000)
	aixChan := make(chan AIXArtifact, 1000)

	// Result collectors
	var wg sync.WaitGroup
	wg.Add(5)

	// Collect credentials
	go func() {
		defer wg.Done()
		for cred := range credChan {
			result.Credentials = append(result.Credentials, cred)
		}
	}()

	// Collect emails
	go func() {
		defer wg.Done()
		emailSet := make(map[string]bool)
		for email := range emailChan {
			if !emailSet[email] {
				emailSet[email] = true
				result.Emails = append(result.Emails, email)
			}
		}
	}()

	// Collect IPs
	go func() {
		defer wg.Done()
		ipSet := make(map[string]bool)
		for ip := range ipChan {
			if !ipSet[ip] {
				ipSet[ip] = true
				result.IPs = append(result.IPs, ip)
			}
		}
	}()

	// Collect domains
	go func() {
		defer wg.Done()
		domainSet := make(map[string]bool)
		for domain := range domainChan {
			if !domainSet[domain] {
				domainSet[domain] = true
				result.Domains = append(result.Domains, domain)
			}
		}
	}()

	// Collect AIX artifacts
	go func() {
		defer wg.Done()
		for artifact := range aixChan {
			result.AIXArtifacts = append(result.AIXArtifacts, artifact)
		}
	}()

	// Process lines concurrently
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(a.workers)

	lineChan := make(chan struct {
		text string
		num  int
	}, 100)

	// Line processor workers
	for i := 0; i < a.workers; i++ {
		g.Go(func() error {
			for line := range lineChan {
				select {
				case <-ctx.Done():
					return ctx.Err()
				default:
					a.processLine(line.text, line.num, credChan, emailChan, ipChan, domainChan, aixChan)
				}
			}
			return nil
		})
	}

	// Read and distribute lines
	go func() {
		defer close(lineChan)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			select {
			case lineChan <- struct {
				text string
				num  int
			}{scanner.Text(), lineNum}:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Wait for processing to complete
	if err := g.Wait(); err != nil {
		return err
	}

	// Close channels and wait for collectors
	close(credChan)
	close(emailChan)
	close(ipChan)
	close(domainChan)
	close(aixChan)
	wg.Wait()

	return scanner.Err()
}

// processLine analyzes a single line for patterns
func (a *Analyzer) processLine(line string, lineNum int, credChan chan<- Credential, emailChan chan<- string, ipChan chan<- string, domainChan chan<- string, aixChan chan<- AIXArtifact) {
	// Extract credentials
	for _, pattern := range a.credentialPatterns {
		matches := pattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) > 1 {
				credType := strings.Split(match[0], ":")[0]
				credChan <- Credential{
					Type:    strings.TrimSpace(credType),
					Value:   match[1],
					Context: truncateContext(line, 100),
					Line:    lineNum,
				}
			}
		}
	}

	// Extract emails
	emails := a.emailPattern.FindAllString(line, -1)
	for _, email := range emails {
		emailChan <- email
	}

	// Extract IPs
	ips := a.ipPattern.FindAllString(line, -1)
	for _, ip := range ips {
		ipChan <- ip
	}

	// Extract domains
	domains := a.domainPattern.FindAllString(line, -1)
	for _, domain := range domains {
		domainChan <- domain
	}

	// Extract AIX artifacts
	for artifactType, pattern := range a.aixPatterns {
		matches := pattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			aixChan <- AIXArtifact{
				Type:    artifactType,
				Value:   match[0],
				Context: truncateContext(line, 100),
				Line:    lineNum,
			}
		}
	}
}

// Helper functions and types
type readCloser struct {
	io.Reader
	io.Closer
}

type multiCloser struct {
	io.Reader
	closers []io.Closer
}

func (mc *multiCloser) Close() error {
	for _, closer := range mc.closers {
		closer.Close()
	}
	return nil
}

func detectFileType(filePath string) string {
	file, err := os.Open(filePath)
	if err != nil {
		return "unknown"
	}
	defer file.Close()

	header := make([]byte, 16)
	n, err := file.Read(header)
	if err != nil || n < 2 {
		return "unknown"
	}

	if header[0] == 0x1f && header[1] == 0x8b {
		return "gzip"
	}
	if header[0] == 'B' && header[1] == 'Z' && header[2] == 'h' {
		return "bzip2"
	}
	if strings.Contains(string(header[:10]), "pax") {
		return "pax"
	}

	return "text"
}

func truncateContext(text string, maxLen int) string {
	if len(text) <= maxLen {
		return text
	}
	return text[:maxLen] + "..."
}

// processLineWithChannels processes a line and sends results to appropriate channels
func (a *Analyzer) processLineWithChannels(line string, lineNum int, credChan chan<- Credential, emailChan chan<- string, ipChan chan<- string, domainChan chan<- string, aixChan chan<- AIXArtifact) {
	// Process credentials
	for _, pattern := range a.credentialPatterns {
		matches := pattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				cred := Credential{
					Type:    getCredentialType(pattern),
					Value:   match[1],
					Line:    lineNum,
					Context: line,
				}
				select {
				case credChan <- cred:
				default:
				}
			}
		}
	}
	
	// Process emails
	if matches := a.emailPattern.FindAllString(line, -1); len(matches) > 0 {
		for _, email := range matches {
			select {
			case emailChan <- email:
			default:
			}
		}
	}
	
	// Process IPs
	if matches := a.ipPattern.FindAllString(line, -1); len(matches) > 0 {
		for _, ip := range matches {
			select {
			case ipChan <- ip:
			default:
			}
		}
	}
	
	// Process domains
	if matches := a.domainPattern.FindAllString(line, -1); len(matches) > 0 {
		for _, domain := range matches {
			select {
			case domainChan <- domain:
			default:
			}
		}
	}
	
	// Process AIX artifacts
	for _, pattern := range a.aixPatterns {
		matches := pattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) >= 2 {
				artifact := AIXArtifact{
					Type:    getAIXType(pattern),
					Value:   match[1],
					Line:    lineNum,
					Context: line,
				}
				select {
				case aixChan <- artifact:
				default:
				}
			}
		}
	}
}

// getCredentialType determines credential type from regex pattern
func getCredentialType(pattern *regexp.Regexp) string {
	patternStr := pattern.String()
	switch {
	case strings.Contains(patternStr, "AKIA"):
		return "AWS Access Key"
	case strings.Contains(patternStr, "ghp_"):
		return "GitHub Token"
	case strings.Contains(patternStr, "xoxb"):
		return "Slack Token"
	case strings.Contains(patternStr, "password"):
		return "Password"
	case strings.Contains(patternStr, "api.?key"):
		return "API Key"
	case strings.Contains(patternStr, "BEGIN.*PRIVATE.*KEY"):
		return "Private Key"
	case strings.Contains(patternStr, "eyJ"):
		return "JWT Token"
	default:
		return "Unknown"
	}
}

// getAIXType determines AIX artifact type from regex pattern
func getAIXType(pattern *regexp.Regexp) string {
	patternStr := pattern.String()
	switch {
	case strings.Contains(patternStr, "[0-9]{4}.*[0-9]{4}.*[0-9]{4}.*[0-9]{4}"):
		return "Credit Card"
	case strings.Contains(patternStr, "[0-9]{3}-[0-9]{2}-[0-9]{4}"):
		return "SSN"
	default:
		return "Sensitive Data"
	}
}

