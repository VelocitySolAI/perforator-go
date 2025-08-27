# Edge Case Testing Suite for Perforator-Go

This document describes the comprehensive edge case testing suite designed to rigorously test the perforator-go framework against various challenging scenarios and attack vectors.

## Overview

The edge case testing suite consists of mock servers and test scenarios that challenge every aspect of the perforator-go framework:

- **S3 Enumeration Edge Cases**: Malformed responses, timeouts, rate limiting, large payloads
- **API Validation Edge Cases**: Authentication failures, malicious JSON, network errors
- **Dump Analysis Edge Cases**: Corrupted files, memory stress, pattern edge cases
- **Integration Tests**: Multi-component scenarios with realistic failure modes
- **Performance & Stress Tests**: High-load scenarios and memory leak detection

## Test Files Structure

```
internal/
├── s3/enumerator_edge_test.go          # S3 enumeration edge cases
├── api/validator_edge_test.go          # API validation edge cases  
├── dump/analyzer_edge_test.go          # Dump analysis edge cases
├── scanner/scanner_integration_test.go # Integration tests
└── performance/stress_test.go          # Performance & stress tests

scripts/
└── run_edge_tests.sh                   # Test runner script
```

## Test Categories

### 1. S3 Enumeration Edge Cases (`internal/s3/enumerator_edge_test.go`)

**Mock Server Features:**
- Configurable delays and failure rates
- Rate limiting simulation
- Malformed XML responses
- Various HTTP status codes
- Large response payloads (10,000+ objects)
- Custom response scenarios

**Test Scenarios:**
- **Timeout Handling**: Servers that don't respond within timeout
- **Rate Limiting**: HTTP 429 responses with retry-after headers
- **Malformed Responses**: Invalid XML, non-XML responses, truncated data
- **Empty Buckets**: Buckets with no objects
- **Large Responses**: Buckets with thousands of objects
- **Sensitive File Detection**: Buckets containing passwords, keys, backups
- **Access Denied**: HTTP 403 forbidden responses
- **Not Found**: HTTP 404 bucket not found
- **Random Failures**: Intermittent server errors
- **Concurrency Stress**: High concurrent request loads
- **Memory Stress**: Extremely large object lists (100,000+ objects)
- **Malicious Payloads**: XML bombs, deeply nested structures, invalid UTF-8

### 2. API Validation Edge Cases (`internal/api/validator_edge_test.go`)

**Mock Server Features:**
- Service-specific response simulation (AWS, GitHub, Slack, Stripe)
- Authentication failure scenarios
- Rate limiting with proper headers
- Malformed JSON responses
- Custom response configuration

**Test Scenarios:**
- **AWS Edge Cases**: Invalid credentials, expired tokens, limited permissions
- **GitHub Edge Cases**: Revoked tokens, read-only access, bad credentials
- **Slack Edge Cases**: Expired tokens, invalid auth, limited scopes
- **Stripe Edge Cases**: Test vs live keys, authentication errors
- **Rate Limiting**: Proper retry-after handling
- **Timeout Scenarios**: Slow API responses
- **Malformed JSON**: Invalid JSON, incomplete responses, null bytes
- **Concurrency Testing**: Multiple simultaneous validations
- **Malicious Payloads**: JSON bombs, extremely large responses, invalid UTF-8
- **Retry Logic**: Intermittent failures with eventual success

### 3. Dump Analysis Edge Cases (`internal/dump/analyzer_edge_test.go`)

**Test Scenarios:**
- **Malformed Files**: Empty files, binary garbage, extremely large files (100MB+)
- **Encoding Issues**: Null bytes, mixed encodings, invalid UTF-8
- **Structured Data**: Malformed JSON, deeply nested structures, SQL dumps
- **Log Files**: Timestamped entries with mixed sensitive content
- **Pattern Edge Cases**: Various API key formats, password patterns, connection strings
- **Sensitive Data Types**: Private keys, JWT tokens, credit cards, SSNs
- **Performance Testing**: Large files with long lines, many patterns
- **Concurrency**: Multiple files analyzed simultaneously
- **Memory Stress**: Files with extremely long lines (10KB+ per line)
- **File System Issues**: Permission denied, files deleted during analysis

### 4. Integration Tests (`internal/scanner/scanner_integration_test.go`)

**Test Scenarios:**
- **Complete Security Scan**: All components working together
- **Mixed Results**: Some services succeed, others fail
- **Service-Specific Scans**: S3-only, API-only, dump-only modes
- **Error Handling**: Server unavailability, invalid inputs
- **Performance Testing**: Large-scale scans with many targets
- **Resource Management**: Proper cleanup and resource limits

**Mock Infrastructure:**
- Combined S3 and API mock servers
- Realistic test data generation
- Temporary file management
- Concurrent request simulation

### 5. Performance & Stress Tests (`internal/performance/stress_test.go`)

**Stress Test Features:**
- Configurable load parameters
- Memory usage monitoring
- Response time tracking
- Throughput measurement
- Error rate analysis

**Test Scenarios:**
- **S3 Enumeration Stress**: 1000+ concurrent bucket checks
- **API Validation Stress**: 500+ concurrent API validations
- **Dump Analysis Stress**: 50+ large files (10MB each)
- **Memory Leak Detection**: Repeated operations with GC monitoring
- **Throughput Testing**: Requests per second measurement
- **Resource Limits**: Memory and CPU usage validation

## Running the Tests

### Quick Start

```bash
# Run all edge case tests (excluding stress tests)
./scripts/run_edge_tests.sh

# Run with verbose output
./scripts/run_edge_tests.sh -v

# Include stress tests (takes longer)
./scripts/run_edge_tests.sh -s

# Run specific test categories
go test -v ./internal/s3 -run TestS3EdgeCases
go test -v ./internal/api -run TestAPIValidationEdgeCases
go test -v ./internal/dump -run TestDumpAnalyzer
```

### Test Runner Options

```bash
./scripts/run_edge_tests.sh [OPTIONS]

Options:
  -v, --verbose     Enable verbose output
  -s, --stress      Run stress tests (takes longer)
  --no-parallel     Disable parallel test execution
  --timeout DURATION Set test timeout (default: 30m)
  -h, --help        Show help message
```

### Environment Variables

```bash
export VERBOSE=true        # Enable verbose output
export STRESS_TESTS=true   # Run stress tests
export PARALLEL=false      # Disable parallel execution
```

## Test Metrics and Validation

### Performance Benchmarks

- **S3 Enumeration**: >10 RPS throughput, <1s average response time
- **API Validation**: >5 RPS throughput, <2s average response time  
- **Dump Analysis**: >1 file/sec, handles 100MB+ files
- **Memory Usage**: <500MB peak memory during stress tests
- **Error Handling**: <20% failure rate under stress conditions

### Security Validations

- **Malicious Payload Resistance**: No crashes from XML/JSON bombs
- **Memory Safety**: No memory leaks during extended operations
- **Input Validation**: Proper handling of invalid UTF-8, null bytes
- **Resource Limits**: Bounded memory and CPU usage
- **Timeout Handling**: Graceful handling of slow/unresponsive services

## Mock Server Architecture

### S3 Mock Server
- Simulates AWS S3 ListBucket API
- Configurable response scenarios
- Rate limiting and error injection
- Large payload generation
- Malicious content simulation

### API Mock Server  
- Multi-service simulation (AWS, GitHub, Slack, Stripe)
- Authentication flow simulation
- Rate limiting with proper headers
- Malformed response generation
- Service-specific error codes

## Best Practices for Edge Case Testing

1. **Comprehensive Coverage**: Test both happy path and failure scenarios
2. **Realistic Payloads**: Use real-world data sizes and patterns
3. **Concurrency Testing**: Validate thread safety and resource sharing
4. **Memory Management**: Monitor for leaks and excessive usage
5. **Error Propagation**: Ensure errors are properly handled and reported
6. **Timeout Handling**: Test various timeout scenarios
7. **Resource Cleanup**: Verify proper cleanup of temporary resources

## Extending the Test Suite

### Adding New Edge Cases

1. **Identify Edge Case**: Document the specific scenario to test
2. **Create Mock Response**: Add appropriate mock server behavior
3. **Write Test Case**: Create test with expected behavior validation
4. **Update Documentation**: Document the new test scenario
5. **Add to Test Runner**: Include in the automated test script

### Mock Server Extensions

```go
// Add new scenario to mock server
mock.SetCustomResponse("/new-endpoint", MockResponse{
    StatusCode: 500,
    Body:       `{"error": "custom error scenario"}`,
    Headers:    map[string]string{"Retry-After": "5"},
})
```

### Performance Test Extensions

```go
// Add new stress test configuration
config := StressTestConfig{
    MaxConcurrency:  100,
    RequestCount:    2000,
    PayloadSizeKB:   200,
    TestDurationSec: 60,
    ErrorRate:       0.05,
}
```

## Troubleshooting

### Common Issues

1. **Test Timeouts**: Increase timeout with `--timeout 60m`
2. **Memory Issues**: Run stress tests individually
3. **Port Conflicts**: Mock servers use random ports
4. **File Permissions**: Ensure temp directory is writable
5. **Resource Limits**: Check system ulimits for file descriptors

### Debug Mode

```bash
# Run with maximum verbosity
VERBOSE=true go test -v -race ./internal/s3 -run TestS3EdgeCases

# Run single test with detailed output
go test -v ./internal/api -run TestAPIValidationEdgeCases/AWS_Invalid_credentials
```

## Continuous Integration

The edge case tests are designed to run in CI environments:

```yaml
# Example GitHub Actions configuration
- name: Run Edge Case Tests
  run: |
    ./scripts/run_edge_tests.sh -v
    
- name: Run Stress Tests (Nightly)
  run: |
    ./scripts/run_edge_tests.sh -v -s
  if: github.event_name == 'schedule'
```

## Conclusion

This comprehensive edge case testing suite ensures that perforator-go is robust, secure, and performant under various challenging conditions. The tests cover realistic failure scenarios, security attack vectors, and performance stress conditions that the framework may encounter in production environments.

Regular execution of these tests helps maintain code quality and prevents regressions when adding new features or making changes to the codebase.
