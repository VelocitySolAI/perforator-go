#!/bin/bash

# Comprehensive Edge Case Test Runner for Perforator-Go
# This script runs all rigorous tests with proper configuration

set -e

echo "🚀 Starting Perforator-Go Edge Case Test Suite"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TIMEOUT="30m"
VERBOSE=${VERBOSE:-false}
STRESS_TESTS=${STRESS_TESTS:-false}
PARALLEL=${PARALLEL:-true}

print_section() {
    echo -e "\n${BLUE}📋 $1${NC}"
    echo "----------------------------------------"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to run tests with proper flags
run_test_suite() {
    local package=$1
    local description=$2
    local extra_flags=$3
    
    print_section "Running $description"
    
    local cmd="go test"
    if [ "$VERBOSE" = true ]; then
        cmd="$cmd -v"
    fi
    if [ "$PARALLEL" = true ]; then
        cmd="$cmd -parallel 4"
    fi
    cmd="$cmd -timeout $TIMEOUT $extra_flags ./$package"
    
    echo "Command: $cmd"
    
    if eval $cmd; then
        print_success "$description completed successfully"
        return 0
    else
        print_error "$description failed"
        return 1
    fi
}

# Main test execution
main() {
    echo "Configuration:"
    echo "  Timeout: $TIMEOUT"
    echo "  Verbose: $VERBOSE"
    echo "  Stress Tests: $STRESS_TESTS"
    echo "  Parallel: $PARALLEL"
    echo ""
    
    # Track test results
    local total_tests=0
    local passed_tests=0
    local failed_tests=0
    
    # 1. S3 Edge Case Tests
    print_section "S3 Enumerator Edge Cases"
    total_tests=$((total_tests + 1))
    if run_test_suite "internal/s3" "S3 Edge Case Tests" "-run TestS3EdgeCases"; then
        passed_tests=$((passed_tests + 1))
    else
        failed_tests=$((failed_tests + 1))
    fi
    
    # 2. API Validator Edge Cases
    print_section "API Validator Edge Cases"
    total_tests=$((total_tests + 1))
    if run_test_suite "internal/api" "API Validation Edge Cases" "-run TestAPIValidationEdgeCases"; then
        passed_tests=$((passed_tests + 1))
    else
        failed_tests=$((failed_tests + 1))
    fi
    
    # 3. Dump Analyzer Edge Cases
    print_section "Dump Analyzer Edge Cases"
    total_tests=$((total_tests + 1))
    if run_test_suite "internal/dump" "Dump Analysis Edge Cases" "-run TestDumpAnalyzer"; then
        passed_tests=$((passed_tests + 1))
    else
        failed_tests=$((failed_tests + 1))
    fi
    
    # 4. Integration Tests
    print_section "Integration Tests"
    total_tests=$((total_tests + 1))
    if run_test_suite "internal/scanner" "Integration Tests" "-run TestFullIntegration"; then
        passed_tests=$((passed_tests + 1))
    else
        failed_tests=$((failed_tests + 1))
    fi
    
    # 5. Concurrency Tests
    print_section "Concurrency Tests"
    total_tests=$((total_tests + 1))
    if run_test_suite "internal/s3" "S3 Concurrency Tests" "-run TestS3ConcurrencyEdgeCases"; then
        passed_tests=$((passed_tests + 1))
    else
        failed_tests=$((failed_tests + 1))
    fi
    
    total_tests=$((total_tests + 1))
    if run_test_suite "internal/api" "API Concurrency Tests" "-run TestAPIValidationConcurrency"; then
        passed_tests=$((passed_tests + 1))
    else
        failed_tests=$((failed_tests + 1))
    fi
    
    total_tests=$((total_tests + 1))
    if run_test_suite "internal/dump" "Dump Concurrency Tests" "-run TestDumpAnalyzerConcurrency"; then
        passed_tests=$((passed_tests + 1))
    else
        failed_tests=$((failed_tests + 1))
    fi
    
    # 6. Malicious Payload Tests
    print_section "Security Tests (Malicious Payloads)"
    total_tests=$((total_tests + 1))
    if run_test_suite "internal/s3" "S3 Malicious Payload Tests" "-run TestS3MaliciousPayloads"; then
        passed_tests=$((passed_tests + 1))
    else
        failed_tests=$((failed_tests + 1))
    fi
    
    total_tests=$((total_tests + 1))
    if run_test_suite "internal/api" "API Malicious Payload Tests" "-run TestAPIValidationMaliciousPayloads"; then
        passed_tests=$((passed_tests + 1))
    else
        failed_tests=$((failed_tests + 1))
    fi
    
    # 7. Stress Tests (optional)
    if [ "$STRESS_TESTS" = true ]; then
        print_section "Performance & Stress Tests"
        print_warning "Running stress tests - this may take a while..."
        
        total_tests=$((total_tests + 1))
        if run_test_suite "internal/performance" "S3 Stress Tests" "-run TestS3EnumeratorStress"; then
            passed_tests=$((passed_tests + 1))
        else
            failed_tests=$((failed_tests + 1))
        fi
        
        total_tests=$((total_tests + 1))
        if run_test_suite "internal/performance" "API Stress Tests" "-run TestAPIValidatorStress"; then
            passed_tests=$((passed_tests + 1))
        else
            failed_tests=$((failed_tests + 1))
        fi
        
        total_tests=$((total_tests + 1))
        if run_test_suite "internal/performance" "Dump Analysis Stress Tests" "-run TestDumpAnalyzerStress"; then
            passed_tests=$((passed_tests + 1))
        else
            failed_tests=$((failed_tests + 1))
        fi
        
        total_tests=$((total_tests + 1))
        if run_test_suite "internal/performance" "Memory Leak Detection" "-run TestMemoryLeakDetection"; then
            passed_tests=$((passed_tests + 1))
        else
            failed_tests=$((failed_tests + 1))
        fi
    else
        print_warning "Skipping stress tests (set STRESS_TESTS=true to enable)"
    fi
    
    # 8. Memory and Performance Tests
    print_section "Memory & Performance Tests"
    total_tests=$((total_tests + 1))
    if run_test_suite "internal/s3" "S3 Memory Stress Tests" "-run TestS3MemoryStress"; then
        passed_tests=$((passed_tests + 1))
    else
        failed_tests=$((failed_tests + 1))
    fi
    
    total_tests=$((total_tests + 1))
    if run_test_suite "internal/dump" "Dump Memory Stress Tests" "-run TestDumpAnalyzerMemoryStress"; then
        passed_tests=$((passed_tests + 1))
    else
        failed_tests=$((failed_tests + 1))
    fi
    
    # Final Results
    echo ""
    echo "=============================================="
    echo "🏁 Test Suite Complete"
    echo "=============================================="
    echo "Total Test Suites: $total_tests"
    print_success "Passed: $passed_tests"
    if [ $failed_tests -gt 0 ]; then
        print_error "Failed: $failed_tests"
    else
        echo -e "${GREEN}Failed: $failed_tests${NC}"
    fi
    
    local success_rate=$((passed_tests * 100 / total_tests))
    echo "Success Rate: $success_rate%"
    
    if [ $failed_tests -eq 0 ]; then
        print_success "All edge case tests passed! 🎉"
        echo ""
        echo "Your perforator-go framework is robust and handles edge cases well."
        echo "The following scenarios have been thoroughly tested:"
        echo "  • Malformed responses and payloads"
        echo "  • Network timeouts and failures"
        echo "  • Rate limiting and authentication errors"
        echo "  • Concurrent access patterns"
        echo "  • Memory stress and leak detection"
        echo "  • Large file processing"
        echo "  • Security attack simulations"
        return 0
    else
        print_error "Some tests failed. Please review the output above."
        return 1
    fi
}

# Handle command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -s|--stress)
            STRESS_TESTS=true
            shift
            ;;
        --no-parallel)
            PARALLEL=false
            shift
            ;;
        --timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose     Enable verbose output"
            echo "  -s, --stress      Run stress tests (takes longer)"
            echo "  --no-parallel     Disable parallel test execution"
            echo "  --timeout DURATION Set test timeout (default: 30m)"
            echo "  -h, --help        Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  VERBOSE=true      Same as -v"
            echo "  STRESS_TESTS=true Same as -s"
            echo "  PARALLEL=false    Same as --no-parallel"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use -h or --help for usage information"
            exit 1
            ;;
    esac
done

# Run the main function
main
