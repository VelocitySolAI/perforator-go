# Perforator-Go Makefile - Go Implementation with Advanced Algorithms
# Original project: https://github.com/copyleftdev/perforator by copyleftdev
.PHONY: build test clean install demo benchmark edge-tests algorithms

# Build variables
BINARY_NAME=perforator-go
VERSION=2.1.0-advanced
BUILD_TIME=$(shell date +%Y-%m-%d_%H:%M:%S)
GO_VERSION=$(shell go version | cut -d' ' -f3)
LDFLAGS=-ldflags "-X main.Version=${VERSION} -X main.BuildTime=${BUILD_TIME} -X main.GoVersion=${GO_VERSION} -s -w"

# Default target
all: build

# Build the binary
build:
	@echo "🔨 Building Perforator-Go v${VERSION}..."
	go build ${LDFLAGS} -o ${BINARY_NAME} .
	@echo "✅ Build complete: ${BINARY_NAME}"

# Build optimized release binary
release:
	@echo "🚀 Building optimized release binary..."
	CGO_ENABLED=0 go build ${LDFLAGS} -a -installsuffix cgo -o ${BINARY_NAME} .
	@echo "✅ Release build complete"

# Cross-compile for multiple platforms
cross-compile:
	@echo "🌍 Cross-compiling for multiple platforms..."
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-linux-amd64 .
	GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-windows-amd64.exe .
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o ${BINARY_NAME}-darwin-arm64 .
	@echo "✅ Cross-compilation complete"

# Run tests
test:
	@echo "🧪 Running standard tests..."
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "✅ Tests complete"

# Run advanced algorithm edge case tests
edge-tests:
	@echo "🔬 Running advanced edge case tests..."
	./scripts/run_edge_tests.sh
	@echo "✅ Edge case tests complete"

# Run algorithm-specific tests
algorithms:
	@echo "🧠 Testing advanced algorithms..."
	go test -v ./internal/s3/ -run "TestS3.*Algorithm|TestS3.*Detection"
	go test -v ./internal/dump/ -run "TestDump.*Buffer|TestDump.*Concurrent"
	go test -v ./internal/api/ -run "TestAPI.*Validation|TestAPI.*Mock"
	@echo "✅ Algorithm tests complete"

# Run benchmarks
benchmark:
	@echo "⚡ Running performance benchmarks..."
	go test -bench=. -benchmem ./...

# Install dependencies
deps:
	@echo "📦 Installing dependencies..."
	go mod download
	go mod tidy

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -f ${BINARY_NAME}*
	rm -f coverage.out coverage.html
	go clean -cache
	@echo "✅ Clean complete"

# Install binary to GOPATH
install: build
	@echo "📥 Installing ${BINARY_NAME}..."
	go install ${LDFLAGS} .
	@echo "✅ Installation complete"

# Run demo
demo: build
	@echo "🎬 Running Perforator-Go demo..."
	./demo.sh

# Development setup
dev-setup:
	@echo "🛠️  Setting up development environment..."
	go install golang.org/x/tools/cmd/goimports@latest
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "✅ Development setup complete"

# Lint code
lint:
	@echo "🔍 Running linter..."
	golangci-lint run ./...

# Format code
fmt:
	@echo "🎨 Formatting code..."
	go fmt ./...
	goimports -w .

# Security scan
security:
	@echo "🔒 Running security scan..."
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	gosec ./...

# Performance profiling
profile: build
	@echo "📊 Running performance profile..."
	./$(BINARY_NAME) scan --target https://httpbin.org --mode s3 --workers 200 &
	sleep 2
	go tool pprof http://localhost:6060/debug/pprof/profile

# Docker build
docker:
	@echo "🐳 Building Docker image..."
	docker build -t perforator-go:${VERSION} .

# Comprehensive test suite
test-all: test edge-tests algorithms benchmark
	@echo "🎯 All tests completed"

# Performance stress tests
stress-test:
	@echo "💪 Running stress tests..."
	STRESS_TESTS=true VERBOSE=true ./scripts/run_edge_tests.sh
	@echo "✅ Stress tests complete"

# Help
help:
	@echo "Perforator-Go v${VERSION} - Go Implementation with Advanced Algorithms"
	@echo "Original: https://github.com/copyleftdev/perforator by copyleftdev"
	@echo ""
	@echo "Available targets:"
	@echo "  build         - Build the binary"
	@echo "  release       - Build optimized release binary"
	@echo "  cross-compile - Build for multiple platforms"
	@echo "  test          - Run standard tests with coverage"
	@echo "  edge-tests    - Run advanced edge case tests"
	@echo "  algorithms    - Test advanced algorithms specifically"
	@echo "  test-all      - Run comprehensive test suite"
	@echo "  stress-test   - Run performance stress tests"
	@echo "  benchmark     - Run performance benchmarks"
	@echo "  deps          - Install dependencies"
	@echo "  clean         - Clean build artifacts"
	@echo "  install       - Install binary to GOPATH"
	@echo "  demo          - Run interactive demo"
	@echo "  dev-setup     - Setup development environment"
	@echo "  lint          - Run code linter"
	@echo "  fmt           - Format code"
	@echo "  security      - Run security scan"
	@echo "  docker        - Build Docker image"
	@echo "  help          - Show this help"
