#!/bin/bash

echo "🚀 Perforator-Go Demo - High-Performance Penetration Testing Framework"
echo "=================================================================="

# Build the project
echo "📦 Building Perforator-Go..."
go build -o perforator-go .

# Demo 1: S3 Enumeration with high concurrency
echo ""
echo "🔍 Demo 1: High-Performance S3 Enumeration"
echo "Target: httpbin.org (demo endpoint)"
echo "Workers: 100 concurrent goroutines"
time ./perforator-go scan --target https://httpbin.org --mode s3 --workers 100 --timeout 5

# Demo 2: API Key Validation
echo ""
echo "🔑 Demo 2: API Key Validation"
echo "Testing multiple API services concurrently"
./perforator-go scan --api-key github:demo_key --api-key amplitude:demo_key --mode api --workers 20

# Demo 3: JSON Output
echo ""
echo "📊 Demo 3: JSON Output Format"
./perforator-go scan --target https://httpbin.org --mode s3 --workers 50 --output json | head -20

echo ""
echo "✅ Demo completed! Perforator-Go showcases:"
echo "   • Concurrent goroutine-based scanning"
echo "   • Memory-efficient streaming processing"
echo "   • Multiple output formats (console, JSON, XML, CSV)"
echo "   • Enterprise-grade error handling and logging"
echo "   • Configurable worker pools and rate limiting"
