# Makefile for flacon
# A simple Kubernetes reconnaissance tool

# Variables
BINARY_NAME=flacon
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT_SHA=$(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-X github.com/a1ex-var1amov/flacon/version.Version=${VERSION} -X github.com/a1ex-var1amov/flacon/version.CommitSHA=${COMMIT_SHA} -X github.com/a1ex-var1amov/flacon/version.BuildTime=${BUILD_TIME}"

# Default target
.PHONY: all
all: build

# Build the application
.PHONY: build
build:
	@echo "Building ${BINARY_NAME} version ${VERSION}..."
	go build ${LDFLAGS} -o ${BINARY_NAME} .

# Build for multiple platforms
.PHONY: build-all
build-all: build-linux build-darwin build-windows

# Build for Linux
.PHONY: build-linux
build-linux:
	@echo "Building for Linux..."
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o ${BINARY_NAME}-linux-arm64 .

# Build for macOS
.PHONY: build-darwin
build-darwin:
	@echo "Building for macOS..."
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o ${BINARY_NAME}-darwin-arm64 .

# Build for Windows
.PHONY: build-windows
build-windows:
	@echo "Building for Windows..."
	GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o ${BINARY_NAME}-windows-amd64.exe .
	GOOS=windows GOARCH=arm64 go build ${LDFLAGS} -o ${BINARY_NAME}-windows-arm64.exe .

# Install the application
.PHONY: install
install:
	@echo "Installing ${BINARY_NAME}..."
	go install ${LDFLAGS} .

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -f ${BINARY_NAME}
	rm -f ${BINARY_NAME}-*
	rm -f *.exe

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

# Run the application
.PHONY: run
run: build
	@echo "Running ${BINARY_NAME}..."
	./${BINARY_NAME}

# Show version information
.PHONY: version
version: build
	@echo "Version information:"
	./${BINARY_NAME} version

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build        - Build the application"
	@echo "  build-all    - Build for all platforms (Linux, macOS, Windows)"
	@echo "  build-linux  - Build for Linux (amd64, arm64)"
	@echo "  build-darwin - Build for macOS (amd64, arm64)"
	@echo "  build-windows- Build for Windows (amd64, arm64)"
	@echo "  install      - Install the application"
	@echo "  clean        - Clean build artifacts"
	@echo "  test         - Run tests"
	@echo "  run          - Build and run the application"
	@echo "  version      - Show version information"
	@echo "  help         - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION      - Set version (default: git describe or 'dev')"
	@echo ""
	@echo "Examples:"
	@echo "  make build VERSION=1.0.0"
	@echo "  make build-all"
	@echo "  make version" 