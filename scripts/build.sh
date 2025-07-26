#!/bin/bash

# Build script for flacon
# A simple Kubernetes reconnaissance tool

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
VERSION=""
PLATFORM=""
ARCH=""
OUTPUT_DIR="dist"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -v, --version VERSION    Set version (default: git describe or 'dev')"
    echo "  -p, --platform PLATFORM  Target platform (linux, darwin, windows, all)"
    echo "  -a, --arch ARCH          Target architecture (amd64, arm64, all)"
    echo "  -o, --output DIR         Output directory (default: dist)"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                                    # Build for current platform"
    echo "  $0 -v 1.0.0                          # Build with specific version"
    echo "  $0 -p linux -a amd64                 # Build for Linux AMD64"
    echo "  $0 -p all -a all -v 1.0.0            # Build all platforms with version"
    echo "  $0 -o ./binaries                     # Build to custom output directory"
}

# Function to get git version
get_git_version() {
    if command -v git >/dev/null 2>&1; then
        git describe --tags --always --dirty 2>/dev/null || echo "dev"
    else
        echo "dev"
    fi
}

# Function to get git commit SHA
get_git_commit() {
    if command -v git >/dev/null 2>&1; then
        git rev-parse HEAD 2>/dev/null || echo "unknown"
    else
        echo "unknown"
    fi
}

# Function to build for specific platform and architecture
build_binary() {
    local platform=$1
    local arch=$2
    local version=$3
    local output_dir=$4
    
    local binary_name="flacon"
    if [[ "$platform" == "windows" ]]; then
        binary_name="${binary_name}.exe"
    fi
    
    local output_file="${output_dir}/${binary_name}-${platform}-${arch}"
    if [[ "$platform" == "windows" ]]; then
        output_file="${output_file}.exe"
    fi
    
    print_status "Building for ${platform}/${arch}..."
    
    # Set environment variables for cross-compilation
    export GOOS=$platform
    export GOARCH=$arch
    
    # Build with ldflags
    local commit_sha=$(get_git_commit)
    local build_time=$(date -u '+%Y-%m-%d_%H:%M:%S')
    local ldflags="-X github.com/a1ex-var1amov/flacon/version.Version=${version} -X github.com/a1ex-var1amov/flacon/version.CommitSHA=${commit_sha} -X github.com/a1ex-var1amov/flacon/version.BuildTime=${build_time}"
    
    if go build -ldflags "$ldflags" -o "$output_file" .; then
        print_success "Built: $output_file"
    else
        print_error "Failed to build for ${platform}/${arch}"
        return 1
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -p|--platform)
            PLATFORM="$2"
            shift 2
            ;;
        -a|--arch)
            ARCH="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Set default version if not provided
if [[ -z "$VERSION" ]]; then
    VERSION=$(get_git_version)
fi

print_status "Building flacon version: $VERSION"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Determine platforms and architectures to build
platforms=()
architectures=()

if [[ -z "$PLATFORM" ]]; then
    # Default to current platform
    platforms=("$(go env GOOS)")
elif [[ "$PLATFORM" == "all" ]]; then
    platforms=("linux" "darwin" "windows")
else
    platforms=("$PLATFORM")
fi

if [[ -z "$ARCH" ]]; then
    # Default to current architecture
    architectures=("$(go env GOARCH)")
elif [[ "$ARCH" == "all" ]]; then
    architectures=("amd64" "arm64")
else
    architectures=("$ARCH")
fi

# Build for each platform and architecture combination
for platform in "${platforms[@]}"; do
    for arch in "${architectures[@]}"; do
        if ! build_binary "$platform" "$arch" "$VERSION" "$OUTPUT_DIR"; then
            print_error "Build failed for ${platform}/${arch}"
            exit 1
        fi
    done
done

print_success "All builds completed successfully!"
print_status "Binaries are available in: $OUTPUT_DIR"

# List built binaries
echo ""
print_status "Built binaries:"
ls -la "$OUTPUT_DIR"/flacon* 