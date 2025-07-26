#!/bin/bash

# Installation script for flacon
# A simple Kubernetes reconnaissance tool

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
VERSION="latest"
INSTALL_DIR="/usr/local/bin"
REPO="a1ex-var1amov/flacon"

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
    echo "  -v, --version VERSION    Install specific version (default: latest)"
    echo "  -d, --dir DIR            Installation directory (default: /usr/local/bin)"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                       # Install latest version"
    echo "  $0 -v v1.0.0            # Install specific version"
    echo "  $0 -d ~/.local/bin       # Install to custom directory"
}

# Function to detect OS and architecture
detect_platform() {
    local os=$(uname -s | tr '[:upper:]' '[:lower:]')
    local arch=$(uname -m)
    
    case $arch in
        x86_64)
            arch="amd64"
            ;;
        aarch64|arm64)
            arch="arm64"
            ;;
        *)
            print_error "Unsupported architecture: $arch"
            exit 1
            ;;
    esac
    
    echo "${os}-${arch}"
}

# Function to get latest version
get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -s "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/'
    else
        print_error "curl is required to get latest version"
        exit 1
    fi
}

# Function to download and install
install_flacon() {
    local version=$1
    local install_dir=$2
    
    print_status "Installing flacon version: $version"
    
    # Detect platform
    local platform=$(detect_platform)
    print_status "Detected platform: $platform"
    
    # Create installation directory if it doesn't exist
    if [[ ! -d "$install_dir" ]]; then
        print_status "Creating installation directory: $install_dir"
        mkdir -p "$install_dir"
    fi
    
    # Download URL
    local download_url="https://github.com/${REPO}/releases/download/${version}/flacon-${platform}"
    local binary_path="${install_dir}/flacon"
    
    print_status "Downloading from: $download_url"
    
    # Download binary
    if curl -L -o "$binary_path" "$download_url"; then
        print_success "Downloaded flacon to $binary_path"
    else
        print_error "Failed to download flacon"
        exit 1
    fi
    
    # Make executable
    chmod +x "$binary_path"
    print_success "Made flacon executable"
    
    # Verify installation
    if "$binary_path" version >/dev/null 2>&1; then
        print_success "Installation verified successfully"
        echo ""
        print_status "flacon has been installed to: $binary_path"
        print_status "Version information:"
        "$binary_path" version
    else
        print_error "Installation verification failed"
        exit 1
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--version)
            VERSION="$2"
            shift 2
            ;;
        -d|--dir)
            INSTALL_DIR="$2"
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

# Check if running as root for system-wide installation
if [[ "$INSTALL_DIR" == "/usr/local/bin" && "$EUID" -ne 0 ]]; then
    print_warning "Installing to system directory. You may need to run with sudo."
fi

# Get latest version if not specified
if [[ "$VERSION" == "latest" ]]; then
    print_status "Getting latest version..."
    VERSION=$(get_latest_version)
    print_status "Latest version: $VERSION"
fi

# Install flacon
install_flacon "$VERSION" "$INSTALL_DIR"

print_success "Installation completed!"
print_status "You can now run: flacon --help" 