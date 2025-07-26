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
# Install latest version
curl -sSL https://raw.githubusercontent.com/a1ex-var1amov/flacon/main/scripts/install.sh | bash

# Install specific version
curl -sSL https://raw.githubusercontent.com/a1ex-var1amov/flacon/main/scripts/install.sh | bash -s -- -v v1.0.0

# Install to custom directory
curl -sSL https://raw.githubusercontent.com/a1ex-var1amov/flacon/main/scripts/install.sh | bash -s -- -d ~/.local/bin
```

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

## Usage

### Basic Usage

```bash
# Run reconnaissance (outputs YAML by default)
./flacon

# Show version information
./flacon version

# Show help
./flacon --help
```

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
