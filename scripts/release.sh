#!/bin/bash

# Release script for flacon
# A simple Kubernetes reconnaissance tool

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
    echo "Usage: $0 [OPTIONS] VERSION"
    echo ""
    echo "Options:"
    echo "  -m, --message MESSAGE    Custom release message"
    echo "  -p, --push               Push tag to remote (default: false)"
    echo "  -d, --dry-run            Show what would be done without doing it"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Arguments:"
    echo "  VERSION                  Version to release (e.g., v1.0.0)"
    echo ""
    echo "Examples:"
    echo "  $0 v1.0.0               # Create tag v1.0.0"
    echo "  $0 -p v1.0.0            # Create and push tag v1.0.0"
    echo "  $0 -m 'Initial release' v1.0.0  # Create tag with custom message"
    echo "  $0 -d v1.0.0            # Show what would be done"
}

# Function to validate version format
validate_version() {
    local version=$1
    
    # Check if version starts with 'v'
    if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+ ]]; then
        print_error "Version must be in format vX.Y.Z (e.g., v1.0.0)"
        exit 1
    fi
    
    # Check if version already exists
    if git tag -l | grep -q "^$version$"; then
        print_error "Version $version already exists"
        exit 1
    fi
}

# Function to check git status
check_git_status() {
    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        print_error "Not in a git repository"
        exit 1
    fi
    
    # Check if there are uncommitted changes
    if ! git diff-index --quiet HEAD --; then
        print_warning "You have uncommitted changes. Consider committing them first."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Check if we're on main branch
    local current_branch=$(git branch --show-current)
    if [[ "$current_branch" != "main" && "$current_branch" != "master" ]]; then
        print_warning "You're not on main/master branch (current: $current_branch)"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Function to create release
create_release() {
    local version=$1
    local message=$2
    local push=$3
    local dry_run=$4
    
    print_status "Creating release for version: $version"
    
    if [[ "$dry_run" == "true" ]]; then
        print_status "[DRY RUN] Would create tag: $version"
        print_status "[DRY RUN] Would use message: $message"
        if [[ "$push" == "true" ]]; then
            print_status "[DRY RUN] Would push tag to remote (triggers GitHub Actions)"
        fi
        return
    fi
    
    # Create tag
    if git tag -a "$version" -m "$message"; then
        print_success "Created tag: $version"
    else
        print_error "Failed to create tag"
        exit 1
    fi
    
    # Push tag if requested
    if [[ "$push" == "true" ]]; then
        print_status "Pushing tag to remote..."
        if git push origin "$version"; then
            print_success "Pushed tag to remote"
            print_status "✅ GitHub Actions will automatically:"
            print_status "   - Build for all platforms (Linux, macOS, Windows)"
            print_status "   - Create a GitHub release with binaries"
            print_status "   - Generate checksums for verification"
            print_status "   - Upload all files to the release"
            print_status ""
            print_status "Monitor progress at: https://github.com/a1ex-var1amov/flacon/actions"
        else
            print_error "Failed to push tag"
            exit 1
        fi
    else
        print_warning "Tag created locally. To trigger automated release, run:"
        print_status "  git push origin $version"
    fi
}

# Parse command line arguments
VERSION=""
MESSAGE=""
PUSH=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--message)
            MESSAGE="$2"
            shift 2
            ;;
        -p|--push)
            PUSH=true
            shift
            ;;
        -d|--dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        -*)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
        *)
            if [[ -z "$VERSION" ]]; then
                VERSION="$1"
            else
                print_error "Multiple versions specified: $VERSION and $1"
                exit 1
            fi
            shift
            ;;
    esac
done

# Check if version is provided
if [[ -z "$VERSION" ]]; then
    print_error "Version is required"
    show_usage
    exit 1
fi

# Set default message if not provided
if [[ -z "$MESSAGE" ]]; then
    MESSAGE="Release $VERSION"
fi

# Validate version format
validate_version "$VERSION"

# Check git status
check_git_status

# Show what will be done
print_status "Release Summary:"
print_status "  Version: $VERSION"
print_status "  Message: $MESSAGE"
print_status "  Push to remote: $PUSH"
print_status "  Dry run: $DRY_RUN"

if [[ "$DRY_RUN" != "true" ]]; then
    echo
    read -p "Continue with release? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Release cancelled"
        exit 0
    fi
fi

# Create release
create_release "$VERSION" "$MESSAGE" "$PUSH" "$DRY_RUN"

if [[ "$DRY_RUN" != "true" ]]; then
    print_success "Release process completed!"
    if [[ "$PUSH" == "true" ]]; then
        print_status "Check GitHub Actions to monitor the release build:"
        print_status "  https://github.com/a1ex-var1amov/flacon/actions"
    fi
fi 