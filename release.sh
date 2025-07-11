#!/bin/bash

# release.sh - Create git tag from CMakeLists.txt version
# Usage: ./release.sh [--dry-run] [--force]

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default options
DRY_RUN=false
FORCE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--dry-run] [--force]"
            echo "  --dry-run    Show what would be done without making changes"
            echo "  --force      Force create tag even if it already exists"
            echo "  --help       Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Function to print colored output
print_info() {
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

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    print_error "This is not a git repository!"
    exit 1
fi

# Check if CMakeLists.txt exists
if [[ ! -f "CMakeLists.txt" ]]; then
    print_error "CMakeLists.txt not found in current directory!"
    exit 1
fi

print_info "Reading version from CMakeLists.txt..."

# Extract version components from CMakeLists.txt
MAJOR=$(grep "set(CVC_MAJOR" CMakeLists.txt | sed 's/.*set(CVC_MAJOR \([0-9]*\)).*/\1/')
MINOR=$(grep "set(CVC_MINOR" CMakeLists.txt | sed 's/.*set(CVC_MINOR \([0-9]*\)).*/\1/')
PATCH=$(grep "set(CVC_PATCH" CMakeLists.txt | sed 's/.*set(CVC_PATCH \([0-9]*\)).*/\1/')

# Validate that we found version numbers
if [[ -z "$MAJOR" || -z "$MINOR" || -z "$PATCH" ]]; then
    print_error "Failed to extract version numbers from CMakeLists.txt"
    print_error "Expected format: set(CVC_MAJOR X), set(CVC_MINOR Y), set(CVC_PATCH Z)"
    exit 1
fi

# Validate that version numbers are integers
if ! [[ "$MAJOR" =~ ^[0-9]+$ ]] || ! [[ "$MINOR" =~ ^[0-9]+$ ]] || ! [[ "$PATCH" =~ ^[0-9]+$ ]]; then
    print_error "Version numbers must be integers"
    print_error "Found: MAJOR=$MAJOR, MINOR=$MINOR, PATCH=$PATCH"
    exit 1
fi

# Construct version string and tag
VERSION="$MAJOR.$MINOR.$PATCH"
TAG="v$VERSION"

print_success "Found version: $VERSION"
print_info "Git tag will be: $TAG"

# Check if working directory is clean
if [[ -n $(git status --porcelain) ]]; then
    print_warning "Working directory has uncommitted changes:"
    git status --short
    echo
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Aborted by user"
        exit 0
    fi
fi

# Check if tag already exists
if git rev-parse --verify "refs/tags/$TAG" >/dev/null 2>&1; then
    if [[ "$FORCE" == "true" ]]; then
        print_warning "Tag $TAG already exists, will be overwritten due to --force"
    else
        print_error "Tag $TAG already exists!"
        print_info "Use --force to overwrite existing tag"
        print_info "Or update the version in CMakeLists.txt"
        exit 1
    fi
fi

# Check if we're on main/master branch
CURRENT_BRANCH=$(git branch --show-current)
if [[ "$CURRENT_BRANCH" != "main" && "$CURRENT_BRANCH" != "master" ]]; then
    print_warning "You are on branch '$CURRENT_BRANCH', not main/master"
    read -p "Continue creating tag on this branch? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Aborted by user"
        exit 0
    fi
fi

# Get current commit hash
COMMIT_HASH=$(git rev-parse HEAD)
SHORT_HASH=$(git rev-parse --short HEAD)

print_info "Current commit: $SHORT_HASH"
print_info "Current branch: $CURRENT_BRANCH"

if [[ "$DRY_RUN" == "true" ]]; then
    print_warning "DRY RUN MODE - No changes will be made"
    echo
    print_info "Would create tag: $TAG"
    print_info "On commit: $COMMIT_HASH"
    print_info "Commands that would be executed:"
    if [[ "$FORCE" == "true" ]]; then
        echo "  git tag -d $TAG (if exists)"
        echo "  git push origin :refs/tags/$TAG (if exists remotely)"
    fi
    echo "  git tag -a $TAG -m \"Release version $VERSION\""
    echo "  git push origin $TAG"
    exit 0
fi

# Final confirmation
echo
print_info "Ready to create and push tag:"
echo "  Tag: $TAG"
echo "  Version: $VERSION"
echo "  Commit: $SHORT_HASH"
echo "  Branch: $CURRENT_BRANCH"
echo
read -p "Proceed with creating the release tag? (y/N): " -n 1 -r
echo

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    print_info "Aborted by user"
    exit 0
fi

# Delete existing tag if force is enabled
if [[ "$FORCE" == "true" ]] && git rev-parse --verify "refs/tags/$TAG" >/dev/null 2>&1; then
    print_info "Deleting existing local tag: $TAG"
    git tag -d "$TAG"

    # Check if tag exists on remote and delete it
    if git ls-remote --tags origin | grep -q "refs/tags/$TAG$"; then
        print_info "Deleting existing remote tag: $TAG"
        git push origin ":refs/tags/$TAG"
    fi
fi

# Create the annotated tag
print_info "Creating annotated tag: $TAG"
git tag -a "$TAG" -m "Release version $VERSION

Generated from CMakeLists.txt version:
- CVC_MAJOR: $MAJOR
- CVC_MINOR: $MINOR
- CVC_PATCH: $PATCH

Commit: $COMMIT_HASH"

# Push the tag to origin
print_info "Pushing tag to origin..."
git push origin "$TAG"

print_success "Successfully created and pushed tag: $TAG"
print_success "GitHub Actions will now build and create a release for version $VERSION"

# Show next steps
echo
print_info "Next steps:"
echo "  1. Monitor the GitHub Actions workflow at:"
echo "     https://github.com/$(git config --get remote.origin.url | sed 's/.*github.com[:/]\([^.]*\).*/\1/')/actions"
echo "  2. Once complete, the release will be available at:"
echo "     https://github.com/$(git config --get remote.origin.url | sed 's/.*github.com[:/]\([^.]*\).*/\1/')/releases/tag/$TAG"
echo "  3. To increment version for next release, update CMakeLists.txt:"
echo "     - CVC_MAJOR, CVC_MINOR, or CVC_PATCH values"