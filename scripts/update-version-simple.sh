#!/bin/bash

###############################################################################
#!/bin/bash

# Silver Assist Security Essentials - Simple Version Update Script
#
# A more robust version updater that handles macOS sed quirks better
#
# Usage: ./scripts/update-version-simple.sh <new-version> [--no-confirm]
# Example: ./scripts/update-version-simple.sh 1.0.3
#
# @package SilverAssist\Security
# @since 1.0.0
# @author Silver Assist
# @version 1.0.1
###############################################################################

set -e  # Exit on any error

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

# Validate input
if [ $# -eq 0 ]; then
    print_error "No version specified"
    echo "Usage: $0 <new-version> [--no-confirm]"
    echo "Example: $0 1.0.3"
    echo "Example: $0 1.0.3 --no-confirm"
    exit 1
fi

NEW_VERSION="$1"
NO_CONFIRM=false

# Parse arguments
if [ $# -eq 2 ] && [ "$2" = "--no-confirm" ]; then
    NO_CONFIRM=true
elif [ $# -gt 1 ] && [ "$2" != "--no-confirm" ]; then
    print_error "Invalid argument: $2"
    echo "Usage: $0 <new-version> [--no-confirm]"
    exit 1
fi

# Validate version format
if ! [[ $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    print_error "Invalid version format. Use semantic versioning (e.g., 1.0.3)"
    exit 1
fi

# Get project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

print_status "Updating Silver Assist Security Essentials to version ${NEW_VERSION}"
print_status "Project root: ${PROJECT_ROOT}"

# Check if we're in the right directory
if [ ! -f "${PROJECT_ROOT}/silver-assist-security.php" ]; then
    print_error "Main plugin file not found. Make sure you're running this from the project root."
    exit 1
fi

# Get current version
CURRENT_VERSION=$(grep -o "Version: [0-9]\+\.[0-9]\+\.[0-9]\+" "${PROJECT_ROOT}/silver-assist-security.php" | cut -d' ' -f2)

if [ -z "$CURRENT_VERSION" ]; then
    print_error "Could not detect current version"
    exit 1
fi

print_status "Current version: ${CURRENT_VERSION}"
print_status "New version: ${NEW_VERSION}"

# Check if versions are the same
if [ "$CURRENT_VERSION" = "$NEW_VERSION" ]; then
    print_warning "Current version and new version are the same (${NEW_VERSION})"
    if [ "$NO_CONFIRM" = false ]; then
        echo ""
        read -p "$(echo -e ${YELLOW}[CONFIRM]${NC} Continue anyway? [y/N]: )" -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_warning "Version update cancelled"
            exit 0
        fi
    else
        print_status "Same version detected in CI mode - exiting successfully (no changes needed)"
        exit 0
    fi
else
    # Confirm with user only if not in no-confirm mode
    if [ "$NO_CONFIRM" = false ]; then
        echo ""
        read -p "$(echo -e ${YELLOW}[CONFIRM]${NC} Update version from ${CURRENT_VERSION} to ${NEW_VERSION}? [y/N]: )" -n 1 -r
        echo ""

        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_warning "Version update cancelled"
            exit 0
        fi
    else
        print_status "Running in non-interactive mode (--no-confirm)"
    fi
fi

echo ""
print_status "Starting version update process..."

# Function to update file using perl (more reliable than sed on macOS)
update_file() {
    local file="$1"
    local pattern="$2"
    local description="$3"
    
    if [ -f "$file" ]; then
        # Create backup
        cp "$file" "$file.bak"
        
        # Apply perl substitution
        if perl -i -pe "$pattern" "$file" 2>/dev/null; then
            # Verify the change was made
            if ! cmp -s "$file" "$file.bak"; then
                print_status "  Updated $description"
                rm "$file.bak"
                return 0
            else
                print_warning "  No changes made to $description (pattern not found)"
                mv "$file.bak" "$file"
                return 1
            fi
        else
            print_error "  Failed to update $description"
            mv "$file.bak" "$file"
            return 1
        fi
    else
        print_warning "  File not found: $file"
        return 1
    fi
}

# 1. Update main plugin file
print_status "Updating main plugin file..."

# Update plugin header
update_file "${PROJECT_ROOT}/silver-assist-security.php" \
    "s/Version: [0-9]+\\.[0-9]+\\.[0-9]+/Version: ${NEW_VERSION}/g" \
    "plugin header"

# Update constant
update_file "${PROJECT_ROOT}/silver-assist-security.php" \
    "s/define\\('SILVER_ASSIST_SECURITY_VERSION', '[0-9]+\\.[0-9]+\\.[0-9]+'\\)/define('SILVER_ASSIST_SECURITY_VERSION', '${NEW_VERSION}')/g" \
    "plugin constant"

# Update @version tag
update_file "${PROJECT_ROOT}/silver-assist-security.php" \
    "s/\\@version [0-9]+\\.[0-9]+\\.[0-9]+/\\@version ${NEW_VERSION}/g" \
    "main file @version tag"

print_success "Main plugin file updated"

# 2. Update PHP files
print_status "Updating PHP files..."

find "${PROJECT_ROOT}/src" -name "*.php" -print0 | while IFS= read -r -d '' file; do
    if grep -q "@version" "$file"; then
        update_file "$file" \
            "s/\\@version [0-9]+\\.[0-9]+\\.[0-9]+/\\@version ${NEW_VERSION}/g" \
            "$(basename "$file")"
    fi
done

print_success "PHP files updated"

# 3. Update CSS files  
print_status "Updating CSS files..."

if [ -d "${PROJECT_ROOT}/assets/css" ]; then
    find "${PROJECT_ROOT}/assets/css" -name "*.css" -print0 | while IFS= read -r -d '' file; do
        if grep -q "@version" "$file"; then
            update_file "$file" \
                "s/\\@version [0-9]+\\.[0-9]+\\.[0-9]+/\\@version ${NEW_VERSION}/g" \
                "$(basename "$file")"
        fi
    done
    print_success "CSS files updated"
else
    print_warning "CSS directory not found"
fi

# 4. Update JavaScript files
print_status "Updating JavaScript files..."

if [ -d "${PROJECT_ROOT}/assets/js" ]; then
    find "${PROJECT_ROOT}/assets/js" -name "*.js" -print0 | while IFS= read -r -d '' file; do
        if grep -q "@version" "$file"; then
            update_file "$file" \
                "s/\\@version [0-9]+\\.[0-9]+\\.[0-9]+/\\@version ${NEW_VERSION}/g" \
                "$(basename "$file")"
        fi
    done
    print_success "JavaScript files updated"
else
    print_warning "JavaScript directory not found"
fi

# 5. Update HEADER-STANDARDS.md
print_status "Updating header standards documentation..."

if [ -f "${PROJECT_ROOT}/HEADER-STANDARDS.md" ]; then
    # Update Version: entries
    update_file "${PROJECT_ROOT}/HEADER-STANDARDS.md" \
        "s/Version: [0-9]+\\.[0-9]+\\.[0-9]+/Version: ${NEW_VERSION}/g" \
        "header standards version references"
    
    # Update @version entries
    update_file "${PROJECT_ROOT}/HEADER-STANDARDS.md" \
        "s/\\@version [0-9]+\\.[0-9]+\\.[0-9]+/\\@version ${NEW_VERSION}/g" \
        "header standards @version tags"
    
    print_success "Header standards documentation updated"
else
    print_warning "HEADER-STANDARDS.md not found"
fi

# 6. Update version scripts
print_status "Updating version scripts..."

if [ -f "${PROJECT_ROOT}/scripts/update-version.sh" ]; then
    update_file "${PROJECT_ROOT}/scripts/update-version.sh" \
        "s/\\@version [0-9]+\\.[0-9]+\\.[0-9]+/\\@version ${NEW_VERSION}/g" \
        "update-version.sh"
fi

if [ -f "${PROJECT_ROOT}/scripts/update-version-simple.sh" ]; then
    update_file "${PROJECT_ROOT}/scripts/update-version-simple.sh" \
        "s/\\@version [0-9]+\\.[0-9]+\\.[0-9]+/\\@version ${NEW_VERSION}/g" \
        "update-version-simple.sh"
fi

print_success "Version scripts updated"

# 7. Update README.md if it contains version references
print_status "Checking README.md for version references..."

if [ -f "${PROJECT_ROOT}/README.md" ]; then
    if grep -q "Version: [0-9]\+\.[0-9]\+\.[0-9]\+" "${PROJECT_ROOT}/README.md"; then
        update_file "${PROJECT_ROOT}/README.md" \
            "s/Version: [0-9]+\\.[0-9]+\\.[0-9]+/Version: ${NEW_VERSION}/g" \
            "README.md version references"
        print_success "README.md updated"
    else
        print_status "No version references found in README.md"
    fi
else
    print_warning "README.md not found"
fi

echo ""
print_success "✨ Version update completed successfully!"
echo ""
print_status "Summary of changes:"
echo "  • Main plugin file: silver-assist-security.php"
echo "  • PHP files: src/**/*.php"
echo "  • CSS files: assets/css/*.css"
echo "  • JavaScript files: assets/js/*.js"
echo "  • Header standards: HEADER-STANDARDS.md"
echo "  • Documentation: README.md (if applicable)"
echo "  • Update scripts: scripts/update-version*.sh"
echo ""
print_status "Next steps:"
echo "  1. Verify changes: ./scripts/check-versions.sh"
echo "  2. Review the changes: git diff"
echo "  3. Test the plugin with new version"
echo "  4. Update CHANGELOG.md manually (if needed)"
echo "  5. Update MIGRATION.md if there are breaking changes"
echo "  6. Commit changes: git add . && git commit -m '🔧 Update version to ${NEW_VERSION}'"
echo "  7. Create tag: git tag v${NEW_VERSION}"
echo "  8. Push changes: git push origin main && git push origin v${NEW_VERSION}"
echo "  9. Create GitHub release with release notes"
echo ""
print_warning "Remember: This script only updates @version tags, not @since tags!"
print_warning "New files should have their @since tag set manually to the version when they were introduced."
