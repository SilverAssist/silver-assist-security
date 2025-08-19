#!/bin/bash

###############################################################################
# Silver Assist Security Suite - Version Check Script
#
# Checks and displays current version numbers across all plugin files
# Useful for verifying version consistency before and after updates
#
# Usage: ./scripts/check-versions.sh
#
# @package SilverAssist\Security
# @since 1.0.0
# @author Silver Assist
# @version 1.1.6
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${CYAN}=== $1 ===${NC}"
}

print_file() {
    echo -e "${BLUE}📄 $1${NC}"
}

print_version() {
    echo -e "   ${GREEN}Version: $1${NC}"
}

print_error() {
    echo -e "   ${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "   ${YELLOW}⚠️  $1${NC}"
}

# Get current directory (should be project root)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    VERSION CHECK REPORT                     ║"
echo "║               Silver Assist Security Suite                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if we're in the right directory
if [ ! -f "${PROJECT_ROOT}/silver-assist-security.php" ]; then
    print_error "Main plugin file not found. Make sure you're running this from the project root."
    exit 1
fi

print_header "Main Plugin File"
print_file "silver-assist-security.php"

# Extract versions from main file
PLUGIN_HEADER_VERSION=$(grep -o "Version: [0-9]\+\.[0-9]\+\.[0-9]\+" "${PROJECT_ROOT}/silver-assist-security.php" | cut -d' ' -f2)
PLUGIN_CONSTANT_VERSION=$(grep -o "SILVER_ASSIST_SECURITY_VERSION.*[0-9]\+\.[0-9]\+\.[0-9]\+" "${PROJECT_ROOT}/silver-assist-security.php" | grep -o "[0-9]\+\.[0-9]\+\.[0-9]\+")
PLUGIN_DOCBLOCK_VERSION=$(grep -o "@version [0-9]\+\.[0-9]\+\.[0-9]\+" "${PROJECT_ROOT}/silver-assist-security.php" | cut -d' ' -f2)

if [ -n "$PLUGIN_HEADER_VERSION" ]; then
    print_version "Plugin Header: $PLUGIN_HEADER_VERSION"
else
    print_error "Plugin header version not found"
fi

if [ -n "$PLUGIN_CONSTANT_VERSION" ]; then
    print_version "Plugin Constant: $PLUGIN_CONSTANT_VERSION"
else
    print_error "Plugin constant version not found"
fi

if [ -n "$PLUGIN_DOCBLOCK_VERSION" ]; then
    print_version "DocBlock: $PLUGIN_DOCBLOCK_VERSION"
else
    print_error "DocBlock version not found"
fi

# Set main version for comparison
MAIN_VERSION="$PLUGIN_HEADER_VERSION"

echo ""
print_header "PHP Files (src/)"

find "${PROJECT_ROOT}/src" -name "*.php" -type f | sort | while read -r file; do
    # Get relative path for display
    relative_path=${file#$PROJECT_ROOT/}
    print_file "$relative_path"
    
    # Only search in first 20 lines for @version tag in header comments
    version=$(head -n 20 "$file" | grep -o "# @version [0-9]\+\.[0-9]\+\.[0-9]\+" 2>/dev/null | cut -d' ' -f3)
    # Fallback to standard @version in docblock comments (without #)
    if [ -z "$version" ]; then
        version=$(head -n 20 "$file" | grep -o " \* @version [0-9]\+\.[0-9]\+\.[0-9]\+" 2>/dev/null | cut -d' ' -f4)
    fi
    
    if [ -n "$version" ]; then
        if [ "$version" = "$MAIN_VERSION" ]; then
            print_version "$version ✓"
        else
            print_warning "$version (differs from main: $MAIN_VERSION)"
        fi
    else
        print_error "No @version tag found in header"
    fi
done

echo ""
print_header "CSS Files (assets/css/)"

if [ -d "${PROJECT_ROOT}/assets/css" ]; then
    find "${PROJECT_ROOT}/assets/css" -name "*.css" -type f | sort | while read -r file; do
        filename=$(basename "$file")
        print_file "$filename"
        
        # Only search in first 20 lines for @version tag in header comments
        version=$(head -n 20 "$file" | grep -o " \* @version [0-9]\+\.[0-9]\+\.[0-9]\+" 2>/dev/null | cut -d' ' -f4)
        
        if [ -n "$version" ]; then
            if [ "$version" = "$MAIN_VERSION" ]; then
                print_version "$version ✓"
            else
                print_warning "$version (differs from main: $MAIN_VERSION)"
            fi
        else
            print_error "No @version tag found in header"
        fi
    done
else
    print_warning "assets/css directory not found"
fi

echo ""
print_header "JavaScript Files (assets/js/)"

if [ -d "${PROJECT_ROOT}/assets/js" ]; then
    find "${PROJECT_ROOT}/assets/js" -name "*.js" -type f | sort | while read -r file; do
        filename="assets/js/$(basename "$file")"
        print_file "$filename"
        
        # Only search in first 20 lines for @version tag in header comments
        version=$(head -n 20 "$file" | grep -o " \* @version [0-9]\+\.[0-9]\+\.[0-9]\+" 2>/dev/null | cut -d' ' -f4)
        
        if [ -n "$version" ]; then
            if [ "$version" = "$MAIN_VERSION" ]; then
                print_version "$version ✓"
            else
                print_warning "$version (differs from main: $MAIN_VERSION)"
            fi
        else
            print_error "No @version tag found in header"
        fi
    done
else
    print_warning "assets/js directory not found"
fi

echo ""
print_header "Documentation Files"

# Check HEADER-STANDARDS.md
if [ -f "${PROJECT_ROOT}/HEADER-STANDARDS.md" ]; then
    print_file "HEADER-STANDARDS.md"
    
    # Check for both @version and Version: patterns
    version_count_at=$(grep -o "@version [0-9]\+\.[0-9]\+\.[0-9]\+" "${PROJECT_ROOT}/HEADER-STANDARDS.md" 2>/dev/null | wc -l | tr -d ' ')
    version_count_colon=$(grep -o "Version: [0-9]\+\.[0-9]\+\.[0-9]\+" "${PROJECT_ROOT}/HEADER-STANDARDS.md" 2>/dev/null | wc -l | tr -d ' ')
    
    # Combine both patterns
    total_versions=0
    versions_found=""
    
    if [ "$version_count_at" -gt 0 ]; then
        at_versions=$(grep -o "@version [0-9]\+\.[0-9]\+\.[0-9]\+" "${PROJECT_ROOT}/HEADER-STANDARDS.md" 2>/dev/null | cut -d' ' -f2)
        versions_found="$versions_found $at_versions"
        total_versions=$((total_versions + version_count_at))
    fi
    
    if [ "$version_count_colon" -gt 0 ]; then
        colon_versions=$(grep -o "Version: [0-9]\+\.[0-9]\+\.[0-9]\+" "${PROJECT_ROOT}/HEADER-STANDARDS.md" 2>/dev/null | cut -d' ' -f2)
        versions_found="$versions_found $colon_versions"
        total_versions=$((total_versions + version_count_colon))
    fi
    
    if [ "$total_versions" -gt 0 ]; then
        # Get unique versions
        versions=$(echo $versions_found | tr ' ' '\n' | sort -u)
        
        # Check if all versions match main version
        all_match=true
        for version in $versions; do
            if [ "$version" != "$MAIN_VERSION" ]; then
                all_match=false
                break
            fi
        done
        
        if [ "$all_match" = true ]; then
            print_version "$MAIN_VERSION ✓"
        else
            for version in $versions; do
                if [ "$version" = "$MAIN_VERSION" ]; then
                    print_version "$version ✓"
                else
                    print_warning "$version (differs from main: $MAIN_VERSION)"
                fi
            done
        fi
    else
        print_error "No version references found in HEADER-STANDARDS.md"
    fi
else
    print_warning "HEADER-STANDARDS.md not found"
fi

# Check README.md
if [ -f "${PROJECT_ROOT}/README.md" ]; then
    print_file "README.md"
    
    version=$(grep -o "Version: [0-9]\+\.[0-9]\+\.[0-9]\+" "${PROJECT_ROOT}/README.md" 2>/dev/null | cut -d' ' -f2)
    
    if [ -n "$version" ]; then
        if [ "$version" = "$MAIN_VERSION" ]; then
            print_version "$version ✓"
        else
            print_warning "$version (differs from main: $MAIN_VERSION)"
        fi
    else
        print_warning "No version references found in README.md"
    fi
else
    print_warning "README.md not found"
fi

echo ""
print_header "Scripts"

find "${PROJECT_ROOT}/scripts" -name "*.sh" -type f | sort | while read -r file; do
    filename="scripts/$(basename "$file")"
    print_file "$filename"
    
    # Only search in first 20 lines for @version tag in header comments
    version=$(head -n 20 "$file" | grep -o "# @version [0-9]\+\.[0-9]\+\.[0-9]\+" 2>/dev/null | cut -d' ' -f3)
    
    if [ -n "$version" ]; then
        if [ "$version" = "$MAIN_VERSION" ]; then
            print_version "$version ✓"
        else
            print_warning "$version (differs from main: $MAIN_VERSION)"
        fi
    else
        print_error "No @version tag found in header"
    fi
done

echo ""
print_header "Composer Configuration"

if [ -f "${PROJECT_ROOT}/composer.json" ]; then
    print_file "composer.json"
    print_version "Version field removed (recommended for non-Packagist packages) ✓"
else
    print_warning "composer.json not found"
fi

echo ""
print_header "Summary"

if [ -n "$MAIN_VERSION" ]; then
    echo -e "${GREEN}✓ Main plugin version: $MAIN_VERSION${NC}"
    
    # Count files with correct versions
    total_files=0
    matching_files=0
    
    # Check PHP files
    while IFS= read -r file; do
        total_files=$((total_files + 1))
        # Only search in first 20 lines for @version tag in header comments
        version=$(head -n 20 "$file" | grep -o "# @version [0-9]\+\.[0-9]\+\.[0-9]\+" 2>/dev/null | cut -d' ' -f3)
        # Fallback to standard @version in docblock comments (without #)
        if [ -z "$version" ]; then
            version=$(head -n 20 "$file" | grep -o " \* @version [0-9]\+\.[0-9]\+\.[0-9]\+" 2>/dev/null | cut -d' ' -f4)
        fi
        if [ "$version" = "$MAIN_VERSION" ]; then
            matching_files=$((matching_files + 1))
        fi
    done < <(find "${PROJECT_ROOT}/src" -name "*.php" -type f 2>/dev/null)
    
    # Check CSS files
    while IFS= read -r file; do
        total_files=$((total_files + 1))
        version=$(head -n 20 "$file" | grep -o " \* @version [0-9]\+\.[0-9]\+\.[0-9]\+" 2>/dev/null | cut -d' ' -f4)
        if [ "$version" = "$MAIN_VERSION" ]; then
            matching_files=$((matching_files + 1))
        fi
    done < <(find "${PROJECT_ROOT}/assets/css" -name "*.css" -type f 2>/dev/null)
    
    # Check JS files
    while IFS= read -r file; do
        total_files=$((total_files + 1))
        version=$(head -n 20 "$file" | grep -o " \* @version [0-9]\+\.[0-9]\+\.[0-9]\+" 2>/dev/null | cut -d' ' -f4)
        if [ "$version" = "$MAIN_VERSION" ]; then
            matching_files=$((matching_files + 1))
        fi
    done < <(find "${PROJECT_ROOT}/assets/js" -name "*.js" -type f 2>/dev/null)
    
    # Check scripts
    while IFS= read -r file; do
        total_files=$((total_files + 1))
        version=$(head -n 20 "$file" | grep -o "# @version [0-9]\+\.[0-9]\+\.[0-9]\+" 2>/dev/null | cut -d' ' -f3)
        if [ "$version" = "$MAIN_VERSION" ]; then
            matching_files=$((matching_files + 1))
        fi
    done < <(find "${PROJECT_ROOT}/scripts" -name "*.sh" -type f 2>/dev/null)
    
    echo -e "${BLUE}📊 Version consistency: ${matching_files}/${total_files} files match${NC}"
    
    if [ "$matching_files" -eq "$total_files" ]; then
        echo -e "${GREEN}🎉 All files have consistent versions!${NC}"
    else
        echo -e "${YELLOW}⚠️  Some files have different versions${NC}"
    fi
else
    echo -e "${RED}❌ Could not determine main plugin version${NC}"
fi

echo ""
echo -e "${BLUE}💡 Tips:${NC}"
echo "• Use ${YELLOW}./scripts/update-version-simple.sh <version>${NC} to update all versions"
echo "• Green checkmarks (✓) indicate files matching the main version"
echo "• Warnings (⚠️) indicate version mismatches that may need attention"
echo "• Errors (❌) indicate missing version tags"
echo ""
echo -e "${CYAN}📝 Next steps:${NC}"
echo "• If versions are inconsistent, run: ${YELLOW}./scripts/update-version-simple.sh ${MAIN_VERSION}${NC}"
echo "• To update to a new version, run: ${YELLOW}./scripts/update-version-simple.sh <new-version>${NC}"
