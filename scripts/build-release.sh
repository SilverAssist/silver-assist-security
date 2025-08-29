#!/bin/bash

###############################################################################
# Silver Assist Security Essentials - Release ZIP Creator
#
# Creates a properly structured ZIP file for WordPress plugin distribution
# The ZIP will have a versioned filename but the internal folder will be just "silver-assist-security"
#
# Usage: ./scripts/build-release.sh [version]
# If version is not provided, it will be extracted from the main plugin file
#
# @package SilverAssist\Security
# @since 1.0.0
# @author Silver Assist
# @version 1.1.11
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}=== Silver Assist Security Essentials Release ZIP Creator ===${NC}"
echo ""

# Get current directory (should be project root)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Check if we're in the right directory
if [ ! -f "silver-assist-security.php" ]; then
    echo -e "${RED}❌ Error: silver-assist-security.php not found. Make sure you're running this from the project root.${NC}"
    exit 1
fi

# Get version from parameter or extract from main plugin file
if [ -n "$1" ]; then
    VERSION="$1"
    echo -e "${YELLOW}📋 Using provided version: ${VERSION}${NC}"
else
    VERSION=$(grep "Version:" silver-assist-security.php | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
    echo -e "${YELLOW}📋 Extracted version from plugin file: ${VERSION}${NC}"
fi

if [ -z "$VERSION" ]; then
    echo -e "${RED}❌ Error: Could not determine version. Please provide version as argument or ensure silver-assist-security.php has proper version header.${NC}"
    exit 1
fi

echo -e "${GREEN}📦 Creating ZIP for version: ${VERSION}${NC}"
echo ""

# Define files and directories to include
ZIP_NAME="silver-assist-security-v${VERSION}.zip"
TEMP_DIR="/tmp/silver-assist-security-release"
PLUGIN_DIR="${TEMP_DIR}/silver-assist-security"

# Clean up any existing temp directory
if [ -d "$TEMP_DIR" ]; then
    rm -rf "$TEMP_DIR"
fi

# Create temporary directory structure
mkdir -p "$PLUGIN_DIR"

echo -e "${YELLOW}📋 Copying files...${NC}"

# Copy main plugin file
cp silver-assist-security.php "$PLUGIN_DIR/"
echo "  ✅ silver-assist-security.php copied"

# Copy documentation files
cp README.md "$PLUGIN_DIR/"
cp LICENSE "$PLUGIN_DIR/"
echo "  ✅ Documentation files copied"

# Copy CHANGELOG.md if it exists
if [ -f "CHANGELOG.md" ]; then
    cp CHANGELOG.md "$PLUGIN_DIR/"
    echo "  ✅ CHANGELOG.md copied"
fi

# Copy src directory
if [ -d "src" ]; then
    cp -r src "$PLUGIN_DIR/"
    echo "  ✅ src/ directory copied"
fi

# Copy assets directory
if [ -d "assets" ]; then
    # Generate minified asset versions BEFORE copying
    echo -e "${YELLOW}🔧 Generating minified assets for production (NPM + Grunt)...${NC}"
    if [ -f "scripts/minify-assets-npm.sh" ]; then
        # Run NPM-based minification script - reliable professional build system
        MINIFY_OUTPUT=$(./scripts/minify-assets-npm.sh 2>&1)
        MINIFY_EXIT_CODE=$?
        
        if [ $MINIFY_EXIT_CODE -eq 0 ]; then
            echo "  ✅ Minified CSS and JS files generated successfully with NPM + Grunt"
            echo "$MINIFY_OUTPUT" | grep -E "(SUCCESS|✓)" | sed 's/^/    /' || true
        else
            echo -e "${YELLOW}  ⚠️  Warning: NPM asset minification failed (exit code: $MINIFY_EXIT_CODE)${NC}"
            echo -e "${YELLOW}  📋 Minification output:${NC}"
            echo "$MINIFY_OUTPUT" | sed 's/^/    /'
            echo -e "${YELLOW}  🔄 Proceeding with original files - build will continue${NC}"
        fi
    else
        echo -e "${YELLOW}  ⚠️  Warning: NPM minification script not found, using original assets${NC}"
    fi
    
    # Now copy the assets directory (including minified files)
    cp -r assets "$PLUGIN_DIR/"
    echo "  ✅ assets/ directory copied"
    
    # Show compression statistics if minified files exist
    if [ -f "assets/css/admin.css" ] && [ -f "assets/css/admin.min.css" ]; then
        original_css=$(wc -c < "assets/css/admin.css")
        minified_css=$(wc -c < "assets/css/admin.min.css")
        css_reduction=$(( (original_css - minified_css) * 100 / original_css ))
        echo "  📊 CSS compression: ${css_reduction}% reduction"
    fi
    
    if [ -f "assets/js/admin.js" ] && [ -f "assets/js/admin.min.js" ]; then
        original_js=$(wc -c < "assets/js/admin.js")
        minified_js=$(wc -c < "assets/js/admin.min.js")
        js_reduction=$(( (original_js - minified_js) * 100 / original_js ))
        echo "  📊 JS compression: ${js_reduction}% reduction"
    fi
fi

# Copy languages directory if it exists
if [ -d "languages" ]; then
    cp -r languages "$PLUGIN_DIR/"
    echo "  ✅ languages/ directory copied"
fi

# Copy composer.json if it exists (for PSR-4 autoloading)
if [ -f "composer.json" ]; then
    cp composer.json "$PLUGIN_DIR/"
    echo "  ✅ composer.json copied"
fi

# Copy vendor directory (Composer dependencies) - REQUIRED for external packages
if [ -d "vendor" ]; then
    echo -e "${YELLOW}📦 Installing production dependencies...${NC}"
    
    # Install only production dependencies (no dev packages)
    composer install --no-dev --optimize-autoloader --no-scripts --quiet
    
    # Create vendor directory in plugin
    mkdir -p "$PLUGIN_DIR/vendor"
    
    # Copy only essential vendor files (exclude unnecessary files)
    echo -e "${YELLOW}📦 Copying optimized vendor dependencies...${NC}"
    
    # Copy Composer autoloader files (essential)
    cp -r vendor/composer "$PLUGIN_DIR/vendor/"
    cp vendor/autoload.php "$PLUGIN_DIR/vendor/"
    
    # Copy only silverassist packages and their essential files
    if [ -d "vendor/silverassist" ]; then
        mkdir -p "$PLUGIN_DIR/vendor/silverassist"
        
        # Copy each silverassist package, excluding unnecessary files
        for package_dir in vendor/silverassist/*/; do
            if [ -d "$package_dir" ]; then
                package_name=$(basename "$package_dir")
                dest_dir="$PLUGIN_DIR/vendor/silverassist/$package_name"
                mkdir -p "$dest_dir"
                
                # Copy essential files only
                [ -f "$package_dir/composer.json" ] && cp "$package_dir/composer.json" "$dest_dir/"
                [ -d "$package_dir/src" ] && cp -r "$package_dir/src" "$dest_dir/"
                
                echo "    ✅ silverassist/$package_name (optimized)"
            fi
        done
    fi
    
    echo "  ✅ vendor/ directory copied (production dependencies - optimized)"
    
    # Restore dev dependencies after build
    composer install --quiet
    echo "  ✅ Development dependencies restored"
else
    echo -e "${RED}⚠️  Warning: vendor/ directory not found. Run 'composer install' first.${NC}"
fi

echo ""

# Create releases directory if it doesn't exist
mkdir -p "$PROJECT_ROOT/releases"

# Create the ZIP file directly in releases directory
echo -e "${YELLOW}🗜️  Creating ZIP archive...${NC}"
cd "$TEMP_DIR"
zip -r "$ZIP_NAME" silver-assist-security/ -x "*.DS_Store*" "*.git*" "*node_modules*" "*.log*" "*.tmp*" "*scripts*" "*.github*" "*tests*" "*.idea*" "*.vscode*" "*HEADER-STANDARDS.md*" "*MIGRATION.md*" "*phpunit.xml*" "*.phpcs.xml*"

# Move ZIP directly to releases directory (no copy in project root)
mv "$ZIP_NAME" "$PROJECT_ROOT/releases/"

cd "$PROJECT_ROOT"

# Clean up temp directory
rm -rf "$TEMP_DIR"

# Get ZIP size information from releases directory
ZIP_PATH="$PROJECT_ROOT/releases/$ZIP_NAME"
ZIP_SIZE=$(du -h "$ZIP_PATH" | cut -f1)
ZIP_SIZE_BYTES=$(stat -f%z "$ZIP_PATH" 2>/dev/null || stat -c%s "$ZIP_PATH" 2>/dev/null || echo "0")
ZIP_SIZE_KB=$((ZIP_SIZE_BYTES / 1024))

echo ""
echo -e "${GREEN}✅ Release ZIP created successfully!${NC}"
echo -e "${BLUE}📦 File: releases/${ZIP_NAME}${NC}"
echo -e "${BLUE}📏 Size: ${ZIP_SIZE} (~${ZIP_SIZE_KB}KB)${NC}"
echo ""
echo -e "${GREEN}🎉 Ready for WordPress installation!${NC}"
echo ""
echo -e "${BLUE}📋 Next steps:${NC}"
if [ -n "$GITHUB_OUTPUT" ]; then
    # Running in CI/CD - shorter, technical output
    echo "• Package created for GitHub Release automation"
    echo "• File: releases/${ZIP_NAME}"
    echo "• GitHub Actions will handle release creation"
else
    # Running manually - detailed user instructions
    echo "1. Navigate to releases/ folder to find your ZIP file"
    echo "2. Upload ${ZIP_NAME} to WordPress admin (Plugins → Add New → Upload Plugin)"
    echo "3. The plugin folder will be extracted as 'silver-assist-security' (without version)"
    echo "4. Activate and configure the security settings"
fi
echo ""
echo -e "${CYAN}🔧 Development notes:${NC}"
echo "• ZIP location: releases/${ZIP_NAME}"
echo "• Internal folder name: silver-assist-security (clean, no version)"
echo "• Size: ~${ZIP_SIZE_KB}KB"
echo "• Excludes: .git, node_modules, vendor, scripts, tests, .vscode, development files"
echo "• Includes: Core security features, admin panel, GraphQL protection"

# Output package information for GitHub Actions (if running in CI)
if [ -n "$GITHUB_OUTPUT" ]; then
    echo "package_name=silver-assist-security-v${VERSION}" >> $GITHUB_OUTPUT
    echo "package_size=${ZIP_SIZE}" >> $GITHUB_OUTPUT
    echo "package_size_kb=${ZIP_SIZE_KB}KB" >> $GITHUB_OUTPUT
    echo "zip_path=releases/${ZIP_NAME}" >> $GITHUB_OUTPUT
    echo "zip_file=${ZIP_NAME}" >> $GITHUB_OUTPUT
    echo "version=${VERSION}" >> $GITHUB_OUTPUT
fi
