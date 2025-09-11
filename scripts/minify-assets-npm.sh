#!/bin/bash

# Silver Assist Security Essentials - NPM-based Asset Minification Script
# 
# Uses PostCSS + cssnano for CSS minification and Grunt with grunt-contrib-uglify
# for JavaScript minification in both local and CI/CD environments.
# 
# The PostCSS system replaced grunt-contrib-cssmin to properly handle:
# - CSS @layer directives
# - CSS nesting
# - Container queries  
# - Modern CSS syntax
#
# @version 1.1.12
# @author Silver Assist Security Team
# @since 1.1.10

# Color output functions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Project configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Main execution
main() {
    info "Silver Assist Security Essentials - NPM Asset Minification"
    info "Project root: $PROJECT_ROOT"
    
    # Change to project root
    cd "$PROJECT_ROOT" || {
        error "Failed to change to project root directory"
        return 1
    }
    
    # Check if we're in the right directory
    if [ ! -f "silver-assist-security.php" ]; then
        error "Not in plugin root directory - missing silver-assist-security.php"
        return 1
    fi
    
    # Check if package.json exists
    if [ ! -f "package.json" ]; then
        error "package.json not found - run 'npm init' first"
        return 1
    fi
    
    # Check if postcss.config.js exists
    if [ ! -f "postcss.config.js" ]; then
        error "postcss.config.js not found - PostCSS configuration required"
        return 1
    fi
    
    # Check if Gruntfile.js exists (still needed for JavaScript minification)
    if [ ! -f "Gruntfile.js" ]; then
        error "Gruntfile.js not found - required for JavaScript minification"
        return 1
    fi
    
    # Check if Node.js is available
    if ! command -v node >/dev/null 2>&1; then
        error "Node.js is required but not installed"
        info "Install Node.js from https://nodejs.org/ or use nvm"
        return 1
    fi
    
    # Check if npm is available
    if ! command -v npm >/dev/null 2>&1; then
        error "npm is required but not installed"
        return 1
    fi
    
    # Check if PostCSS CLI is available
    if ! command -v npx >/dev/null 2>&1; then
        error "npx is required but not available"
        return 1
    fi
    
    info "Node.js version: $(node --version)"
    info "npm version: $(npm --version)"
    
    # Install dependencies if node_modules doesn't exist
    if [ ! -d "node_modules" ]; then
        info "Installing npm dependencies..."
        if ! npm install; then
            error "Failed to install npm dependencies"
            return 1
        fi
        success "Dependencies installed successfully"
    else
        info "Dependencies already installed"
        # Always run npm install to ensure dependencies are up to date
        # Note: Using npm install instead of npm ci since package-lock.json is gitignored
        info "Ensuring dependencies are up to date..."
        if ! npm install; then
            error "Failed to update npm dependencies"
            return 1
        fi
    fi
    
    # Display build system information
    info "Build System Information:"
    info "  • CSS Minification: PostCSS + cssnano (modern CSS support)"
    info "  • JS Minification: Grunt + uglify (reliable ES5 support)"
    info "  • Command: This script runs 'npm run build' internally"
    
    # Clean existing minified files
    info "Cleaning existing minified files..."
    rm -f assets/css/*.min.css assets/js/*.min.js
    
    # Run the complete build process using npm scripts
    info "Running complete build process (CSS with PostCSS + JS with Grunt)..."
    if ! npm run build; then
        error "Build process failed"
        return 1
    fi
    
    # Verify minified files were created
    local expected_files=(
        "assets/css/admin.min.css"
        "assets/css/password-validation.min.css"
        "assets/css/variables.min.css"
        "assets/js/admin.min.js"
        "assets/js/password-validation.min.js"
    )
    
    local missing_files=0
    info "Verifying minified files..."
    
    for file in "${expected_files[@]}"; do
        if [ -f "$file" ]; then
            local original_file="${file%.min.*}.${file##*.min.}"
            if [ -f "$original_file" ]; then
                local original_size=$(wc -c < "$original_file")
                local minified_size=$(wc -c < "$file")
                local reduction=$(( (original_size - minified_size) * 100 / original_size ))
                success "✓ $(basename "$file") created (${reduction}% reduction: ${original_size} → ${minified_size} bytes)"
            else
                success "✓ $(basename "$file") created"
            fi
        else
            error "✗ $(basename "$file") not found"
            ((missing_files++))
        fi
    done
    
    # Summary
    echo ""
    if [ $missing_files -eq 0 ]; then
        success "✨ Asset minification completed successfully!"
        success "All 5 minified files created with PostCSS (CSS) + Grunt (JS)"
        echo ""
        info "📊 System Information:"
        info "  • CSS: PostCSS + cssnano (supports @layer, nesting, container queries)"
        info "  • JavaScript: Grunt + uglify (reliable ES5 minification)"
        info "  • Build command: npm run build"
    else
        warning "Asset minification completed with $missing_files missing files"
    fi
    
    info "Next steps:"
    info "  1. Review the generated .min.css and .min.js files"
    info "  2. Test the plugin with SCRIPT_DEBUG disabled"
    info "  3. Include minified files in release package"
    info "  4. Use 'npm run build' for future minification"
    
    return 0
}

# Script help
show_help() {
    echo "Silver Assist Security Essentials - NPM Asset Minification Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help    Show this help message"
    echo ""
    echo "This script uses npm, PostCSS, and Grunt to generate minified versions of CSS and JavaScript files"
    echo "using PostCSS + cssnano for CSS and grunt-contrib-uglify for JavaScript. The minified files preserve"
    echo "the original file headers and are saved with .min.css and .min.js extensions."
    echo ""
    echo "Requirements:"
    echo "  - Node.js 16+ and npm 8+"
    echo "  - package.json with postcss, cssnano, and grunt dependencies"
    echo "  - postcss.config.js with cssnano configuration"
    echo "  - Gruntfile.js with uglify tasks for JavaScript"
    echo ""
    echo "Examples:"
    echo "  $0                 # Run complete build (CSS with PostCSS + JS with Grunt)"
    echo "  $0 --help          # Show this help"
    echo ""
    echo "Available npm commands:"
    echo "  npm run build      # Complete build process (recommended)"
    echo "  npm run minify     # Minify CSS + JS without cleaning"
    echo "  npm run minify:css # Minify only CSS files with PostCSS"
    echo "  npm run minify:js  # Minify only JS files with Grunt"
    echo "  npm run clean      # Remove all .min.css and .min.js files"
    echo ""
}

# Parse command line arguments
case "${1:-}" in
    -h|--help)
        show_help
        exit 0
        ;;
    "")
        main
        ;;
    *)
        error "Unknown option: $1"
        echo ""
        show_help
        exit 1
        ;;
esac
