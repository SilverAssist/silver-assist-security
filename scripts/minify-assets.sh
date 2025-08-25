#!/bin/bash

# Silver Assist Security Essentials - Asset Minification Script
# 
# Generates minified versions of CSS and JavaScript files using Toptal's API.
# Preserves file headers and creates .min.css and .min.js versions.
#
# @version 1.1.10
# @author Silver Assist Security Team
# @since 1.1.10

set -e

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
    echo -e "${RED}[ERROR]${NC} $1"
}

# Project configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CSS_DIR="$PROJECT_ROOT/assets/css"
JS_DIR="$PROJECT_ROOT/assets/js"

# API endpoints
CSS_API_URL="https://www.toptal.com/developers/cssminifier/api/raw"
JS_API_URL="https://www.toptal.com/developers/javascript-minifier/api/raw"

# Function to extract file header (everything before the first non-comment/non-empty line)
extract_header() {
    local file_path="$1"
    local file_type="$2"
    local header=""
    local in_header=true
    
    while IFS= read -r line; do
        # Remove leading/trailing whitespace
        trimmed=$(echo "$line" | xargs)
        
        if [ "$file_type" = "css" ]; then
            # CSS: Look for /* */ comments and empty lines
            if [[ "$trimmed" =~ ^/\*.*\*/$ ]] || [[ "$trimmed" =~ ^/\*.*$ ]] || [[ "$trimmed" =~ ^\*.*$ ]] || [[ "$trimmed" =~ ^.*\*/$ ]] || [ -z "$trimmed" ]; then
                header="$header$line"$'\n'
            elif [[ "$trimmed" =~ ^@(charset|import) ]]; then
                # Include CSS directives like @charset, @import
                header="$header$line"$'\n'
            else
                break
            fi
        elif [ "$file_type" = "js" ]; then
            # JavaScript: Look for // comments, /* */ comments and empty lines
            if [[ "$trimmed" =~ ^//.*$ ]] || [[ "$trimmed" =~ ^/\*.*\*/$ ]] || [[ "$trimmed" =~ ^/\*.*$ ]] || [[ "$trimmed" =~ ^\*.*$ ]] || [[ "$trimmed" =~ ^.*\*/$ ]] || [ -z "$trimmed" ]; then
                header="$header$line"$'\n'
            else
                break
            fi
        fi
    done < "$file_path"
    
    echo -n "$header"
}

# Function to get content without header
get_content_without_header() {
    local file_path="$1"
    local file_type="$2"
    local content=""
    local skip_header=true
    
    while IFS= read -r line; do
        trimmed=$(echo "$line" | xargs)
        
        if [ "$skip_header" = true ]; then
            if [ "$file_type" = "css" ]; then
                if [[ "$trimmed" =~ ^/\*.*\*/$ ]] || [[ "$trimmed" =~ ^/\*.*$ ]] || [[ "$trimmed" =~ ^\*.*$ ]] || [[ "$trimmed" =~ ^.*\*/$ ]] || [ -z "$trimmed" ]; then
                    continue
                elif [[ "$trimmed" =~ ^@(charset|import) ]]; then
                    continue
                else
                    skip_header=false
                fi
            elif [ "$file_type" = "js" ]; then
                if [[ "$trimmed" =~ ^//.*$ ]] || [[ "$trimmed" =~ ^/\*.*\*/$ ]] || [[ "$trimmed" =~ ^/\*.*$ ]] || [[ "$trimmed" =~ ^\*.*$ ]] || [[ "$trimmed" =~ ^.*\*/$ ]] || [ -z "$trimmed" ]; then
                    continue
                else
                    skip_header=false
                fi
            fi
        fi
        
        if [ "$skip_header" = false ]; then
            content="$content$line"$'\n'
        fi
    done < "$file_path"
    
    echo -n "$content"
}

# Function to minify content using API
minify_content() {
    local content="$1"
    local file_type="$2"
    local api_url
    
    if [ "$file_type" = "css" ]; then
        api_url="$CSS_API_URL"
    elif [ "$file_type" = "js" ]; then
        api_url="$JS_API_URL"
    else
        error "Unsupported file type: $file_type"
        return 1
    fi
    
    # Use curl to send POST request to API
    local minified_content
    minified_content=$(curl -s -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "input=$(printf '%s' "$content" | perl -MURI::Escape -e 'print uri_escape(<STDIN>)')" \
        "$api_url")
    
    # Check if curl was successful
    if [ $? -ne 0 ] || [ -z "$minified_content" ]; then
        error "Failed to minify content using API"
        return 1
    fi
    
    echo -n "$minified_content"
}

# Function to process a single file
process_file() {
    local file_path="$1"
    local file_type="$2"
    local filename=$(basename "$file_path")
    local basename="${filename%.*}"
    local extension="${filename##*.}"
    local directory=$(dirname "$file_path")
    local output_file="$directory/$basename.min.$extension"
    
    info "Processing $filename..."
    
    # Check if source file exists
    if [ ! -f "$file_path" ]; then
        warning "File not found: $file_path"
        return 1
    fi
    
    # Extract header and content
    local header
    header=$(extract_header "$file_path" "$file_type")
    local content
    content=$(get_content_without_header "$file_path" "$file_type")
    
    # Skip if content is empty
    if [ -z "$content" ]; then
        warning "No content to minify in $filename"
        return 1
    fi
    
    # Minify content
    local minified_content
    minified_content=$(minify_content "$content" "$file_type")
    
    if [ $? -ne 0 ] || [ -z "$minified_content" ]; then
        error "Failed to minify $filename"
        return 1
    fi
    
    # Combine header with minified content
    {
        echo -n "$header"
        echo -n "$minified_content"
    } > "$output_file"
    
    # Get file sizes for comparison
    local original_size=$(wc -c < "$file_path")
    local minified_size=$(wc -c < "$output_file")
    local reduction=$(( (original_size - minified_size) * 100 / original_size ))
    
    success "✓ $basename.min.$extension created (${reduction}% reduction: ${original_size} → ${minified_size} bytes)"
}

# Main execution
main() {
    info "Silver Assist Security Essentials - Asset Minification"
    info "Project root: $PROJECT_ROOT"
    
    # Check dependencies
    if ! command -v curl &> /dev/null; then
        error "curl is required but not installed"
        exit 1
    fi
    
    if ! command -v perl &> /dev/null; then
        error "perl is required but not installed"
        exit 1
    fi
    
    local total_processed=0
    local total_errors=0
    
    info "Processing CSS files..."
    if [ -d "$CSS_DIR" ]; then
        for css_file in "$CSS_DIR"/*.css; do
            # Skip already minified files
            if [[ "$css_file" == *.min.css ]]; then
                continue
            fi
            
            if [ -f "$css_file" ]; then
                if process_file "$css_file" "css"; then
                    ((total_processed++))
                else
                    ((total_errors++))
                fi
            fi
        done
    else
        warning "CSS directory not found: $CSS_DIR"
    fi
    
    info "Processing JavaScript files..."
    if [ -d "$JS_DIR" ]; then
        for js_file in "$JS_DIR"/*.js; do
            # Skip already minified files
            if [[ "$js_file" == *.min.js ]]; then
                continue
            fi
            
            if [ -f "$js_file" ]; then
                if process_file "$js_file" "js"; then
                    ((total_processed++))
                else
                    ((total_errors++))
                fi
            fi
        done
    else
        warning "JavaScript directory not found: $JS_DIR"
    fi
    
    # Summary
    echo ""
    if [ $total_errors -eq 0 ]; then
        success "✨ Asset minification completed successfully!"
        success "Processed $total_processed files"
    else
        warning "Asset minification completed with $total_errors errors"
        warning "Successfully processed: $total_processed files"
        warning "Errors: $total_errors files"
    fi
    
    info "Next steps:"
    info "  1. Review the generated .min.css and .min.js files"
    info "  2. Test the plugin with SCRIPT_DEBUG disabled"
    info "  3. Include minified files in release package"
}

# Script help
show_help() {
    echo "Silver Assist Security Essentials - Asset Minification Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help    Show this help message"
    echo ""
    echo "This script generates minified versions of CSS and JavaScript files"
    echo "using Toptal's online minification API. The minified files preserve"
    echo "the original file headers and are saved with .min.css and .min.js extensions."
    echo ""
    echo "Examples:"
    echo "  $0                 # Minify all CSS and JS files"
    echo "  $0 --help          # Show this help"
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
