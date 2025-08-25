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

# Function to create a simple local minifier for CSS (fallback)
minify_css_simple() {
    local content="$1"
    echo -n "$content" | \
    # Remove comments
    sed 's|/\*[^*]*\*\+\([^/*][^*]*\*\+\)*/||g' | \
    # Remove extra whitespace
    sed 's/[[:space:]]\+/ /g' | \
    # Remove whitespace around specific characters
    sed 's/[[:space:]]*{[[:space:]]*/{/g; s/[[:space:]]*}[[:space:]]*/}/g; s/[[:space:]]*;[[:space:]]*/;/g; s/[[:space:]]*:[[:space:]]*/:/g; s/[[:space:]]*,[[:space:]]*/,/g' | \
    # Remove leading and trailing whitespace
    sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

# Function to create a simple local minifier for JS (fallback)
minify_js_simple() {
    local content="$1"
    echo -n "$content" | \
    # Remove single-line comments (but preserve URLs and regexes)
    sed 's|^\s*//.*$||g' | \
    # Remove multi-line comments
    sed 's|/\*[^*]*\*\+\([^/*][^*]*\*\+\)*/||g' | \
    # Remove extra whitespace
    sed 's/[[:space:]]\+/ /g' | \
    # Remove whitespace around operators and delimiters
    sed 's/[[:space:]]*([[:space:]]*/(/g; s/[[:space:]]*)[[:space:]]*/)/g; s/[[:space:]]*{[[:space:]]*/{/g; s/[[:space:]]*}[[:space:]]*/}/g; s/[[:space:]]*;[[:space:]]*/;/g' | \
    # Remove leading and trailing whitespace
    sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

# Function to URL encode content (compatible with GitHub Actions)
url_encode() {
    local string="$1"
    
    # Try Python3 first (available in GitHub Actions)
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "$string" | python3 -c "
import sys
import urllib.parse
content = sys.stdin.read()
print(urllib.parse.quote(content, safe=''), end='')
" 2>/dev/null
        return $?
    fi
    
    # Try Node.js as fallback (also available in GitHub Actions)
    if command -v node >/dev/null 2>&1; then
        printf '%s' "$string" | node -e "
const fs = require('fs');
let content = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => content += chunk);
process.stdin.on('end', () => process.stdout.write(encodeURIComponent(content)));
" 2>/dev/null
        return $?
    fi
    
    # If no encoding tools available, use local minifier instead
    return 1
}

# Function to minify content using API with better error handling
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
    
    # Try API minification first
    local encoded_content
    encoded_content=$(url_encode "$content")
    local encode_exit_code=$?
    
    if [ $encode_exit_code -ne 0 ] || [ -z "$encoded_content" ]; then
        warning "URL encoding failed, using local minifier instead"
        # Use local fallback minifier
        if [ "$file_type" = "css" ]; then
            minify_css_simple "$content"
        elif [ "$file_type" = "js" ]; then
            minify_js_simple "$content"
        fi
        return $?
    fi
    
    # Use curl to send POST request to API with better error handling
    local temp_file=$(mktemp)
    local curl_exit_code
    
    curl -s -X POST \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -H "User-Agent: Silver-Assist-Security-Minifier/1.1.10" \
        -H "Accept: text/plain, text/css, application/javascript, */*" \
        --connect-timeout 30 \
        --max-time 60 \
        --retry 2 \
        --retry-delay 1 \
        -w "%{http_code}" \
        -d "input=$encoded_content" \
        -o "$temp_file" \
        "$api_url" > /tmp/http_code 2>/dev/null
    
    curl_exit_code=$?
    local http_code=$(cat /tmp/http_code 2>/dev/null || echo "000")
    local minified_content=$(cat "$temp_file" 2>/dev/null)
    
    # Clean up temp files
    rm -f "$temp_file" /tmp/http_code 2>/dev/null
    
    # Check curl exit code
    if [ $curl_exit_code -ne 0 ]; then
        warning "API request failed (curl exit code: $curl_exit_code), using local minifier"
        if [ "$file_type" = "css" ]; then
            minify_css_simple "$content"
        elif [ "$file_type" = "js" ]; then
            minify_js_simple "$content"
        fi
        return $?
    fi
    
    # Check HTTP status code
    if [ "$http_code" != "200" ]; then
        warning "API returned HTTP status $http_code, using local minifier"
        if [ "$file_type" = "css" ]; then
            minify_css_simple "$content"
        elif [ "$file_type" = "js" ]; then
            minify_js_simple "$content"
        fi
        return $?
    fi
    
    # Check if content is empty
    if [ -z "$minified_content" ]; then
        warning "API returned empty content, using local minifier"
        if [ "$file_type" = "css" ]; then
            minify_css_simple "$content"
        elif [ "$file_type" = "js" ]; then
            minify_js_simple "$content"
        fi
        return $?
    fi
    
    # Check if API returned an error page
    if echo "$minified_content" | grep -qi "<!DOCTYPE\|<html\|<body\|error\|exception" >/dev/null 2>&1; then
        warning "API returned an error response, using local minifier"
        if [ "$file_type" = "css" ]; then
            minify_css_simple "$content"
        elif [ "$file_type" = "js" ]; then
            minify_js_simple "$content"
        fi
        return $?
    fi
    
    # Basic validation: minified content should be shorter or same length
    local original_length=${#content}
    local minified_length=${#minified_content}
    
    if [ $minified_length -gt $((original_length * 2)) ]; then
        warning "Minified content is suspiciously large, using local minifier"
        if [ "$file_type" = "css" ]; then
            minify_css_simple "$content"
        elif [ "$file_type" = "js" ]; then
            minify_js_simple "$content"
        fi
        return $?
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
