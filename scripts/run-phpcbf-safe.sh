#!/usr/bin/env bash
#
# PHPCBF Safe Runner - Intelligent Error Code Handling
#
# This script runs PHPCBF and handles exit codes intelligently:
# - Exit 0: No issues found (success)
# - Exit 1: Issues found and fixed (treat as success)
# - Exit 2: Issues found but couldn't be fixed (failure - needs manual intervention)
# - Exit 3: Processing error (failure - configuration/system issue)
#
# @package SilverAssist\Security
# @since 1.1.15
# @author Silver Assist
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print functions
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Main PHPCBF execution with intelligent error handling
main() {
    print_info "Running PHPCBF (PHP Code Beautifier and Fixer)"
    
    # Run PHPCBF and capture the exit code
    set +e  # Temporarily disable exit on error to capture exit code
    phpcbf --standard=phpcs.xml
    exit_code=$?
    set -e  # Re-enable exit on error
    
    # Handle different exit codes according to PHPCBF documentation
    case $exit_code in
        0)
            print_success "No coding standards violations found"
            print_info "All files already comply with WordPress coding standards"
            exit 0
            ;;
        1)
            print_success "Coding standards violations found and automatically fixed"
            print_info "PHPCBF successfully corrected formatting issues"
            
            # Verify the fixes by running PHPCS
            print_info "Verifying fixes with PHPCS..."
            if phpcs --standard=phpcs.xml --report=summary; then
                print_success "All fixes verified - code now complies with standards"
                exit 0
            else
                print_warning "Some issues were fixed but others remain"
                print_info "Run 'composer run phpcs' to see remaining issues"
                exit 1
            fi
            ;;
        2)
            print_error "Coding standards violations found but could not be automatically fixed"
            print_error "Manual intervention required to fix the issues"
            print_info "Common unfixable issues:"
            print_info "- Complex logic that needs restructuring"
            print_info "- Missing translator comments"
            print_info "- Incorrect function/variable naming"
            print_info "- Security-related coding patterns"
            echo ""
            print_info "Next steps:"
            print_info "1. Run 'composer run phpcs' to see detailed violations"
            print_info "2. Fix the issues manually"
            print_info "3. Run 'composer run phpcbf' again"
            exit 2
            ;;
        3)
            print_error "PHPCBF processing error occurred"
            print_error "This usually indicates a configuration or system issue"
            print_info "Possible causes:"
            print_info "- Invalid phpcs.xml configuration"
            print_info "- Insufficient memory or disk space"
            print_info "- File permission issues"
            print_info "- Corrupted vendor dependencies"
            echo ""
            print_info "Troubleshooting steps:"
            print_info "1. Check phpcs.xml syntax: xmllint phpcs.xml"
            print_info "2. Verify file permissions: ls -la src/"
            print_info "3. Check available memory: php -i | grep memory_limit"
            print_info "4. Reinstall dependencies: composer install --no-dev"
            exit 3
            ;;
        *)
            print_error "Unexpected PHPCBF exit code: $exit_code"
            print_error "This may indicate an unknown issue with PHPCBF or the environment"
            print_info "Please check the PHPCBF documentation or report this issue"
            exit $exit_code
            ;;
    esac
}

# Show help if requested
if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    echo "PHPCBF Safe Runner - Intelligent Error Code Handling"
    echo ""
    echo "This script runs PHPCBF with proper exit code interpretation:"
    echo ""
    echo "Exit Codes:"
    echo "  0 - No issues found (success)"
    echo "  1 - Issues found and fixed (success)"
    echo "  2 - Issues found but couldn't fix (manual intervention needed)"
    echo "  3 - Processing error (configuration/system issue)"
    echo ""
    echo "Usage:"
    echo "  $0              # Run PHPCBF with intelligent error handling"
    echo "  $0 --help       # Show this help message"
    echo ""
    echo "Examples:"
    echo "  composer run phpcbf                    # Run via Composer"
    echo "  bash scripts/run-phpcbf-safe.sh       # Run directly"
    echo ""
    exit 0
fi

# Execute main function
main "$@"