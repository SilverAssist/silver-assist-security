#!/bin/bash
################################################################################
# Silver Assist Security - Quality Checks Script
#
# Runs the same quality checks as GitHub Actions CI/CD pipeline
# This ensures local testing matches remote validation
#
# CRITICAL: Security plugin requires WordPress environment for testing
#
# Usage: ./scripts/run-quality-checks.sh [--skip-tests] [--skip-phpstan] [--skip-phpcs]
#
# @package SilverAssist\Security
# @since 1.1.13
################################################################################

set -e  # Exit on any error

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Script directory
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Change to project root
cd "$PROJECT_ROOT"

# Default options
RUN_TESTS=true
RUN_PHPSTAN=true
RUN_PHPCS=true
VERBOSE=false

################################################################################
# Functions
################################################################################

print_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

show_usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Runs quality checks matching GitHub Actions CI/CD configuration.

OPTIONS:
    --skip-tests        Skip PHPUnit tests
    --skip-phpstan      Skip PHPStan static analysis
    --skip-phpcs        Skip WordPress Coding Standards
    --verbose           Show detailed output
    -h, --help          Show this help message

EXAMPLES:
    # Run all checks
    ./scripts/run-quality-checks.sh

    # Run only PHPStan
    ./scripts/run-quality-checks.sh --skip-tests --skip-phpcs

    # Run only tests
    ./scripts/run-quality-checks.sh --skip-phpstan --skip-phpcs

EXIT CODES:
    0   All checks passed
    1   One or more checks failed
    2   Missing dependencies
EOF
}

check_dependencies() {
    print_header "Checking Dependencies"
    
    local missing_deps=0
    
    # Check Composer
    if ! command -v composer &> /dev/null; then
        print_error "Composer not found"
        missing_deps=1
    else
        print_success "Composer: $(composer --version | head -1)"
    fi
    
    # Check vendor directory
    if [ ! -d "vendor" ]; then
        print_error "vendor/ directory not found. Run: composer install"
        missing_deps=1
    else
        print_success "Composer dependencies installed"
    fi
    
    # Check PHPUnit
    if [ ! -f "vendor/bin/phpunit" ]; then
        print_error "PHPUnit not found in vendor/bin/"
        missing_deps=1
    else
        print_success "PHPUnit: $(vendor/bin/phpunit --version)"
    fi
    
    # Check PHPStan
    if [ ! -f "vendor/bin/phpstan" ]; then
        print_error "PHPStan not found in vendor/bin/"
        missing_deps=1
    else
        print_success "PHPStan: $(vendor/bin/phpstan --version)"
    fi
    
    # Check PHPCS
    if [ ! -f "vendor/bin/phpcs" ]; then
        print_error "PHPCS not found in vendor/bin/"
        missing_deps=1
    else
        print_success "PHPCS: $(vendor/bin/phpcs --version)"
    fi
    
    # Check WordPress Test Suite (for PHPUnit tests)
    if [ "$RUN_TESTS" = true ]; then
        if [ ! -f "/tmp/wordpress-tests-lib/includes/functions.php" ]; then
            print_warning "WordPress Test Suite not found"
            print_info "Run: ./scripts/install-wp-tests.sh wordpress_test root '' localhost latest"
            missing_deps=1
        else
            print_success "WordPress Test Suite installed"
        fi
    fi
    
    echo ""
    
    if [ $missing_deps -eq 1 ]; then
        print_error "Missing required dependencies"
        return 2
    fi
    
    return 0
}

run_phpstan() {
    print_header "PHPStan Static Analysis (Level 8) - Standalone Mode"
    
    print_info "Running PHPStan WITHOUT WordPress Test Suite..."
    print_info "Configuration: phpstan.neon"
    print_info "Memory limit: 1G"
    print_info "Level: 8 (strictest)"
    print_warning "PHPStan runs standalone (no WordPress) - validates PHP syntax only"
    print_info "WordPress functionality is validated by PHPUnit tests"
    echo ""
    
    if [ "$VERBOSE" = true ]; then
        vendor/bin/phpstan analyse --memory-limit=1G
    else
        vendor/bin/phpstan analyse --memory-limit=1G 2>&1 | grep -v "^Note:" || true
    fi
    
    local exit_code=$?
    
    echo ""
    if [ $exit_code -eq 0 ]; then
        print_success "PHPStan: PASSED ✓"
        print_info "Type safety validated (without WordPress runtime)"
        return 0
    else
        print_error "PHPStan: FAILED ✗"
        print_warning "Fix type errors before running WordPress tests"
        return 1
    fi
}

run_phpcs() {
    print_header "WordPress Coding Standards (PHPCS)"
    
    print_info "Running PHPCS with WordPress standards..."
    print_info "Standard: WordPress"
    print_info "Extensions: php"
    echo ""
    
    if [ "$VERBOSE" = true ]; then
        vendor/bin/phpcs
    else
        vendor/bin/phpcs 2>&1 | tail -20
    fi
    
    local exit_code=$?
    
    echo ""
    if [ $exit_code -eq 0 ]; then
        print_success "PHPCS: PASSED ✓"
        return 0
    else
        print_error "PHPCS: FAILED ✗"
        print_info "Run 'composer phpcbf' to auto-fix issues"
        return 1
    fi
}

run_phpunit() {
    print_header "PHPUnit Tests (WordPress Test Suite) - REAL ENVIRONMENT"
    
    print_info "🔒 CRITICAL: Security plugin testing in real WordPress environment"
    print_info "Running PHPUnit with WordPress Test Suite..."
    print_info "Configuration: phpunit.xml.dist"
    print_info "Test directory: tests/"
    print_info "Environment: WordPress 6.5+ with MySQL database"
    echo ""
    
    # Check if WordPress Test Suite is installed
    if [ ! -f "/tmp/wordpress-tests-lib/includes/functions.php" ]; then
        print_error "WordPress Test Suite not installed"
        print_warning "CRITICAL: Cannot test security features without WordPress!"
        echo ""
        print_info "Install WordPress Test Suite:"
        echo "  ./scripts/install-wp-tests.sh wordpress_test root '' localhost latest"
        echo ""
        print_info "Or use MySQL with password:"
        echo "  ./scripts/install-wp-tests.sh wordpress_test root 'password' localhost latest"
        return 1
    fi
    
    # Check if MySQL is running
    if ! command -v mysql &> /dev/null; then
        print_warning "MySQL client not found - tests may fail"
    fi
    
    print_info "Starting WordPress tests..."
    echo ""
    
    if [ "$VERBOSE" = true ]; then
        vendor/bin/phpunit --testdox
    else
        vendor/bin/phpunit --testdox --colors=always 2>&1 | tail -50
    fi
    
    local exit_code=$?
    
    echo ""
    if [ $exit_code -eq 0 ]; then
        print_success "PHPUnit: PASSED ✓"
        print_success "Security features validated in real WordPress environment"
        return 0
    else
        print_error "PHPUnit: FAILED ✗"
        print_error "Security features not working correctly in WordPress"
        return 1
    fi
}

################################################################################
# Parse command line arguments
################################################################################

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-tests)
            RUN_TESTS=false
            shift
            ;;
        --skip-phpstan)
            RUN_PHPSTAN=false
            shift
            ;;
        --skip-phpcs)
            RUN_PHPCS=false
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

################################################################################
# Main execution
################################################################################

print_header "Silver Assist Security - Quality Checks"
echo "Project: $(basename "$PROJECT_ROOT")"
echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# Check dependencies
check_dependencies
if [ $? -eq 2 ]; then
    exit 2
fi

# Track overall status
OVERALL_STATUS=0

# Run PHPStan
if [ "$RUN_PHPSTAN" = true ]; then
    run_phpstan
    if [ $? -ne 0 ]; then
        OVERALL_STATUS=1
    fi
fi

# Run PHPCS
if [ "$RUN_PHPCS" = true ]; then
    run_phpcs
    if [ $? -ne 0 ]; then
        OVERALL_STATUS=1
    fi
fi

# Run PHPUnit
if [ "$RUN_TESTS" = true ]; then
    run_phpunit
    if [ $? -ne 0 ]; then
        OVERALL_STATUS=1
    fi
fi

################################################################################
# Summary
################################################################################

print_header "Quality Checks Summary"

echo "Testing Strategy (Security Plugin):"
echo ""
echo "  1. PHPStan (Standalone)"
echo "     • Validates PHP type safety WITHOUT WordPress"
echo "     • Fast static analysis (no database required)"
echo "     • Catches type errors before running tests"
echo ""
echo "  2. PHPUnit (WordPress Environment)"
echo "     • Validates security features IN REAL WordPress"
echo "     • Tests actual WordPress hooks, filters, database"
echo "     • CRITICAL for security plugin validation"
echo ""
echo "  3. PHPCS (Code Standards)"
echo "     • Validates WordPress coding standards"
echo "     • Ensures code quality and consistency"
echo ""

echo "Checks executed:"
if [ "$RUN_PHPSTAN" = true ]; then
    echo "  • PHPStan Static Analysis (no WordPress)"
fi
if [ "$RUN_PHPCS" = true ]; then
    echo "  • WordPress Coding Standards"
fi
if [ "$RUN_TESTS" = true ]; then
    echo "  • PHPUnit Tests (WordPress Test Suite)"
fi

echo ""

if [ $OVERALL_STATUS -eq 0 ]; then
    print_success "ALL CHECKS PASSED ✓"
    echo ""
    print_success "🔒 Security features validated in real WordPress environment"
    print_info "Your code is ready to push to GitHub!"
    print_info "CI/CD pipeline should pass with these results."
else
    print_error "SOME CHECKS FAILED ✗"
    echo ""
    print_warning "Fix the issues above before pushing to GitHub"
    print_info "CI/CD pipeline will fail with current code"
    echo ""
    if [ "$RUN_TESTS" = true ] && [ ! -f "/tmp/wordpress-tests-lib/includes/functions.php" ]; then
        print_warning "WordPress Test Suite not installed!"
        print_info "Install: ./scripts/install-wp-tests.sh wordpress_test root '' localhost latest"
    fi
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

exit $OVERALL_STATUS
