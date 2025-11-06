#!/bin/bash
# Quality Checks Runner for Silver Assist Security Essentials
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SKIP_WP_SETUP="${SKIP_WP_SETUP:-false}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_header() {
    echo -e "\n${BLUE}$1${NC}"
    echo "=========================================="
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

run_composer_validate() {
    print_header "📦 Validating Composer Files"
    cd "$PROJECT_ROOT"
    composer validate --strict
    print_success "Composer files validated"
}

run_phpcs() {
    print_header "🎨 Running PHPCS"
    cd "$PROJECT_ROOT"
    composer run phpcs
    print_success "PHPCS passed"
}

run_phpstan() {
    print_header "🔍 Running PHPStan"
    cd "$PROJECT_ROOT"
    composer run phpstan
    print_success "PHPStan passed"
}

run_phpunit() {
    print_header "🧪 Running PHPUnit Tests"
    cd "$PROJECT_ROOT"
    export WP_TESTS_DIR="${WP_TESTS_DIR:-/tmp/wordpress-tests-lib}"
    vendor/bin/phpunit --testdox
    print_success "All tests passed"
}

# Parse arguments
checks=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-wp-setup)
            SKIP_WP_SETUP="true"
            shift
            ;;
        --verbose|-v)
            set -x  # Enable verbose mode
            shift
            ;;
        phpcs|phpstan|phpunit|composer-validate|all)
            checks+=("$1")
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Default to all if no checks specified
if [ ${#checks[@]} -eq 0 ]; then
    checks=("all")
fi

# Setup WordPress Test Suite if needed
if [[ " ${checks[*]} " =~ " phpunit " ]] || [[ " ${checks[*]} " =~ " all " ]]; then
    if [ "$SKIP_WP_SETUP" != "true" ]; then
        print_header "🐘 Setting up WordPress Test Suite"
        bash "$SCRIPT_DIR/install-wp-tests.sh" wordpress_test root '' localhost latest true
        print_success "WordPress Test Suite ready"
    fi
fi

# Run checks
failed_checks=()
for check in "${checks[@]}"; do
    case $check in
        all)
            run_composer_validate || failed_checks+=("composer-validate")
            run_phpcs || failed_checks+=("phpcs")
            run_phpstan || failed_checks+=("phpstan")
            run_phpunit || failed_checks+=("phpunit")
            ;;
        composer-validate)
            run_composer_validate || failed_checks+=("composer-validate")
            ;;
        phpcs)
            run_phpcs || failed_checks+=("phpcs")
            ;;
        phpstan)
            run_phpstan || failed_checks+=("phpstan")
            ;;
        phpunit)
            run_phpunit || failed_checks+=("phpunit")
            ;;
    esac
done

# Summary
print_header "📋 Summary"
if [ ${#failed_checks[@]} -eq 0 ]; then
    print_success "All quality checks passed! ✨"
    exit 0
else
    print_error "Failed checks: ${failed_checks[*]}"
    exit 1
fi
