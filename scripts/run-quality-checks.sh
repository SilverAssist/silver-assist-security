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
    
    # Run all tests with detailed output
    vendor/bin/phpunit --testdox
    
    print_header "📊 Test Summary"
    
    # Check if Contact Form 7 tests ran successfully
    # WordPress core is installed in /tmp/wordpress, not inside the tests directory
    WP_CORE_DIR=$(dirname ${WP_TESTS_DIR})/wordpress
    CF7_PLUGIN_FILE="$WP_CORE_DIR/wp-content/plugins/contact-form-7/wp-contact-form-7.php"
    
    if [ -f "$CF7_PLUGIN_FILE" ]; then
        CF7_VERSION=$(grep "Version:" "$CF7_PLUGIN_FILE" | sed 's/.*Version: //' | sed 's/ .*//')
        echo "✅ Contact Form 7 v$CF7_VERSION integration active"
        echo "Plugin location: $CF7_PLUGIN_FILE"
        
        # Run CF7-specific tests for detailed reporting
        echo ""
        echo "Contact Form 7 Integration Test Results:"
        CF7_RESULT=$(vendor/bin/phpunit tests/Integration/ContactForm7IntegrationTest.php --testdox 2>/dev/null | grep -c "✔" || echo "0")
        echo "- CF7 Security Integration: $CF7_RESULT/10 tests"
        
        ADMIN_RESULT=$(vendor/bin/phpunit tests/Integration/CF7AdminPanelTest.php --testdox 2>/dev/null | grep -c "✔" || echo "0")
        echo "- CF7 Admin Panel: $ADMIN_RESULT/6 tests"
    else
        echo "⚠️  Contact Form 7 not found at: $CF7_PLUGIN_FILE"
        echo "Integration tests may be limited"
    fi
    
    print_success "All tests completed"
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
        
        print_header "📧 Installing Contact Form 7 for Integration Tests"
        export WP_TESTS_DIR="${WP_TESTS_DIR:-/tmp/wordpress-tests-lib}"
        if [ -f "$SCRIPT_DIR/install-cf7-for-tests.sh" ]; then
            chmod +x "$SCRIPT_DIR/install-cf7-for-tests.sh"
            bash "$SCRIPT_DIR/install-cf7-for-tests.sh"
            print_success "Contact Form 7 integration ready"
        else
            print_error "CF7 installation script not found at: $SCRIPT_DIR/install-cf7-for-tests.sh"
        fi
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
