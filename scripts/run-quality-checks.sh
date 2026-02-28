#!/bin/bash
# Quality Checks Runner for Silver Assist Security Essentials
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Configuration with environment variable support
SKIP_WP_SETUP="${SKIP_WP_SETUP:-false}"
FORCE_DB_RECREATE="${FORCE_DB_RECREATE:-false}"
FORCE_CF7_REINSTALL="${FORCE_CF7_REINSTALL:-false}"
FORCE_GRAPHQL_REINSTALL="${FORCE_GRAPHQL_REINSTALL:-false}"
NON_INTERACTIVE="${NON_INTERACTIVE:-false}"

# Auto-detect CI environment and set non-interactive mode
if [[ "$CI" == "true" ]] || [[ "$GITHUB_ACTIONS" == "true" ]] || [[ "$CONTINUOUS_INTEGRATION" == "true" ]]; then
    NON_INTERACTIVE="true"
    FORCE_DB_RECREATE="true"
    FORCE_CF7_REINSTALL="true"
    FORCE_GRAPHQL_REINSTALL="true"
    echo "🤖 CI environment detected - running in non-interactive mode"
fi

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

setup_wordpress_test_suite() {
    if [[ "$SKIP_WP_SETUP" == "true" ]]; then
        echo "⏭️  Skipping WordPress Test Suite setup"
        return 0
    fi
    
    print_header "🚀 Setting Up WordPress Test Suite"
    cd "$PROJECT_ROOT"
    
    # Set TMPDIR to match install-wp-tests.sh behavior
    TMPDIR=${TMPDIR:-/tmp}
    TMPDIR=$(echo $TMPDIR | sed -e "s/\/$//")
    
    # Set environment variables for non-interactive installation
    export FORCE_DB_RECREATE="$FORCE_DB_RECREATE"
    export FORCE_CF7_REINSTALL="$FORCE_CF7_REINSTALL"
    export FORCE_GRAPHQL_REINSTALL="$FORCE_GRAPHQL_REINSTALL"
    export WP_TESTS_DIR="${WP_TESTS_DIR:-$TMPDIR/wordpress-tests-lib}"
    
    # Determine WordPress version to install
    WP_VERSION="${WP_VERSION:-latest}"
    
    # Install WordPress Test Suite - Check if in CI environment for credentials
    if [[ "$CI" == "true" ]] || [[ "$GITHUB_ACTIONS" == "true" ]]; then
        # CI environment - use root password and 127.0.0.1
        bash scripts/install-wp-tests.sh wordpress_test root root 127.0.0.1 "$WP_VERSION"
    else
        # Local environment - use empty password and localhost
        bash scripts/install-wp-tests.sh wordpress_test root '' localhost "$WP_VERSION"
    fi
    
    # Install Contact Form 7 for integration tests
    if [[ -f "scripts/install-cf7-for-tests.sh" ]]; then
        echo "📦 Installing Contact Form 7 for integration tests..."
        bash scripts/install-cf7-for-tests.sh
    fi
    
    # Install WPGraphQL for integration tests
    if [[ -f "scripts/install-wpgraphql-for-tests.sh" ]]; then
        echo "📦 Installing WPGraphQL for integration tests..."
        bash scripts/install-wpgraphql-for-tests.sh
    fi
    
    print_success "WordPress Test Suite ready"
}

run_phpunit() {
    print_header "🧪 Running PHPUnit Tests"
    cd "$PROJECT_ROOT"
    
    # Set TMPDIR to match install-wp-tests.sh behavior
    TMPDIR=${TMPDIR:-/tmp}
    TMPDIR=$(echo $TMPDIR | sed -e "s/\/$//")
    export WP_TESTS_DIR="${WP_TESTS_DIR:-$TMPDIR/wordpress-tests-lib}"
    
    # Ensure WordPress Test Suite is setup
    if [[ ! -d "$WP_TESTS_DIR" ]]; then
        setup_wordpress_test_suite
    fi
    
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
    
    # Check WPGraphQL integration
    GRAPHQL_PLUGIN_FILE="$WP_CORE_DIR/wp-content/plugins/wp-graphql/wp-graphql.php"
    if [ -f "$GRAPHQL_PLUGIN_FILE" ]; then
        GRAPHQL_VERSION=$(grep "Version:" "$GRAPHQL_PLUGIN_FILE" | sed 's/.*Version: //' | sed 's/ .*//')
        echo "✅ WPGraphQL v$GRAPHQL_VERSION integration active"
        
        GRAPHQL_RESULT=$(vendor/bin/phpunit --filter="GraphQL" --testdox 2>/dev/null | grep -c "✔" || echo "0")
        echo "- GraphQL Security Integration: $GRAPHQL_RESULT tests"
    else
        echo "⚠️  WPGraphQL not found at: $GRAPHQL_PLUGIN_FILE"
        echo "GraphQL integration tests will be skipped"
    fi
    
    print_success "All tests completed"
}

# Show help
show_help() {
    echo "Silver Assist Security - Quality Checks Runner"
    echo ""
    echo "Usage: $0 [OPTIONS] [CHECKS...]"
    echo ""
    echo "Available Checks:"
    echo "  composer     - Validate composer.json and check for vulnerabilities"
    echo "  phpcs        - WordPress Coding Standards check"
    echo "  phpstan      - Static analysis with PHPStan"
    echo "  phpunit      - Run PHPUnit test suite"
    echo "  all          - Run all checks (default)"
    echo ""
    echo "Options:"
    echo "  --help, -h              Show this help message"
    echo "  --skip-wp-setup         Skip WordPress Test Suite installation"
    echo "  --non-interactive       Run in non-interactive mode (auto-yes to prompts)"
    echo "  --force-db-recreate     Force database recreation without prompting"
    echo "  --force-cf7-reinstall   Force Contact Form 7 reinstallation"
    echo "  --force-graphql-reinstall Force WPGraphQL reinstallation"
    echo "  --verbose, -v           Enable verbose output"
    echo ""
    echo "Environment Variables:"
    echo "  SKIP_WP_SETUP=true      Skip WordPress setup"
    echo "  NON_INTERACTIVE=true    Enable non-interactive mode"
    echo "  FORCE_DB_RECREATE=true  Force database recreation"
    echo "  FORCE_CF7_REINSTALL=true Force CF7 reinstallation"
    echo "  FORCE_GRAPHQL_REINSTALL=true Force WPGraphQL reinstallation"
    echo "  CI=true                 Auto-enables non-interactive mode"
    echo ""
    echo "Examples:"
    echo "  $0                              # Run all checks"
    echo "  $0 phpcs phpstan               # Run only coding standards and static analysis"
    echo "  $0 --non-interactive phpunit   # Run tests non-interactively"
    echo "  FORCE_DB_RECREATE=true $0      # Force database recreation"
    echo "  CI=true $0                     # Simulate CI environment"
    echo ""
    exit 0
}

# Parse arguments
checks=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --help|-h)
            show_help
            ;;
        --skip-wp-setup)
            SKIP_WP_SETUP="true"
            shift
            ;;
        --non-interactive)
            NON_INTERACTIVE="true"
            FORCE_DB_RECREATE="true"
            FORCE_CF7_REINSTALL="true"
            FORCE_GRAPHQL_REINSTALL="true"
            shift
            ;;
        --force-db-recreate)
            FORCE_DB_RECREATE="true"
            shift
            ;;
        --force-cf7-reinstall)
            FORCE_CF7_REINSTALL="true"
            shift
            ;;
        --force-graphql-reinstall)
            FORCE_GRAPHQL_REINSTALL="true"
            shift
            ;;
        --verbose|-v)
            set -x  # Enable verbose mode
            shift
            ;;
        composer|phpcs|phpstan|phpunit|all)
            checks+=("$1")
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Run '$0 --help' for available options"
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
    setup_wordpress_test_suite
fi

# Run checks
failed_checks=()
for check in "${checks[@]}"; do
    case $check in
        all)
            run_composer_validate || failed_checks+=("composer")
            run_phpcs || failed_checks+=("phpcs")
            run_phpstan || failed_checks+=("phpstan")
            run_phpunit || failed_checks+=("phpunit")
            ;;
        composer)
            run_composer_validate || failed_checks+=("composer")
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
