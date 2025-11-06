#!/bin/bash

# Silver Assist Security - CI/CD Setup Validation Script
# This script validates that all CI/CD components are properly configured
# for WordPress and Contact Form 7 integration testing.

set -e  # Exit on any error

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}$1${NC}"
    echo "========================================="
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

print_header "🔍 CI/CD Setup Validation"

# Check 1: GitHub Actions workflow exists and is valid
print_header "1. GitHub Actions Workflow Validation"

if [ ! -f ".github/workflows/quality-checks.yml" ]; then
    print_error "GitHub Actions workflow not found"
    exit 1
fi

# Check if workflow includes WordPress setup
if grep -q "Install WordPress Test Suite" ".github/workflows/quality-checks.yml"; then
    print_success "WordPress Test Suite setup found in workflow"
else
    print_error "WordPress Test Suite setup missing from workflow"
    exit 1
fi

# Check if workflow includes CF7 installation
if grep -q "Install Contact Form 7" ".github/workflows/quality-checks.yml"; then
    print_success "Contact Form 7 installation found in workflow"
else
    print_error "Contact Form 7 installation missing from workflow"
    exit 1
fi

# Check if workflow includes CF7 validation
if grep -q "CF7 Integration Tests" ".github/workflows/quality-checks.yml"; then
    print_success "CF7 integration tests validation found in workflow"
else
    print_error "CF7 integration tests validation missing from workflow"
    exit 1
fi

# Check 2: Required scripts exist and are executable
print_header "2. Required Scripts Validation"

REQUIRED_SCRIPTS=(
    "install-wp-tests.sh"
    "install-cf7-for-tests.sh"
    "run-quality-checks.sh"
)

for script in "${REQUIRED_SCRIPTS[@]}"; do
    if [ ! -f "scripts/$script" ]; then
        print_error "Required script missing: scripts/$script"
        exit 1
    fi
    
    if [ ! -x "scripts/$script" ]; then
        print_warning "Script not executable: scripts/$script"
        chmod +x "scripts/$script"
        print_success "Made executable: scripts/$script"
    else
        print_success "Script found and executable: scripts/$script"
    fi
done

# Check 3: CF7 installation script validation
print_header "3. CF7 Installation Script Validation"

if grep -q "Downloading Contact Form 7" "scripts/install-cf7-for-tests.sh"; then
    print_success "CF7 download functionality found"
else
    print_error "CF7 download functionality missing"
    exit 1
fi

if grep -q "WordPress Core Dir:" "scripts/install-cf7-for-tests.sh"; then
    print_success "WordPress path resolution found"
else
    print_error "WordPress path resolution missing"
    exit 1
fi

# Check 4: Quality checks script CF7 integration
print_header "4. Quality Checks Script CF7 Integration"

if grep -q "Installing Contact Form 7" "scripts/run-quality-checks.sh"; then
    print_success "CF7 installation integrated in quality checks"
else
    print_error "CF7 installation not integrated in quality checks"
    exit 1
fi

if grep -q "Contact Form 7.*integration active" "scripts/run-quality-checks.sh"; then
    print_success "CF7 integration reporting found"
else
    print_error "CF7 integration reporting missing"
    exit 1
fi

# Check 5: Test files exist for CF7 integration
print_header "5. CF7 Integration Test Files Validation"

CF7_TEST_FILES=(
    "tests/Integration/ContactForm7IntegrationTest.php"
    "tests/Integration/CF7AdminPanelTest.php"
)

for test_file in "${CF7_TEST_FILES[@]}"; do
    if [ ! -f "$test_file" ]; then
        print_error "CF7 test file missing: $test_file"
        exit 1
    fi
    
    # Check if test file has proper structure
    if grep -q "class.*Test.*extends.*WP_UnitTestCase" "$test_file"; then
        print_success "CF7 test file valid: $test_file"
    else
        print_error "CF7 test file invalid structure: $test_file"
        exit 1
    fi
done

# Check 6: PHPUnit configuration includes test directories
print_header "6. PHPUnit Configuration Validation"

if [ ! -f "phpunit.xml.dist" ]; then
    print_error "PHPUnit configuration not found"
    exit 1
fi

if grep -q "tests/Integration" "phpunit.xml.dist"; then
    print_success "Integration tests directory included in PHPUnit config"
else
    print_error "Integration tests directory missing from PHPUnit config"
    exit 1
fi

# Check 7: WordPress Test Suite requirements
print_header "7. WordPress Test Suite Requirements"

# Check if composer includes required packages
if grep -q "phpunit/phpunit" "composer.json"; then
    print_success "PHPUnit dependency found in composer.json"
else
    print_error "PHPUnit dependency missing from composer.json"
    exit 1
fi

# Check 8: CF7 integration workflow job
print_header "8. CF7-Specific Workflow Job Validation"

if grep -q "cf7-integration-tests:" ".github/workflows/quality-checks.yml"; then
    print_success "Dedicated CF7 integration job found"
else
    print_error "Dedicated CF7 integration job missing"
    exit 1
fi

if grep -q "Run CF7 Integration Test Suite" ".github/workflows/quality-checks.yml"; then
    print_success "CF7 integration test suite execution found"
else
    print_error "CF7 integration test suite execution missing"
    exit 1
fi

# Check 9: Matrix strategy includes CF7 testing
print_header "9. Matrix Strategy Validation"

if grep -A 10 "cf7-integration-tests:" ".github/workflows/quality-checks.yml" | grep -q "matrix:"; then
    print_success "Matrix strategy found for CF7 tests"
else
    print_error "Matrix strategy missing for CF7 tests"
    exit 1
fi

# Check 10: Artifact upload for CF7 results
print_header "10. CF7 Results Artifact Upload"

if grep -q "cf7-integration-results" ".github/workflows/quality-checks.yml"; then
    print_success "CF7 results artifact upload configured"
else
    print_error "CF7 results artifact upload missing"
    exit 1
fi

# Final validation
print_header "🎉 CI/CD Validation Summary"

print_success "All CI/CD components are properly configured!"
echo ""
echo "✅ GitHub Actions workflow includes WordPress Test Suite setup"
echo "✅ Contact Form 7 installation is integrated"
echo "✅ CF7 integration tests are configured"
echo "✅ Dedicated CF7 job runs comprehensive tests"
echo "✅ Test results are uploaded as artifacts"
echo "✅ Quality checks script includes CF7 reporting"
echo ""
print_success "Ready for automated WordPress + CF7 integration testing! 🚀"

exit 0