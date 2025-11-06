#!/usr/bin/env bash
#
# Contact Form 7 Installation Script for Testing
#
# This script downloads and installs Contact Form 7 in the WordPress test environment
# for integration testing purposes.
#
# @package SilverAssist\Security
# @since 1.1.15
# @author Silver Assist
#
# Usage:
#   bash scripts/install-cf7-for-tests.sh
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Print functions
print_header() {
    echo -e "\n${BLUE}$1${NC}"
    echo "=========================================="
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

# Get WordPress test installation directory
# WordPress core is installed in /tmp/wordpress, not inside the tests directory
WP_CORE_DIR=$(dirname ${WP_TESTS_DIR})/wordpress
WP_PLUGINS_DIR="$WP_CORE_DIR/wp-content/plugins"

print_header "Contact Form 7 Test Installation"

echo "WordPress Core Dir: $WP_CORE_DIR"
echo "WordPress Plugins Dir: $WP_PLUGINS_DIR"
echo ""

# Check if WordPress test environment exists
if [ ! -d "$WP_CORE_DIR" ]; then
    print_error "WordPress test environment not found at: $WP_CORE_DIR"
    echo "Please run: bash scripts/install-wp-tests.sh wordpress_test root '' localhost latest"
    exit 1
fi

# Create plugins directory if it doesn't exist
if [ ! -d "$WP_PLUGINS_DIR" ]; then
    print_warning "Creating plugins directory: $WP_PLUGINS_DIR"
    mkdir -p "$WP_PLUGINS_DIR"
fi

CF7_PLUGIN_DIR="$WP_PLUGINS_DIR/contact-form-7"

# Check if Contact Form 7 is already installed
if [ -d "$CF7_PLUGIN_DIR" ]; then
    print_success "Contact Form 7 already installed at: $CF7_PLUGIN_DIR"
    
    # Check version
    if [ -f "$CF7_PLUGIN_DIR/wp-contact-form-7.php" ]; then
        CF7_VERSION=$(grep "Version:" "$CF7_PLUGIN_DIR/wp-contact-form-7.php" | head -1 | sed 's/.*Version: //' | sed 's/ .*//')
        echo "Current version: $CF7_VERSION"
    fi
    
    echo ""
    
    # Check for non-interactive mode via environment variable or CI detection
    if [[ "$FORCE_CF7_REINSTALL" == "true" ]] || [[ "$CI" == "true" ]] || [[ "$GITHUB_ACTIONS" == "true" ]] || [[ "$CONTINUOUS_INTEGRATION" == "true" ]]; then
        print_warning "Non-interactive mode: Automatically reinstalling Contact Form 7"
        REPLY="y"
    else
        read -p "Do you want to reinstall Contact Form 7? (y/N): " -n 1 -r
        echo
    fi
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_success "Using existing Contact Form 7 installation"
        exit 0
    fi
    
    print_warning "Removing existing Contact Form 7..."
    rm -rf "$CF7_PLUGIN_DIR"
fi

print_header "Downloading Contact Form 7"

# Create temporary directory
TEMP_DIR=$(mktemp -d)
CF7_ZIP="$TEMP_DIR/contact-form-7.zip"

# Download latest Contact Form 7 from WordPress.org
echo "Downloading from WordPress.org repository..."
if command -v curl >/dev/null 2>&1; then
    curl -L "https://downloads.wordpress.org/plugin/contact-form-7.latest-stable.zip" -o "$CF7_ZIP"
elif command -v wget >/dev/null 2>&1; then
    wget "https://downloads.wordpress.org/plugin/contact-form-7.latest-stable.zip" -O "$CF7_ZIP"
else
    print_error "Neither curl nor wget found. Please install one of them."
    exit 1
fi

# Verify download
if [ ! -f "$CF7_ZIP" ] || [ ! -s "$CF7_ZIP" ]; then
    print_error "Failed to download Contact Form 7"
    exit 1
fi

print_success "Contact Form 7 downloaded successfully"

print_header "Installing Contact Form 7"

# Extract the plugin
cd "$WP_PLUGINS_DIR"
if command -v unzip >/dev/null 2>&1; then
    unzip -q "$CF7_ZIP"
else
    print_error "unzip command not found. Please install unzip."
    exit 1
fi

# Verify installation
if [ ! -d "$CF7_PLUGIN_DIR" ]; then
    print_error "Contact Form 7 extraction failed"
    exit 1
fi

if [ ! -f "$CF7_PLUGIN_DIR/wp-contact-form-7.php" ]; then
    print_error "Contact Form 7 main file not found"
    exit 1
fi

# Get installed version
CF7_VERSION=$(grep "Version:" "$CF7_PLUGIN_DIR/wp-contact-form-7.php" | head -1 | sed 's/.*Version: //' | sed 's/ .*//')

print_success "Contact Form 7 v$CF7_VERSION installed successfully"

# Clean up temporary files
rm -rf "$TEMP_DIR"

print_header "Verifying Installation"

# Check main plugin file
if [ -f "$CF7_PLUGIN_DIR/wp-contact-form-7.php" ]; then
    print_success "Main plugin file: wp-contact-form-7.php"
fi

# Check for key CF7 classes
CF7_CLASSES=(
    "includes/contact-form.php"
    "includes/submission.php"
    "includes/form-tag.php"
    "includes/validation.php"
)

for class_file in "${CF7_CLASSES[@]}"; do
    if [ -f "$CF7_PLUGIN_DIR/$class_file" ]; then
        print_success "Found: $class_file"
    else
        print_warning "Missing: $class_file"
    fi
done

print_header "Integration Test Setup"

# Create CF7 integration test helper
CF7_TEST_HELPER="$CF7_PLUGIN_DIR/cf7-test-helper.php"
cat > "$CF7_TEST_HELPER" << 'EOF'
<?php
/**
 * Contact Form 7 Test Helper
 * 
 * Helper functions to load CF7 in WordPress test environment
 */

// Ensure CF7 is loaded for tests
if (!defined('WPCF7_PLUGIN_DIR')) {
    define('WPCF7_PLUGIN_DIR', __DIR__);
}

if (!defined('WPCF7_PLUGIN_URL')) {
    define('WPCF7_PLUGIN_URL', plugins_url('/', __FILE__));
}

// Load CF7 main file if not already loaded
if (!class_exists('WPCF7_ContactForm')) {
    require_once __DIR__ . '/wp-contact-form-7.php';
}

// Initialize CF7 for testing
if (!did_action('wpcf7_init')) {
    do_action('wpcf7_init');
}

// Helper function to create test contact form
function create_test_contact_form($title = 'Test Form', $form_content = null) {
    if ($form_content === null) {
        $form_content = '[text* your-name] [email* your-email] [textarea your-message] [submit "Send"]';
    }
    
    $contact_form = WPCF7_ContactForm::get_template();
    $contact_form->set_title($title);
    $contact_form->set_properties(array(
        'form' => $form_content,
        'mail' => array(
            'subject' => 'Test Subject',
            'sender' => '[your-name] <[your-email]>',
            'body' => '[your-message]',
            'recipient' => get_option('admin_email'),
        ),
    ));
    
    $contact_form->save();
    return $contact_form;
}

// Helper function to simulate form submission
function simulate_cf7_submission($form_id, $form_data = array()) {
    $contact_form = wpcf7_contact_form($form_id);
    
    if (!$contact_form) {
        return false;
    }
    
    // Default form data
    $default_data = array(
        'your-name' => 'Test User',
        'your-email' => 'test@example.com',
        'your-message' => 'This is a test message',
    );
    
    $form_data = array_merge($default_data, $form_data);
    
    // Simulate $_POST data
    $_POST = array_merge($_POST, $form_data);
    $_POST['_wpcf7'] = $contact_form->id();
    $_POST['_wpcf7_version'] = WPCF7_VERSION;
    $_POST['_wpcf7_locale'] = get_locale();
    $_POST['_wpcf7_unit_tag'] = 'wpcf7-f' . $contact_form->id() . '-o1';
    
    // Create submission
    $submission = WPCF7_Submission::get_instance($contact_form);
    
    return $submission;
}
EOF

print_success "Created CF7 test helper: cf7-test-helper.php"

print_header "Installation Complete"

echo "Contact Form 7 Installation Summary:"
echo "- Version: $CF7_VERSION"
echo "- Location: $CF7_PLUGIN_DIR"
echo "- Test Helper: $CF7_TEST_HELPER"
echo ""
echo "To use Contact Form 7 in tests, add this to your test setUp():"
echo ""
echo "    if (file_exists('$CF7_TEST_HELPER')) {"
echo "        require_once '$CF7_TEST_HELPER';"
echo "    }"
echo ""

print_success "Contact Form 7 ready for integration testing! 🚀"