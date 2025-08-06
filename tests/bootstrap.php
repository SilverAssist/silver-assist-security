<?php
/**
 * PHPUnit bootstrap file for Silver Assist Security Essentials
 *
 * Sets up WordPress test environment and loads the plugin for testing.
 *
 * @package SilverAssist\Security\Tests
 * @since 1.0.0
 */

// Define test environment
define('SILVER_ASSIST_SECURITY_TESTING', true);

// Composer autoloader
if (file_exists(dirname(__DIR__) . '/vendor/autoload.php')) {
    require_once dirname(__DIR__) . '/vendor/autoload.php';
}

// WordPress tests configuration
if (!defined('WP_TESTS_CONFIG_FILE_PATH')) {
    define('WP_TESTS_CONFIG_FILE_PATH', dirname(__FILE__) . '/wp-tests-config.php');
}

// Plugin constants
define('SILVER_ASSIST_SECURITY_PATH', dirname(__DIR__));
define('SILVER_ASSIST_SECURITY_URL', 'http://example.org/wp-content/plugins/silver-assist-security/');
define('SILVER_ASSIST_SECURITY_BASENAME', 'silver-assist-security/silver-assist-security.php');
define('SILVER_ASSIST_SECURITY_VERSION', '1.0.4');

// Load WordPress test functions
if (file_exists('/tmp/wordpress-tests-lib/includes/functions.php')) {
    require_once '/tmp/wordpress-tests-lib/includes/functions.php';
} elseif (getenv('WP_TESTS_DIR')) {
    require_once getenv('WP_TESTS_DIR') . '/includes/functions.php';
}

/**
 * Manually load the plugin being tested
 */
function _manually_load_plugin() {
    // Load plugin main file
    require dirname(__DIR__) . '/silver-assist-security.php';
}

// Load the plugin before WordPress loads
if (function_exists('tests_add_filter')) {
    tests_add_filter('muplugins_loaded', '_manually_load_plugin');
}

// Load WordPress test environment
if (file_exists('/tmp/wordpress-tests-lib/includes/bootstrap.php')) {
    require_once '/tmp/wordpress-tests-lib/includes/bootstrap.php';
} elseif (getenv('WP_TESTS_DIR')) {
    require_once getenv('WP_TESTS_DIR') . '/includes/bootstrap.php';
} else {
    // Fallback for development environment
    echo "WordPress test environment not found.\n";
    echo "Please install WordPress tests or set WP_TESTS_DIR environment variable.\n";
    exit(1);
}

// Test helper functions
require_once __DIR__ . '/Helpers/TestHelper.php';
