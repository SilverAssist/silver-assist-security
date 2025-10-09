<?php
/**
 * PHPUnit bootstrap file for Silver Assist Security Essentials
 *
 * Sets up WordPress test environment with Brain Monkey and loads the plugin for testing.
 *
 * @package SilverAssist\Security\Tests
 * @since 1.0.0
 * @version 1.1.12
 */

// Define test environment
if (!defined("SILVER_ASSIST_SECURITY_TESTING")) {
    define("SILVER_ASSIST_SECURITY_TESTING", true);
}

// Composer autoloader (loads Brain Monkey FIRST before WordPress stubs)
if (file_exists(dirname(__DIR__) . "/vendor/autoload.php")) {
    require_once dirname(__DIR__) . "/vendor/autoload.php";
}

// NOTE: WordPress stubs are NOT loaded here to avoid conflicts with Brain Monkey
// Brain Monkey's Patchwork needs to be initialized before any WordPress functions are defined
// WordPress stubs will be available through type hints but functions will be mocked by Brain Monkey

// Plugin constants
if (!defined("SILVER_ASSIST_SECURITY_PATH")) {
    define("SILVER_ASSIST_SECURITY_PATH", dirname(__DIR__));
}

if (!defined("SILVER_ASSIST_SECURITY_URL")) {
    define("SILVER_ASSIST_SECURITY_URL", "http://example.org/wp-content/plugins/silver-assist-security/");
}

if (!defined("SILVER_ASSIST_SECURITY_BASENAME")) {
    define("SILVER_ASSIST_SECURITY_BASENAME", "silver-assist-security/silver-assist-security.php");
}

if (!defined("SILVER_ASSIST_SECURITY_VERSION")) {
    define("SILVER_ASSIST_SECURITY_VERSION", "1.1.12");
}

// WordPress constants for testing
if (!defined("ABSPATH")) {
    define("ABSPATH", "/tmp/wordpress/");
}

if (!defined("WP_DEBUG")) {
    define("WP_DEBUG", true);
}

if (!defined("WP_DEBUG_LOG")) {
    define("WP_DEBUG_LOG", false);
}

if (!defined("WP_DEBUG_DISPLAY")) {
    define("WP_DEBUG_DISPLAY", true);
}

// WordPress content directory
if (!defined("WP_CONTENT_DIR")) {
    define("WP_CONTENT_DIR", ABSPATH . "wp-content");
}

// Database configuration for tests (not used with Brain Monkey but kept for compatibility)
if (!defined("DB_NAME")) {
    define("DB_NAME", "wordpress_test");
}

if (!defined("DB_USER")) {
    define("DB_USER", "root");
}

if (!defined("DB_PASSWORD")) {
    define("DB_PASSWORD", "");
}

if (!defined("DB_HOST")) {
    define("DB_HOST", "localhost");
}

// WordPress table prefix
if (!defined("table_prefix")) {
    $table_prefix = "wptests_";
}

/**
 * Initialize Brain Monkey for WordPress function mocking
 * This is called automatically by PHPUnit via TestCase setUp
 */

// Test helper functions
require_once __DIR__ . "/Helpers/TestHelper.php";
