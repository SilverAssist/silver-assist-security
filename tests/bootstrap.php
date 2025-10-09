<?php
/**
 * Bootstrap file for PHPUnit and PHPStan
 * 
 * This file is used by both PHPUnit (for tests) and PHPStan (for static analysis).
 * - For PHPUnit: Loads WordPress Test Suite
 * - For PHPStan: Only defines constants (WordPress stubs loaded via composer)
 *
 * @package SilverAssist\Security\Tests
 * @since 1.1.10
 */

// Composer autoloader must be loaded before WordPress test suite
require_once dirname(__DIR__) . "/vendor/autoload.php";

// Detect if we're running PHPStan (static analysis) or PHPUnit (tests)
// PHPStan sets environment variable or can be detected by checking if we're analyzing
$is_phpstan = getenv("PHPSTAN_RUNNING") === "1" || 
              (isset($_SERVER["argv"]) && in_array("analyse", $_SERVER["argv"]));

// For PHPStan: Define plugin constants (WordPress stubs loaded via composer)
// For PHPUnit: Constants will be defined by plugin main file when loaded
if ($is_phpstan) {
    if (!defined("SILVER_ASSIST_SECURITY_VERSION")) {
        define("SILVER_ASSIST_SECURITY_VERSION", "1.1.11");
    }
    
    if (!defined("SILVER_ASSIST_SECURITY_PATH")) {
        define("SILVER_ASSIST_SECURITY_PATH", dirname(__DIR__));
    }
    
    if (!defined("SILVER_ASSIST_SECURITY_URL")) {
        define("SILVER_ASSIST_SECURITY_URL", "http://example.org/wp-content/plugins/silver-assist-security");
    }
    
    if (!defined("SILVER_ASSIST_SECURITY_BASENAME")) {
        define("SILVER_ASSIST_SECURITY_BASENAME", "silver-assist-security/silver-assist-security.php");
    }
}

// Only load WordPress Test Suite for PHPUnit, not for PHPStan
if (!$is_phpstan) {
    // Get WordPress tests directory
    $_tests_dir = getenv("WP_TESTS_DIR");

if (!$_tests_dir) {
    $_tests_dir = rtrim(sys_get_temp_dir(), "/\\") . "/wordpress-tests-lib";
}

// Forward custom PHPUnit Polyfills configuration to PHPUnit bootstrap file
$_phpunit_polyfills_path = dirname(__DIR__) . "/vendor/yoast/phpunit-polyfills/phpunitpolyfills-autoload.php";
if (file_exists($_phpunit_polyfills_path)) {
    require_once $_phpunit_polyfills_path;
}

if (!file_exists("{$_tests_dir}/includes/functions.php")) {
    echo "\n❌ Could not find WordPress test suite at: {$_tests_dir}/includes/functions.php\n\n";
    echo "📋 Run the following command to install WordPress test suite:\n";
    echo "   scripts/install-wp-tests.sh <db-name> <db-user> <db-pass> [db-host] [wp-version]\n\n";
    echo "💡 Example:\n";
    echo "   scripts/install-wp-tests.sh wordpress_test root '' localhost latest\n\n";
    echo "ℹ️  Or set WP_TESTS_DIR environment variable to your WordPress test installation:\n";
    echo "   export WP_TESTS_DIR=/path/to/wordpress-tests-lib\n\n";
    exit(1);
}

// Give access to tests_add_filter() function
require_once "{$_tests_dir}/includes/functions.php";

/**
 * Manually load the plugin being tested
 */
function _manually_load_plugin() {
    require dirname(__DIR__) . "/silver-assist-security.php";
}

tests_add_filter("muplugins_loaded", "_manually_load_plugin");

// Start up the WP testing environment
require "{$_tests_dir}/includes/bootstrap.php";

// Note: Removed echo statements to prevent "headers already sent" errors
// Output before tests causes issues when tests trigger WordPress hooks that send headers

} // End PHPUnit-only section

// For PHPStan: WordPress stubs are loaded automatically via composer
// No additional WordPress loading needed for static analysis
