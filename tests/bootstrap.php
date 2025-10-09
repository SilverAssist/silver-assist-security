<?php
/**
 * PHPUnit bootstrap file for WordPress Integration Tests
 *
 * @package SilverAssist\Security\Tests
 * @since 1.1.10
 */

// Composer autoloader must be loaded before WordPress test suite
require_once dirname(__DIR__) . "/vendor/autoload.php";

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
    echo "   bin/install-wp-tests.sh <db-name> <db-user> <db-pass> [db-host] [wp-version]\n\n";
    echo "💡 Example:\n";
    echo "   bin/install-wp-tests.sh wordpress_test root '' localhost latest\n\n";
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

echo "\n✅ WordPress Test Environment Loaded Successfully\n";
echo "   WordPress Version: " . get_bloginfo("version") . "\n";
echo "   PHP Version: " . PHP_VERSION . "\n";
echo "   PHPUnit Version: " . \PHPUnit\Runner\Version::id() . "\n\n";
