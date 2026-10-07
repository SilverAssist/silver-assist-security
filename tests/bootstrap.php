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
 * Manually load the plugin being tested and its dependencies
 */
function _manually_load_plugin() {
    // Load WPGraphQL if available in the test environment
    if ( defined( 'WP_PLUGIN_DIR' ) && file_exists( WP_PLUGIN_DIR . '/wp-graphql/wp-graphql.php' ) ) {
        require_once WP_PLUGIN_DIR . '/wp-graphql/wp-graphql.php';
    }

    require dirname(__DIR__) . "/silver-assist-security.php";
}

tests_add_filter("muplugins_loaded", "_manually_load_plugin");

/**
 * Record how far the plugin's loading tiers had got at the moments that matter (PluginLoadingTiersTest)
 *
 * Callbacks registered by a plugin stay in $wp_filter, so a later look cannot tell when they were
 * added. The probes run at fixed points of the real boot sequence and store what they see.
 *
 * @param string $hook     Hook name.
 * @param string $class    Class whose method is expected on the hook.
 * @return bool Whether a callback of the class is registered on the hook.
 */
function _silver_probe_has_callback_of(string $hook, string $class): bool {
    global $wp_filter;
    if (!isset($wp_filter[$hook])) {
        return false;
    }
    foreach ($wp_filter[$hook]->callbacks as $callbacks) {
        foreach ($callbacks as $callback) {
            $function = $callback["function"];
            if (is_array($function) && is_object($function[0]) && $function[0] instanceof $class) {
                return true;
            }
        }
    }
    return false;
}

$GLOBALS["silver_assist_boot_probe"] = array();

// After the p1 tier and before the p5 tier.
tests_add_filter("plugins_loaded", function () {
    $GLOBALS["silver_assist_boot_probe"]["after_p1"] = array(
        "login_hooks" => _silver_probe_has_callback_of("login_init", "SilverAssist\\Security\\Security\\LoginSecurity"),
        "api_key_auth" => _silver_probe_has_callback_of("determine_current_user", "SilverAssist\\Security\\GraphQL\\GraphQLSecurity"),
    );
}, 2);

// After the p5 tier, before WordPress works out the current user.
tests_add_filter("plugins_loaded", function () {
    $GLOBALS["silver_assist_boot_probe"]["after_p5"] = array(
        "wpgraphql_loaded" => class_exists("WPGraphQL"),
        "api_key_auth" => _silver_probe_has_callback_of("determine_current_user", "SilverAssist\\Security\\GraphQL\\GraphQLSecurity"),
        "init_done" => did_action("init"),
    );
}, 6);

// The first time WordPress resolves the user (before init) the API key callback must already be there.
tests_add_filter("determine_current_user", function ($user_id) {
    if (!isset($GLOBALS["silver_assist_boot_probe"]["first_user_resolution"])) {
        $GLOBALS["silver_assist_boot_probe"]["first_user_resolution"] = array(
            "api_key_auth" => _silver_probe_has_callback_of("determine_current_user", "SilverAssist\\Security\\GraphQL\\GraphQLSecurity"),
            "init_done" => did_action("init"),
        );
    }
    return $user_id;
}, 0);

// A test that runs in a separate process can ask for constants that must exist before WordPress
// boots (WP_ENVIRONMENT_TYPE is read once and cached, SCRIPT_DEBUG is defined during startup). It
// passes them as JSON in SILVER_ASSIST_TEST_DEFINES; see ConstantsBehaviorTest. WP_DEBUG cannot be
// injected this way, the test configuration defines it unconditionally.
$_silver_defines = getenv("SILVER_ASSIST_TEST_DEFINES");
if (is_string($_silver_defines) && "" !== $_silver_defines) {
    foreach ((array) json_decode($_silver_defines, true) as $_name => $_value) {
        if (!defined((string) $_name)) {
            define((string) $_name, $_value);
        }
    }
}

// Start up the WP testing environment
require "{$_tests_dir}/includes/bootstrap.php";

// Note: Removed echo statements to prevent "headers already sent" errors
// Output before tests causes issues when tests trigger WordPress hooks that send headers

} // End PHPUnit-only section

// For PHPStan: WordPress stubs are loaded automatically via composer
// No additional WordPress loading needed for static analysis
