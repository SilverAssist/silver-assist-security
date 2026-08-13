<?php
/**
 * Plugin Name: Silver Assist Security Essentials
 * Plugin URI: https://github.com/SilverAssist/silver-assist-security
 * Description: Resolves critical security vulnerabilities: WordPress login protection, HTTPOnly cookie implementation, and comprehensive GraphQL security. Addresses security audit findings automatically.
 * Version: 1.5.1
 * Author: Silver Assist
 * Author URI: http://silverassist.com/
 * Text Domain: silver-assist-security
 * Domain Path: /languages
 * Requires PHP: 8.2
 * Requires at least: 6.5
 * Tested up to: 6.7
 * Network: false
 * License: Polyform Noncommercial License 1.0.0
 * License URI: https://polyformproject.org/licenses/noncommercial/1.0.0/
 *
 * @package SilverAssist\Security
 * @since 1.1.1
 * @author Silver Assist
 * @version 1.5.1
 */

// Prevent direct access.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// PHP version check - Require PHP 8.2+.
if ( version_compare( PHP_VERSION, '8.2.0', '<' ) ) {
	add_action(
		'admin_notices',
		function () {
			echo '<div class="notice notice-error"><p>';
			echo '<strong>Silver Assist Security Essentials:</strong> This plugin requires PHP 8.2 or higher. ';
			echo 'You are currently running PHP ' . PHP_VERSION . '. ';
			echo 'Please contact your hosting provider to upgrade PHP.';
			echo '</p></div>';
		}
	);
	return;
}

// Define plugin constants.
define( 'SILVER_ASSIST_SECURITY_VERSION', '1.5.1' );
define( 'SILVER_ASSIST_SECURITY_PATH', plugin_dir_path( __FILE__ ) );
define( 'SILVER_ASSIST_SECURITY_URL', plugin_dir_url( __FILE__ ) );
define( 'SILVER_ASSIST_SECURITY_BASENAME', plugin_basename( __FILE__ ) );

// Load Composer autoloader for external dependencies and this plugin's own PSR-4-mapped classes.
$composer_autoloader = SILVER_ASSIST_SECURITY_PATH . 'vendor/autoload.php';
if ( file_exists( $composer_autoloader ) ) {
	require_once $composer_autoloader;
}

use SilverAssist\Security\Core\Activator;
use SilverAssist\Security\Core\Plugin;
use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\Core\SecurityLoader;
use SilverAssist\Security\GraphQL\GraphQLLoader;

// Plugin lifecycle hooks.
register_activation_hook( __FILE__, array( Activator::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( Activator::class, 'deactivate' ) );
register_uninstall_hook( __FILE__, array( Activator::class, 'uninstall' ) );

/**
 * Bootstrap the plugin across its three loading tiers.
 *
 * The kernel's AbstractPlugin::init() loads every listed component in one
 * batch, on whichever hook triggers it — so a single bootstrap call can't
 * serve components with genuinely different timing requirements. This
 * plugin has three:
 *
 * - plugins_loaded priority 1 (SecurityLoader): login/brute-force
 *   protection and other auth-adjacent hooks that wp-login.php can act on
 *   before "init" fires.
 * - plugins_loaded priority 5 (GraphQLLoader): GraphQL API-key
 *   authentication, which must register its determine_current_user filter
 *   before WordPress resolves the current user — but late enough to give
 *   WPGraphQL a chance to define its own class first.
 * - init (Plugin, the plugin root): everything else — admin panel, CF7
 *   integration, updater, textdomain — matching the timing every other
 *   Silver Assist plugin on wp-plugin-kernel uses by default.
 *
 * These are pre-existing timing requirements carried over unchanged from
 * the pre-kernel bootstrap; see each loader class's docblock.
 */
add_action(
	'plugins_loaded',
	static function () {
		SecurityHelper::init();
		SecurityLoader::instance()->init();
	},
	1
);

add_action(
	'plugins_loaded',
	static function () {
		GraphQLLoader::instance()->init();
	},
	5
);

add_action(
	'init',
	static function () {
		Plugin::instance()->init();
	}
);
