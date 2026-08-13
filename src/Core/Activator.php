<?php
/**
 * Silver Assist Security Essentials - Activation, Deactivation, and Uninstall
 *
 * Extracted from the former SilverAssistSecurityBootstrap class that lived
 * directly in the main plugin file, so the main file can be reduced to a
 * thin bootstrap matching the rest of the Silver Assist plugin portfolio.
 *
 * @package SilverAssist\Security\Core
 * @since 1.5.1
 * @author Silver Assist
 * @version 1.5.1
 */

namespace SilverAssist\Security\Core;

// Prevent direct access.
defined( 'ABSPATH' ) || exit;

/**
 * Class Activator
 *
 * Static handlers for the plugin's activation, deactivation, and uninstall
 * lifecycle, registered directly against register_activation_hook() /
 * register_deactivation_hook() / register_uninstall_hook() from the main
 * plugin file.
 *
 * @since 1.5.1
 */
class Activator {

	/**
	 * Plugin activation handler
	 *
	 * @since 1.5.1
	 * @return void
	 */
	public static function activate(): void {
		// Set default options using centralized configuration.
		foreach ( DefaultConfig::get_defaults() as $option => $value ) {
			if ( \get_option( $option ) === false ) {
				\add_option( $option, $value );
			}
		}

		// Initialize last_activity for all currently logged-in users.
		// This prevents immediate logout after plugin activation.
		self::initialize_user_last_activity();

		// Flush rewrite rules to ensure custom admin URL routing works properly.
		\flush_rewrite_rules();
	}

	/**
	 * Initialize last_activity for all currently logged-in users
	 *
	 * This prevents immediate logout after plugin activation by setting
	 * last_activity timestamp for users who are currently logged in.
	 *
	 * @since 1.5.1
	 * @return void
	 */
	private static function initialize_user_last_activity(): void {
		// Get all currently logged-in users by checking for active sessions.
		$current_time = time();

		// Query for users who have WordPress sessions (simplified check).
		$users = \get_users(
			array(
				// phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_query -- Session check on activation only, performance acceptable
				'meta_query' => array(
					array(
						'key'     => 'session_tokens',
						'compare' => 'EXISTS',
					),
				),
			)
		);

		// Initialize last_activity for each logged-in user.
		foreach ( $users as $user ) {
			$existing_activity = \get_user_meta( $user->ID, 'last_activity', true );

			// Only set if not already set to avoid overwriting existing data.
			if ( empty( $existing_activity ) ) {
				\update_user_meta( $user->ID, 'last_activity', $current_time );
			}
		}
	}

	/**
	 * Plugin deactivation handler
	 *
	 * @since 1.5.1
	 * @return void
	 */
	public static function deactivate(): void {
		// Clean up transients and temporary data.
		global $wpdb;

		// Clean up rate limiting transients.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Cleanup operation on deactivation, caching not needed
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_graphql_rate_limit_%'" );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Cleanup operation on deactivation, caching not needed
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_graphql_rate_limit_%'" );

		// Flush rewrite rules to clean up custom admin URL routing.
		\flush_rewrite_rules();
	}

	/**
	 * Plugin uninstall handler
	 *
	 * @since 1.5.1
	 * @return void
	 */
	public static function uninstall(): void {
		// Remove all plugin options using centralized configuration.
		foreach ( array_keys( DefaultConfig::get_defaults() ) as $option ) {
			\delete_option( $option );
		}

		// Clean up any remaining transients.
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Cleanup operation on uninstall, caching not needed
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_silver_assist_%'" );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Cleanup operation on uninstall, caching not needed
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_silver_assist_%'" );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Cleanup operation on uninstall, caching not needed
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_graphql_rate_limit_%'" );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Cleanup operation on uninstall, caching not needed
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_graphql_rate_limit_%'" );
	}
}
