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
 * @version 1.5.4
 */

namespace SilverAssist\Security\Core;

use SilverAssist\Security\Security\IPBlacklist;

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
	 * Cron event scheduled by IPBlacklist
	 */
	private const CLEANUP_CRON_HOOK = 'silver_assist_security_cleanup';

	/**
	 * Options saved by earlier versions that are no longer in DefaultConfig
	 *
	 * @var array<int, string>
	 */
	private const LEGACY_OPTIONS = array( 'silver_assist_ip_violation_threshold' );

	/**
	 * Transient name prefixes the plugin writes (without `_transient_`)
	 *
	 * @var array<int, string>
	 */
	private const TRANSIENT_PREFIXES = array(
		'silver_assist_',
		'ip_blacklist_',
		'ip_violations_',
		'lockout_',
		'login_attempts_',
		'login_window_',
		'login_access_',
		'bot_activity_',
		'extended_bot_block_',
		'cf7_total_attacks',
		'graphql_rate_',
		'bot_blocks_count_',
		'form_rate_',
	);

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
				// IDs only: the default fields would load (and cache) every user row with a session.
				'fields'     => 'ID',
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
		foreach ( $users as $user_id ) {
			$user_id           = (int) $user_id;
			$existing_activity = \get_user_meta( $user_id, 'last_activity', true );

			// Only set if not already set to avoid overwriting existing data.
			if ( empty( $existing_activity ) ) {
				\update_user_meta( $user_id, 'last_activity', $current_time );
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
		// Rate limiting counters are cheap to rebuild and would otherwise outlive the plugin.
		self::delete_transients_by_prefix( array( 'graphql_rate_' ) );

		// The cleanup event would otherwise stay in the cron array with no callback.
		\wp_clear_scheduled_hook( self::CLEANUP_CRON_HOOK );

		// Flush rewrite rules to clean up custom admin URL routing.
		\flush_rewrite_rules();
	}

	/**
	 * Plugin uninstall handler
	 *
	 * Removes everything the plugin writes: options (the defaults plus legacy names), every transient
	 * family, the `last_activity` user meta and the cleanup cron event. Single-site only: multisite is
	 * not supported, so the other sites of a network are not visited.
	 *
	 * @since 1.5.1
	 * @return void
	 */
	public static function uninstall(): void {
		foreach ( array_merge( array_keys( DefaultConfig::get_defaults() ), self::LEGACY_OPTIONS, DefaultConfig::get_legacy_option_names() ) as $option ) {
			\delete_option( $option );
		}

		self::delete_transients_by_prefix( self::TRANSIENT_PREFIXES );

		// Form rate keys written before 1.5.4 had the IP and the prefix swapped: `{ip}_{md5('form_rate')}`.
		self::delete_transients_by_suffix( '_' . md5( 'form_rate' ) );

		// Updater caches (names built by the updater package from the plugin slug).
		\delete_transient( 'silver-assist-security_version_check' );
		\delete_transient( 'wp_github_updater_notice_silver-assist-security' );

		\delete_metadata( 'user', 0, 'last_activity', '', true );

		// Index of the IP blacklist (see IPBlacklist::INDEX_OPTION).
		\delete_option( IPBlacklist::INDEX_OPTION );

		\wp_clear_scheduled_hook( self::CLEANUP_CRON_HOOK );
	}

	/**
	 * Delete transients (value and timeout rows) whose name starts with one of the prefixes
	 *
	 * Transients kept in an external object cache are not stored in the options table, so they are
	 * left to expire on their own.
	 *
	 * @since 1.5.4
	 * @param array<int, string> $prefixes Transient name prefixes, without `_transient_`.
	 * @return void
	 */
	private static function delete_transients_by_prefix( array $prefixes ): void {
		global $wpdb;

		foreach ( $prefixes as $prefix ) {
			foreach ( array( '_transient_', '_transient_timeout_' ) as $row_prefix ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Cleanup operation, caching not needed
				$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( $row_prefix . $prefix ) . '%' ) );
			}
		}
	}

	/**
	 * Delete transients (value and timeout rows) whose name ends with the suffix
	 *
	 * @since 1.5.4
	 * @param string $suffix Transient name suffix.
	 * @return void
	 */
	private static function delete_transients_by_suffix( string $suffix ): void {
		global $wpdb;

		foreach ( array( '_transient_', '_transient_timeout_' ) as $row_prefix ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Cleanup operation, caching not needed
			$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( $row_prefix ) . '%' . $wpdb->esc_like( $suffix ) ) );
		}
	}
}
