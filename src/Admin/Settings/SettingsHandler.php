<?php
/**
 * Silver Assist Security Essentials - Settings Handler
 *
 * Handles security settings form processing and validation for all security
 * configuration categories. Provides specialized methods for different settings
 * groups with proper validation and sanitization.
 *
 * @package SilverAssist\Security\Admin\Settings
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Admin\Settings;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\PathValidator;
use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;

/**
 * Settings Handler class
 *
 * Processes and validates all security configuration form submissions
 * with specialized methods for each settings category.
 *
 * @since 1.1.15
 */
class SettingsHandler {

	/**
	 * GraphQL Configuration Manager instance
	 *
	 * @var GraphQLConfigManager
	 */
	private GraphQLConfigManager $config_manager;

	/**
	 * Constructor
	 *
	 * @since 1.1.15
	 */
	public function __construct() {
		$this->config_manager = GraphQLConfigManager::getInstance();
	}

	/**
	 * Main settings processing method
	 *
	 * Validates request and delegates to appropriate specialized method
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function save_security_settings(): void {
		if ( ! isset( $_POST['save_silver_assist_security'] ) || ! \current_user_can( 'manage_options' ) ) {
			return;
		}

		// Verify nonce
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Nonce verification doesn't require unslashing or sanitization
		if ( ! isset( $_POST['_wpnonce'] ) || ! \wp_verify_nonce( $_POST['_wpnonce'], 'silver_assist_security_settings' ) ) {
			\wp_die( \esc_html__( 'Security check failed.', 'silver-assist-security' ) );
		}

		// Process different settings categories
		$this->save_login_security_settings();
		$this->save_admin_hide_settings();
		$this->save_graphql_settings();
		$this->save_contact_form7_settings();
		$this->save_ip_management_settings();
		$this->save_attack_protection_settings();
		$this->save_advanced_protection_settings();

		$this->add_success_notice();
	}

	/**
	 * Save login security settings
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function save_login_security_settings(): void {
		// Login attempts validation
		if ( isset( $_POST['silver_assist_login_attempts'] ) ) {
			$login_attempts = \intval( \sanitize_text_field( \wp_unslash( $_POST['silver_assist_login_attempts'] ) ) );
			$login_attempts = \max( 1, \min( 20, $login_attempts ) );
			\update_option( 'silver_assist_login_attempts', $login_attempts );
		}

		// Lockout duration validation
		if ( isset( $_POST['silver_assist_lockout_duration'] ) ) {
			$lockout_duration = \intval( \sanitize_text_field( \wp_unslash( $_POST['silver_assist_lockout_duration'] ) ) );
			$lockout_duration = \max( 60, \min( 3600, $lockout_duration ) );
			\update_option( 'silver_assist_lockout_duration', $lockout_duration );
		}

		// Session timeout validation
		if ( isset( $_POST['silver_assist_session_timeout'] ) ) {
			$session_timeout = \intval( \sanitize_text_field( \wp_unslash( $_POST['silver_assist_session_timeout'] ) ) );
			$session_timeout = \max( 5, \min( 120, $session_timeout ) );
			\update_option( 'silver_assist_session_timeout', $session_timeout );
		}

		// Boolean settings
		\update_option( 'silver_assist_bot_protection', (int) ( isset( $_POST['silver_assist_bot_protection'] ) ? \sanitize_text_field( \wp_unslash( $_POST['silver_assist_bot_protection'] ) ) : 0 ) );
		\update_option( 'silver_assist_password_strength_enforcement', (int) ( isset( $_POST['silver_assist_password_strength_enforcement'] ) ? \sanitize_text_field( \wp_unslash( $_POST['silver_assist_password_strength_enforcement'] ) ) : 0 ) );
	}

	/**
	 * Save Admin Hide settings
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function save_admin_hide_settings(): void {
		// Admin Hide enable/disable
		$admin_hide_enabled = (int) ( isset( $_POST['silver_assist_admin_hide_enabled'] ) ? \sanitize_text_field( \wp_unslash( $_POST['silver_assist_admin_hide_enabled'] ) ) : 0 );
		\update_option( 'silver_assist_admin_hide_enabled', $admin_hide_enabled );

		// Admin Hide path validation
		$admin_hide_path = isset( $_POST['silver_assist_admin_hide_path'] ) ? \sanitize_title( \wp_unslash( $_POST['silver_assist_admin_hide_path'] ) ) : 'silver-admin';
		if ( ! empty( $admin_hide_path ) && $this->validate_admin_hide_path( $admin_hide_path ) ) {
			\update_option( 'silver_assist_admin_hide_path', $admin_hide_path );
		} else {
			\update_option( 'silver_assist_admin_hide_path', 'silver-admin' );
		}

		// Flush rewrite rules when admin hide settings change
		if ( $admin_hide_enabled ) {
			\flush_rewrite_rules();
		}
	}

	/**
	 * Save GraphQL security settings
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function save_graphql_settings(): void {
		// Headless mode setting
		\update_option( 'silver_assist_graphql_headless_mode', (int) ( isset( $_POST['silver_assist_graphql_headless_mode'] ) ? \sanitize_text_field( \wp_unslash( $_POST['silver_assist_graphql_headless_mode'] ) ) : 0 ) );

		// GraphQL timeout setting
		if ( isset( $_POST['silver_assist_graphql_query_timeout'] ) ) {
			$graphql_timeout = \intval( \sanitize_text_field( \wp_unslash( $_POST['silver_assist_graphql_query_timeout'] ) ) );
			$php_timeout     = $this->config_manager->get_php_execution_timeout();
			$graphql_timeout = \max( 1, \min( $php_timeout, $graphql_timeout ) );
			\update_option( 'silver_assist_graphql_query_timeout', $graphql_timeout );
		}
	}

	/**
	 * Save Contact Form 7 security settings
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function save_contact_form7_settings(): void {
		// Only save CF7 settings if CF7 is active
		if ( ! SecurityHelper::is_contact_form_7_active() ) {
			return;
		}

		// CF7 Protection enable/disable
		\update_option( 'silver_assist_cf7_protection_enabled', (int) ( isset( $_POST['silver_assist_cf7_protection_enabled'] ) ? \sanitize_text_field( \wp_unslash( $_POST['silver_assist_cf7_protection_enabled'] ) ) : 0 ) );

		// CF7 Rate limiting
		if ( isset( $_POST['silver_assist_cf7_rate_limit'] ) ) {
			$cf7_rate_limit = \intval( \sanitize_text_field( \wp_unslash( $_POST['silver_assist_cf7_rate_limit'] ) ) );
			$cf7_rate_limit = \max( 1, \min( 10, $cf7_rate_limit ) );
			\update_option( 'silver_assist_cf7_rate_limit', $cf7_rate_limit );
		}

		if ( isset( $_POST['silver_assist_cf7_rate_window'] ) ) {
			$cf7_rate_window = \intval( \sanitize_text_field( \wp_unslash( $_POST['silver_assist_cf7_rate_window'] ) ) );
			$cf7_rate_window = \max( 30, \min( 300, $cf7_rate_window ) );
			\update_option( 'silver_assist_cf7_rate_window', $cf7_rate_window );
		}
	}

	/**
	 * Save IP management settings
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function save_ip_management_settings(): void {
		// IP Blacklist enable/disable
		\update_option( 'silver_assist_ip_blacklist_enabled', (int) ( isset( $_POST['silver_assist_ip_blacklist_enabled'] ) ? \sanitize_text_field( \wp_unslash( $_POST['silver_assist_ip_blacklist_enabled'] ) ) : 0 ) );

		// IP violation threshold
		if ( isset( $_POST['silver_assist_ip_violation_threshold'] ) ) {
			$ip_violation_threshold = \intval( \sanitize_text_field( \wp_unslash( $_POST['silver_assist_ip_violation_threshold'] ) ) );
			$ip_violation_threshold = \max( 3, \min( 20, $ip_violation_threshold ) );
			\update_option( 'silver_assist_ip_violation_threshold', $ip_violation_threshold );
		}

		// IP blacklist duration
		if ( isset( $_POST['silver_assist_ip_blacklist_duration'] ) ) {
			$ip_blacklist_duration = \intval( \sanitize_text_field( \wp_unslash( $_POST['silver_assist_ip_blacklist_duration'] ) ) );
			$ip_blacklist_duration = \max( 3600, \min( 604800, $ip_blacklist_duration ) );
			\update_option( 'silver_assist_ip_blacklist_duration', $ip_blacklist_duration );
		}
	}

	/**
	 * Save attack protection settings
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function save_attack_protection_settings(): void {
		// Under Attack Mode enable/disable
		\update_option( 'silver_assist_under_attack_enabled', (int) ( isset( $_POST['silver_assist_under_attack_enabled'] ) ? \sanitize_text_field( \wp_unslash( $_POST['silver_assist_under_attack_enabled'] ) ) : 0 ) );

		// Attack threshold
		if ( isset( $_POST['silver_assist_attack_threshold'] ) ) {
			$attack_threshold = \intval( \sanitize_text_field( \wp_unslash( $_POST['silver_assist_attack_threshold'] ) ) );
			$attack_threshold = \max( 5, \min( 50, $attack_threshold ) );
			\update_option( 'silver_assist_attack_threshold', $attack_threshold );
		}

		// Under attack duration
		if ( isset( $_POST['silver_assist_under_attack_duration'] ) ) {
			$under_attack_duration = \intval( \sanitize_text_field( \wp_unslash( $_POST['silver_assist_under_attack_duration'] ) ) );
			$under_attack_duration = \max( 300, \min( 7200, $under_attack_duration ) );
			\update_option( 'silver_assist_under_attack_duration', $under_attack_duration );
		}
	}

	/**
	 * Save advanced protection settings
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function save_advanced_protection_settings(): void {
		// Advanced CF7 protection features
		\update_option( 'silver_assist_cf7_honeypot_enabled', (int) ( isset( $_POST['silver_assist_cf7_honeypot_enabled'] ) ? \sanitize_text_field( \wp_unslash( $_POST['silver_assist_cf7_honeypot_enabled'] ) ) : 0 ) );
		\update_option( 'silver_assist_cf7_timing_protection', (int) ( isset( $_POST['silver_assist_cf7_timing_protection'] ) ? \sanitize_text_field( \wp_unslash( $_POST['silver_assist_cf7_timing_protection'] ) ) : 0 ) );
		\update_option( 'silver_assist_cf7_obsolete_browser_blocking', (int) ( isset( $_POST['silver_assist_cf7_obsolete_browser_blocking'] ) ? \sanitize_text_field( \wp_unslash( $_POST['silver_assist_cf7_obsolete_browser_blocking'] ) ) : 0 ) );
		\update_option( 'silver_assist_cf7_sql_injection_protection', (int) ( isset( $_POST['silver_assist_cf7_sql_injection_protection'] ) ? \sanitize_text_field( \wp_unslash( $_POST['silver_assist_sql_injection_protection'] ) ) : 0 ) );
	}

	/**
	 * Add success notice after settings save
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function add_success_notice(): void {
		\add_action(
			'admin_notices',
			function () {
				echo '<div class="notice notice-success is-dismissible">';
				echo '<p>' . \esc_html__( 'Security settings have been saved successfully.', 'silver-assist-security' ) . '</p>';
				echo '</div>';
			}
		);
	}

	/**
	 * Validate admin hide path using centralized PathValidator
	 *
	 * @since 1.1.15
	 * @param string $path The path to validate
	 * @return bool True if path is valid
	 */
	private function validate_admin_hide_path( string $path ): bool {
		$result = PathValidator::validate_admin_path( $path );
		return $result['is_valid'];
	}
}