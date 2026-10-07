<?php
/**
 * Silver Assist Security Essentials - Default Configuration
 *
 * Centralizes all default configuration values for the plugin
 *
 * @package SilverAssist\Security\Core
 * @since 1.1.1
 * @author Silver Assist
 * @version 1.5.4
 */

namespace SilverAssist\Security\Core;

/**
 * Default Configuration class
 *
 * Provides centralized default values for all plugin settings
 *
 * @since 1.1.1
 */
class DefaultConfig {

	/**
	 * Options of earlier versions mapped to the option that replaced them
	 *
	 * Before 1.5.4 enforcement read `silver_assist_form_rate_*` while the settings screen saved
	 * `silver_assist_cf7_rate_*`, so the screen had no effect. Value: new option, minimum, maximum
	 * (the range the settings saver enforces).
	 *
	 * @var array<string, array{0: string, 1: int, 2: int}>
	 */
	private const LEGACY_OPTION_MAP = array(
		'silver_assist_form_rate_limit'  => array( 'silver_assist_cf7_rate_limit', 1, 10 ),
		'silver_assist_form_rate_window' => array( 'silver_assist_cf7_rate_window', 30, 300 ),
	);

	/**
	 * Legacy option names with no replacement, deleted by the migration
	 *
	 * `silver_assist_form_protection_enabled` was only displayed on the dashboard; the real
	 * switch is `silver_assist_cf7_protection_enabled`, so its value is not adopted.
	 *
	 * The next four were defaults that nothing read (#178). The checks they implied stay always on
	 * (obsolete browser and SQL injection checks in `FormProtection`, spam patterns and the
	 * rate-limit violations that feed the IP blacklist in `ContactForm7Integration`), so there is no
	 * switch to offer; the names stay here so the migration and uninstall remove the stored rows.
	 *
	 * @var array<int, string>
	 */
	private const LEGACY_OPTIONS_DROPPED = array(
		'silver_assist_form_protection_enabled',
		'silver_assist_obsolete_browser_detection',
		'silver_assist_sql_injection_detection',
		'silver_assist_cf7_spam_threshold',
		'silver_assist_cf7_auto_block_bots',
	);

	/**
	 * Names of every legacy option this class migrates or drops
	 *
	 * @since 1.5.4
	 * @return array<int, string>
	 */
	public static function get_legacy_option_names(): array {
		return array_merge( array_keys( self::LEGACY_OPTION_MAP ), self::LEGACY_OPTIONS_DROPPED );
	}

	/**
	 * Move legacy form rate options to the CF7 options, once
	 *
	 * Idempotent: a legacy value is adopted only when the replacement was never stored, so a value
	 * the admin saved is never overwritten, and the legacy row is deleted either way. The adopted
	 * value is clamped to the saver range.
	 *
	 * @since 1.5.4
	 * @return void
	 */
	public static function migrate_legacy_options(): void {
		foreach ( self::LEGACY_OPTION_MAP as $legacy => list( $current, $min, $max ) ) {
			$value = \get_option( $legacy, null );
			if ( null === $value ) {
				continue;
			}

			if ( null === \get_option( $current, null ) ) {
				\add_option( $current, max( $min, min( $max, (int) $value ) ) );
			}
			\delete_option( $legacy );
		}

		foreach ( self::LEGACY_OPTIONS_DROPPED as $legacy ) {
			\delete_option( $legacy );
		}
	}

	/**
	 * Get all default plugin options
	 *
	 * @since 1.1.1
	 * @return array<string, mixed>
	 */
	public static function get_defaults(): array {
		return array(
			'silver_assist_login_attempts'                 => 5,
			'silver_assist_lockout_duration'               => 900, // 15 minutes
			'silver_assist_session_timeout'                => 30, // 30 minutes
			'silver_assist_password_strength_enforcement'  => 1,
			'silver_assist_bot_protection'                 => 1,
			'silver_assist_admin_hide_enabled'             => 0, // Admin hiding disabled by default for security.
			'silver_assist_admin_hide_path'                => 'silver-admin', // Custom admin path.
			'silver_assist_graphql_query_depth'            => 8,
			'silver_assist_graphql_query_complexity'       => 100,
			'silver_assist_graphql_query_timeout'          => 30, // Dynamic: Based on PHP timeout, capped at 30s.
			'silver_assist_graphql_headless_mode'          => 0,
			'silver_assist_graphql_api_key'                => '', // Hashed API key for server-to-server authentication.
			'silver_assist_graphql_service_user_id'        => 0, // WordPress user ID for API key authentication.

			// IP Blacklist Settings.
			'silver_assist_ip_blacklist_enabled'           => 1, // Automatic blacklisting of repeat offenders.
			'silver_assist_ip_blacklist_threshold'         => 5, // Violations before auto-blacklist.
			'silver_assist_ip_blacklist_duration'          => 86400, // 24 hours blacklist duration
			'silver_assist_ip_violation_window'            => 3600, // 1 hour violation tracking window

			// Login Branding Settings.
			'silver_assist_login_branding_enabled'         => 1, // Enable login branding by default.
			'silver_assist_login_branding_logo_url'        => '', // Custom logo URL (empty = built-in SVG).
			'silver_assist_login_branding_bg_color'        => '', // Right column bg color (empty = default gradient).
			'silver_assist_login_branding_show_illustration' => 1, // Show illustration panel.

			// REST API Security Settings.
			'silver_assist_rest_batch_endpoint_protection' => 1, // Restrict batch endpoint for unauthenticated users.
			'silver_assist_rest_rate_limiting_enabled'     => 1, // Enable REST API rate limiting.
			'silver_assist_rest_rate_limit_requests'       => 100, // Max requests per window for unauthenticated users.
			'silver_assist_rest_rate_limit_window'         => 60, // Rate limit window in seconds.

			// Contact Form 7 Integration Settings.
			'silver_assist_cf7_protection_enabled'         => 1, // Enable CF7 protection by default.
			'silver_assist_cf7_rate_limit'                 => 2, // Max CF7 submissions per minute per IP.
			'silver_assist_cf7_rate_window'                => 60, // CF7 rate limiting window in seconds.
			'silver_assist_cf7_honeypot_enabled'           => 1, // Enable honeypot fields.
			'silver_assist_cf7_submission_delay'           => 2000, // Minimum submission time (milliseconds, 0 = off).
			'silver_assist_cf7_ip_block_duration'          => 3600, // Duration of a manual CF7 IP block (seconds, 1 hour).
		);
	}

	/**
	 * Get default value for specific option
	 *
	 * @since 1.1.1
	 * @param string $option_name The option name.
	 * @return mixed Default value or null if not found
	 */
	public static function get_default( string $option_name ) {
		$defaults = self::get_defaults();
		return $defaults[ $option_name ] ?? null;
	}

	/**
	 * Get option from WordPress with default fallback
	 *
	 * @since 1.1.1
	 * @param string $option_name The option name.
	 * @return mixed Option value or default value
	 */
	public static function get_option( string $option_name ) {
		// Handle special case for GraphQL timeout that depends on PHP settings.
		if ( 'silver_assist_graphql_query_timeout' === $option_name ) {
			return self::get_graphql_timeout_option();
		}

		return \get_option( $option_name, self::get_default( $option_name ) );
	}

	/**
	 * Get GraphQL timeout option with dynamic PHP timeout calculation
	 *
	 * @since 1.1.1
	 * @return int GraphQL query timeout in seconds
	 */
	private static function get_graphql_timeout_option(): int {
		// Check if option is already set in database.
		$saved_timeout = \get_option( 'silver_assist_graphql_query_timeout' );
		if ( false !== $saved_timeout ) {
			return (int) $saved_timeout;
		}

		// Calculate dynamic default based on PHP execution timeout.
		$php_timeout     = self::get_php_execution_timeout();
		$default_timeout = $php_timeout > 0 ? min( $php_timeout, 30 ) : 30; // Cap at 30 seconds max.

		return $default_timeout;
	}

	/**
	 * Get PHP execution timeout
	 *
	 * @since 1.1.1
	 * @return int PHP execution timeout in seconds (0 = unlimited)
	 */
	private static function get_php_execution_timeout(): int {
		$timeout = \ini_get( 'max_execution_time' );
		// Handle false return from ini_get.
		if ( ! \is_string( $timeout ) ) {
			return 30;
		}
		// Cast to int - empty string becomes 0.
		$timeout_int = (int) $timeout;
		// Return 30 if timeout is 0 or negative.
		return $timeout_int > 0 ? $timeout_int : 30;
	}

	/**
	 * Get legitimate WordPress actions that should bypass security restrictions
	 *
	 * @since 1.1.8
	 * @param bool $include_logout Whether to include logout action.
	 * @return array<string> List of legitimate WordPress actions
	 */
	public static function get_legitimate_actions( bool $include_logout = true ): array {
		$actions = array(
			'checkemail',       // Check email confirmation page.
			'confirm_admin_email', // Admin email confirmation.
			'confirmaction',     // Confirm action (used in admin email confirmation).
			'expired',          // Password reset link expired.
			'invalidkey',       // Invalid password reset key.
			'lostpassword',     // Lost password form.
			'newpwd',           // Set new password process.
			'postpass',         // Password protected posts.
			'register',         // User registration (if enabled).
			'resetpass',        // Reset password form after clicking email link.
			'retrievepassword', // Retrieve password (alias for lostpassword).
			'rp',                // Reset password request.
		);

		if ( $include_logout ) {
			$actions[] = 'logout'; // User logout process.
		}

		return $actions;
	}

	/**
	 * Get legitimate actions for bot protection (includes logout)
	 *
	 * @since 1.1.8
	 * @return array<string> List of actions that should bypass bot protection
	 */
	public static function get_bot_protection_bypass_actions(): array {
		return self::get_legitimate_actions( true ); // Include logout.
	}

	/**
	 * Get legitimate actions for admin hide URL filtering (excludes logout for tokens)
	 *
	 * @since 1.1.8
	 * @return array<string> List of actions that should not get access tokens
	 */
	public static function get_admin_hide_bypass_actions(): array {
		return self::get_legitimate_actions( false ); // Exclude logout for URL token filtering.
	}
}
