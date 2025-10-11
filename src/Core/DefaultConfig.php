<?php
/**
 * Silver Assist Security Essentials - Default Configuration
 *
 * Centralizes all default configuration values for the plugin
 *
 * @package SilverAssist\Security\Core
 * @since 1.1.1
 * @author Silver Assist
 * @version 1.1.14
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
	 * Get all default plugin options
	 *
	 * @since 1.1.1
	 * @return array<string, mixed>
	 */
	public static function get_defaults(): array {
		return array(
			'silver_assist_login_attempts'                => 5,
			'silver_assist_lockout_duration'              => 900, // 15 minutes
			'silver_assist_session_timeout'               => 30, // 30 minutes
			'silver_assist_password_strength_enforcement' => 1,
			'silver_assist_bot_protection'                => 1,
			'silver_assist_admin_hide_enabled'            => 0, // Admin hiding disabled by default for security.
			'silver_assist_admin_hide_path'               => 'silver-admin', // Custom admin path.
			'silver_assist_graphql_query_depth'           => 8,
			'silver_assist_graphql_query_complexity'      => 100,
			'silver_assist_graphql_query_timeout'         => 30, // Dynamic: Based on PHP timeout, capped at 30s.
			'silver_assist_graphql_headless_mode'         => 0,
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
		// Handle special case for GraphQL timeout that depends on PHP settings
		if ( $option_name === 'silver_assist_graphql_query_timeout' ) {
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
		if ( $saved_timeout !== false ) {
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
		return self::get_legitimate_actions( true ); // Include logout
	}

	/**
	 * Get legitimate actions for admin hide URL filtering (excludes logout for tokens)
	 *
	 * @since 1.1.8
	 * @return array<string> List of actions that should not get access tokens
	 */
	public static function get_admin_hide_bypass_actions(): array {
		return self::get_legitimate_actions( false ); // Exclude logout for URL token filtering
	}
}
