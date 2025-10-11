<?php

namespace SilverAssist\Security\Core;

/**
 * Admin Path Validator Utility
 *
 * Provides centralized validation logic for admin path security.
 * Used by both AdminHideSecurity and AdminPanel classes.
 *
 * @package SilverAssist\Security\Core
 * @since   1.1.4
 * @version 1.1.14
 */
class PathValidator {

	/**
	 * List of forbidden admin path keywords for security
	 *
	 * @var array<string>
	 * @since 1.1.4
	 */
	private static array $forbidden_paths = array(
		'admin',
		'login',
		'wp-admin',
		'wp-login',
		'wp-content',
		'wp-includes',
		'dashboard',
		'backend',
		'administrator',
		'root',
		'user',
		'auth',
		'signin',
		'panel',
		'control',
		'manage',
		'system',
	);

	/**
	 * Validation result structure
	 *
	 * @var array
	 * @since 1.1.4
	 */
	public const RESULT_STRUCTURE = array(
		'is_valid'       => false,
		'error_message'  => '',
		'error_type'     => '',
		'sanitized_path' => '',
	);

	/**
	 * Validate admin path for security compliance
	 *
	 * @since 1.1.4
	 * @param string $path The path to validate
	 * @return array Validation result with structure: [is_valid, error_message, error_type, sanitized_path]
	 */
	public static function validate_admin_path( string $path ): array {
		$result        = self::RESULT_STRUCTURE;
		$original_path = $path;
		$path          = strtolower( trim( $path ) );

		// Check if path is empty
		if ( empty( $path ) ) {
			$result['error_message'] = \__( 'Path cannot be empty', 'silver-assist-security' );
			$result['error_type']    = 'empty';
			return $result;
		}

		// Check length constraints
		if ( strlen( $path ) < 3 ) {
			$result['error_message'] = \__( 'Path must be at least 3 characters long', 'silver-assist-security' );
			$result['error_type']    = 'too_short';
			return $result;
		}

		if ( strlen( $path ) > 50 ) {
			$result['error_message'] = \__( 'Path must be 50 characters or less', 'silver-assist-security' );
			$result['error_type']    = 'too_long';
			return $result;
		}

		// Check character constraints (alphanumeric, hyphens, underscores only)
		if ( ! preg_match( '/^[a-zA-Z0-9-_]+$/', $path ) ) {
			$result['error_message'] = \__( 'Path can only contain letters, numbers, hyphens, and underscores', 'silver-assist-security' );
			$result['error_type']    = 'invalid_chars';
			return $result;
		}

		// Check forbidden paths using centralized logic
		$forbidden_check = self::check_forbidden_patterns( $path );
		if ( ! $forbidden_check['is_valid'] ) {
			$result['error_message'] = $forbidden_check['error_message'];
			$result['error_type']    = 'forbidden';
			return $result;
		}

		// Path is valid - leave error_message empty
		$result['is_valid']       = true;
		$result['sanitized_path'] = \sanitize_title( $original_path );

		return $result;
	}

	/**
	 * Check if path contains forbidden patterns
	 *
	 * @since 1.1.4
	 * @param string $path The path to check (should be lowercase and trimmed)
	 * @return array Result with is_valid and error_message keys
	 */
	private static function check_forbidden_patterns( string $path ): array {
		foreach ( self::$forbidden_paths as $forbidden ) {
			// Reject if:
			// 1. Exact match with forbidden word
			if ( $path === $forbidden ) {
				return array(
					'is_valid'      => false,
					'error_message' => sprintf(
						/* translators: %s: forbidden path keyword */
						\__( 'Path cannot contain "%s" for security reasons', 'silver-assist-security' ),
						$forbidden
					),
				);
			}

			// 2. Starts with forbidden word followed by separator (admin-panel)
			if ( preg_match( "/^{$forbidden}[-_]/", $path ) ) {
				return array(
					'is_valid'      => false,
					'error_message' => sprintf(
						/* translators: %s: forbidden path keyword */
						\__( 'Path cannot contain "%s" for security reasons', 'silver-assist-security' ),
						$forbidden
					),
				);
			}

			// 3. Ends with forbidden word preceded by separator, but allow any valid prefix
			if ( preg_match( "/[-_]{$forbidden}$/", $path ) ) {
				// Allow if it has any prefix (regardless of length)
				$prefix = preg_replace( "/[-_]{$forbidden}$/", '', $path );
				// Only reject if no prefix or if prefix is also forbidden
				if ( empty( $prefix ) || in_array( $prefix, self::$forbidden_paths ) ) {
					return array(
						'is_valid'      => false,
						'error_message' => sprintf(
							/* translators: %s: forbidden path keyword */
							\__( 'Path cannot contain "%s" for security reasons', 'silver-assist-security' ),
							$forbidden
						),
					);
				}
			}

			// 4. Forbidden word in the middle surrounded by separators
			if ( preg_match( "/[-_]{$forbidden}[-_]/", $path ) ) {
				return array(
					'is_valid'      => false,
					'error_message' => sprintf(
						/* translators: %s: forbidden path keyword */
						\__( 'Path cannot contain "%s" for security reasons', 'silver-assist-security' ),
						$forbidden
					),
				);
			}
		}

		return array(
			'is_valid'      => true,
			'error_message' => '',
		);
	}

	/**
	 * Simple boolean check if path is forbidden (for legacy compatibility)
	 *
	 * @since 1.1.4
	 * @param string $path The path to check
	 * @return bool True if path is forbidden, false if allowed
	 */
	public static function is_forbidden_path( string $path ): bool {
		$result = self::validate_admin_path( $path );
		return ! $result['is_valid'];
	}

	/**
	 * Get the list of forbidden paths
	 *
	 * @since 1.1.4
	 * @return array<string> List of forbidden path keywords
	 */
	public static function get_forbidden_paths(): array {
		return self::$forbidden_paths;
	}

	/**
	 * Add custom forbidden path keyword
	 *
	 * @since 1.1.4
	 * @param string $path The forbidden path to add
	 * @return void
	 */
	public static function add_forbidden_path( string $path ): void {
		$path = strtolower( trim( $path ) );
		if ( ! empty( $path ) && ! in_array( $path, self::$forbidden_paths ) ) {
			self::$forbidden_paths[] = $path;
		}
	}

	/**
	 * Remove custom forbidden path keyword
	 *
	 * @since 1.1.4
	 * @param string $path The forbidden path to remove
	 * @return void
	 */
	public static function remove_forbidden_path( string $path ): void {
		$path = strtolower( trim( $path ) );
		$key  = array_search( $path, self::$forbidden_paths );
		if ( $key !== false ) {
			unset( self::$forbidden_paths[ $key ] );
			self::$forbidden_paths = array_values( self::$forbidden_paths ); // Re-index
		}
	}
}
