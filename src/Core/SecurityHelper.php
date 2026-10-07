<?php
/**
 * Silver Assist Security Essentials - Security Helper Utilities
 *
 * Centralized helper functions for common security operations including
 * asset management, IP detection, password validation, and security logging.
 * Eliminates code duplication across security components.
 *
 * @package SilverAssist\Security\Core
 * @since 1.1.10
 * @author Silver Assist
 * @version 1.5.3
 */

namespace SilverAssist\Security\Core;

/**
 * Security Helper class
 *
 * Provides centralized utility functions for common security operations
 *
 * @since 1.1.10
 */
class SecurityHelper {

	/**
	 * Script handle of the shared HTML escaping helper (assets/js/escape-html.js).
	 *
	 * @since 1.5.4
	 */
	public const ESCAPE_HELPER_HANDLE = 'silver-assist-security-utils';

	/**
	 * Plugin URL for assets
	 *
	 * @var string
	 */
	private static string $plugin_url;

	/**
	 * Initialize SecurityHelper with plugin constants
	 *
	 * @since 1.1.10
	 * @return void
	 */
	public static function init(): void {
		self::$plugin_url = SILVER_ASSIST_SECURITY_URL;
	}
	/**
	 * Get asset URL with automatic minification support
	 *
	 * Returns minified version when SCRIPT_DEBUG is not true, regular version otherwise.
	 * This centralizes asset loading logic across all components.
	 *
	 * @since 1.1.10
	 * @param string    $asset_path The relative path to the asset (e.g., 'assets/css/admin.css').
	 * @param bool|null $force_debug Optional. Force debug mode for testing. Defaults to SCRIPT_DEBUG constant.
	 * @return string The full URL to the asset
	 */
	public static function get_asset_url( string $asset_path, ?bool $force_debug = null ): string {
		// Initialize if not already done.
		if ( ! isset( self::$plugin_url ) ) {
			self::init();
		}

		// Determine if we should use minified version
		// Allow override for testing purposes.
		if ( null !== $force_debug ) {
			$use_minified = ! $force_debug;
		} else {
			$use_minified = ! ( defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG );
		}

		if ( $use_minified ) {
			$file_info = pathinfo( $asset_path );

			// Construct minified path: assets/css/admin.css -> assets/css/admin.min.css.
			$dirname       = $file_info['dirname'] ?? '';
			$filename      = $file_info['filename']; // filename always exists.
			$extension     = $file_info['extension'] ?? '';
			$minified_path = $dirname . '/' . $filename . '.min.' . $extension;

			return self::$plugin_url . $minified_path;
		}

		// Return original path for debug mode.
		return self::$plugin_url . $asset_path;
	}

	/**
	 * Enqueue the shared HTML escaping helper used by the admin and password validation scripts
	 *
	 * Exposes `window.SilverAssistSecurityUtils` (escapeHtml, safeUrl). Safe to call from several
	 * components: WordPress ignores a handle that is already enqueued.
	 *
	 * @since 1.5.4
	 * @param string $version Script version for cache busting.
	 * @return void
	 */
	public static function enqueue_escape_helper( string $version ): void {
		\wp_enqueue_script(
			self::ESCAPE_HELPER_HANDLE,
			self::get_asset_url( 'assets/js/escape-html.js' ),
			array(),
			$version,
			true
		);
	}

	/**
	 * Get the client IP address
	 *
	 * This address is the identity behind login lockout, the IP blacklist, form protection and the
	 * REST and GraphQL rate limits, so a client must not be able to choose it by sending headers.
	 *
	 * - `REMOTE_ADDR` is the starting point and is returned as is unless it belongs to a proxy we trust.
	 * - Only `X-Forwarded-For` is honored, and only when the peer is a trusted proxy. Single-value
	 *   headers such as `Client-IP`, `CF-Connecting-IP` or `X-Real-IP` are never read: anything that
	 *   reaches the origin can set them, and a proxy we trust appends to `X-Forwarded-For` instead.
	 * - The chain is read right to left. With declared proxy CIDRs, trusted hops are discarded and the
	 *   first untrusted address is the client; with none declared, the last hop (the one the proxy
	 *   appended) is the client. A value the client placed at the left of the chain is never reached,
	 *   and a hop that cannot be validated makes the resolver fall back to the peer address.
	 *
	 * Trusted proxies are the CIDRs declared with the `SILVER_ASSIST_TRUSTED_PROXY_CIDRS` constant
	 * (comma-separated string or array) and the `silver_assist_trusted_proxy_cidrs` filter. When none
	 * are declared, a peer in a private or reserved range (an internal load balancer such as an AWS ALB)
	 * is trusted: an internet client cannot connect from such an address. Known limit: a client that
	 * can reach the origin directly from a private network (another host in the VPC, a VPN) can still
	 * choose its identity in this mode; declare the CIDRs, or return `false` from
	 * `silver_assist_trust_private_proxies` to ignore forwarded headers until you do.
	 *
	 * @since 1.1.10
	 * @since 1.5.4 Single implementation for every component; forwarded headers are trusted only from proxies.
	 * @return string Client IP address, or `0.0.0.0` when the peer address is missing or invalid.
	 */
	public static function get_client_ip(): string {
		$remote_addr = isset( $_SERVER['REMOTE_ADDR'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';

		if ( ! \filter_var( $remote_addr, \FILTER_VALIDATE_IP ) ) {
			return '0.0.0.0';
		}

		if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) && self::is_trusted_proxy( $remote_addr, true ) ) {
			$client_ip = self::extract_forwarded_client_ip( \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
			if ( '' !== $client_ip ) {
				return $client_ip;
			}
		}

		return $remote_addr;
	}

	/**
	 * Atomically increment a fixed-window rate-limit counter
	 *
	 * Uses `INSERT IGNORE` (persistent-cache path uses `wp_cache_add`) to claim the first request in a
	 * new window, guaranteeing that exactly one caller initializes the window while every other caller is
	 * routed through the atomic increment path. This closes the flood-bypass window that opens at every
	 * window boundary when initialization is done via a non-atomic read-then-write sequence. The window
	 * is fixed: accepted requests never extend it.
	 *
	 * @since 1.5.4 Moved from `RestAPISecurity` so the GraphQL limiter shares it.
	 * @param string $window_key   Transient key for the window start timestamp.
	 * @param string $count_key    Transient key for the request counter.
	 * @param int    $current_time Current Unix timestamp.
	 * @param int    $ttl          Window length in seconds.
	 * @return int Request count for this window (>= 1).
	 */
	public static function increment_rate_window( string $window_key, string $count_key, int $current_time, int $ttl ): int {
		// Persistent object cache: `wp_cache_add` is atomic across processes.
		// We claim the window by adding the *counter* key (not the window key) so
		// that any loser is guaranteed to find a valid counter to increment — no
		// gap between claim and counter-seeding for concurrent losers to slip into.
		if ( \wp_using_ext_object_cache() ) {
			if ( \wp_cache_add( $count_key, 1, '', $ttl ) ) {
				\wp_cache_set( $window_key, $current_time, '', $ttl );
				\set_transient( $count_key, 1, $ttl );
				\set_transient( $window_key, $current_time, $ttl );
				return 1;
			}

			$count = \wp_cache_incr( $count_key, 1, '' );
			if ( false !== $count ) {
				return (int) $count;
			}
			// Cache evicted the counter mid-window. Reclaim atomically so that if
			// several requests observe the miss simultaneously, only one caller
			// wins the `wp_cache_add` and returns 1; every loser is guaranteed to
			// find the reseeded counter and increment it instead of also returning 1.
			if ( \wp_cache_add( $count_key, 1, '', $ttl ) ) {
				\set_transient( $count_key, 1, $ttl );
				return 1;
			}
			$count = \wp_cache_incr( $count_key, 1, '' );
			return false === $count ? 1 : (int) $count;
		}

		// No persistent cache: rely on the UNIQUE index of `wp_options.option_name`
		// (`INSERT IGNORE`) and InnoDB row-level locking (`UPDATE ... value = value + 1`).
		global $wpdb;

		$count_option   = "_transient_{$count_key}";
		$count_timeout  = "_transient_timeout_{$count_key}";
		$window_option  = "_transient_{$window_key}";
		$window_timeout = "_transient_timeout_{$window_key}";
		$expiry         = $current_time + $ttl;

		$inserted = (int) $wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no'), (%s, %s, 'no'), (%s, %s, 'no'), (%s, %s, 'no')",
				$window_option,
				(string) $current_time,
				$window_timeout,
				(string) $expiry,
				$count_option,
				'1',
				$count_timeout,
				(string) $expiry
			)
		);

		if ( $inserted > 0 ) {
			// We won the claim (at least one row was newly inserted).
			return 1;
		}

		// Rows already exist. Detect an expired window: WordPress does not sweep
		// `_transient_timeout_*` rows unless someone reads the transient, but we hit
		// the options table directly, so we must expire and reset the window ourselves.
		// The count_timeout row doubles as the atomic reset lock: exactly one caller
		// transitions its value from "<= now" to the new expiry via the WHERE clause.
		$reset_won = (int) $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s AND CAST(option_value AS UNSIGNED) <= %d",
				(string) $expiry,
				$count_timeout,
				$current_time
			)
		);
		if ( 1 === $reset_won ) {
			$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s", (string) $current_time, $window_option ) );
			$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s", (string) $expiry, $window_timeout ) );
			$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->options} SET option_value = %s WHERE option_name = %s", '1', $count_option ) );
			return 1;
		}

		// Window is still active (or another caller just reset it) — atomically increment.
		$updated = (int) $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->options} SET option_value = CAST(option_value AS UNSIGNED) + 1 WHERE option_name = %s",
				$count_option
			)
		);

		if ( 1 === $updated ) {
			return (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT option_value FROM {$wpdb->options} WHERE option_name = %s",
					$count_option
				)
			);
		}

		// Row vanished (transient GC between claim and increment) — reseed.
		\set_transient( $window_key, $current_time, $ttl );
		\set_transient( $count_key, 1, $ttl );
		return 1;
	}

	/**
	 * Get the trusted proxy CIDRs declared by the site
	 *
	 * Merges the `SILVER_ASSIST_TRUSTED_PROXY_CIDRS` constant (comma-separated string or array) and
	 * the `silver_assist_trusted_proxy_cidrs` filter.
	 *
	 * @since 1.5.4
	 * @return string[] Declared CIDRs; empty when the site declares none.
	 */
	private static function get_trusted_proxy_cidrs(): array {
		$configured = array();

		if ( \defined( 'SILVER_ASSIST_TRUSTED_PROXY_CIDRS' ) ) {
			$raw = \constant( 'SILVER_ASSIST_TRUSTED_PROXY_CIDRS' );
			if ( \is_string( $raw ) ) {
				$configured = \array_values( \array_filter( \array_map( 'trim', \explode( ',', $raw ) ) ) );
			} elseif ( \is_array( $raw ) ) {
				$configured = \array_values( \array_filter( \array_map( 'strval', $raw ) ) );
			}
		}

		/**
		 * Filters the list of trusted proxy CIDRs.
		 *
		 * @since 1.5.0
		 * @param string[] $configured CIDRs already collected from `SILVER_ASSIST_TRUSTED_PROXY_CIDRS`.
		 */
		$trusted = \apply_filters( 'silver_assist_trusted_proxy_cidrs', $configured );

		return \array_values( \array_filter( \array_map( 'strval', (array) $trusted ) ) );
	}

	/**
	 * Check whether an address is a proxy whose forwarded headers can be trusted
	 *
	 * With declared CIDRs, both the peer and the hops in the chain are matched against them. With none
	 * declared, only the **peer** can be trusted, and only when it is in a private or reserved range;
	 * hops are never skipped in that mode, because a private hop may be the real client (VPN, office
	 * network) and stepping over it would reach values the client chose.
	 *
	 * @since 1.5.4
	 * @param string $ip      Address to check.
	 * @param bool   $is_peer True when checking `REMOTE_ADDR`, false for a hop from `X-Forwarded-For`.
	 * @return bool True when trusted.
	 */
	private static function is_trusted_proxy( string $ip, bool $is_peer = false ): bool {
		$cidrs = self::get_trusted_proxy_cidrs();

		if ( ! empty( $cidrs ) ) {
			return self::is_ip_in_range( $ip, $cidrs );
		}

		if ( ! $is_peer ) {
			return false;
		}

		/**
		 * Filters whether a peer in a private or reserved range is trusted when no CIDRs are declared.
		 *
		 * @since 1.5.4
		 * @param bool $trust Default true.
		 */
		if ( ! \apply_filters( 'silver_assist_trust_private_proxies', true ) ) {
			return false;
		}

		return \filter_var( $ip, \FILTER_VALIDATE_IP ) && ! \filter_var( $ip, \FILTER_VALIDATE_IP, \FILTER_FLAG_NO_PRIV_RANGE | \FILTER_FLAG_NO_RES_RANGE );
	}

	/**
	 * Extract the real client IP from an `X-Forwarded-For` chain
	 *
	 * Walks the chain right to left, discarding hops that are declared trusted proxies. The first
	 * remaining address is the client. A hop that cannot be validated stops the walk and the caller
	 * falls back to the peer: skipping it would reach values the client placed at the left.
	 *
	 * @since 1.5.4
	 * @param string $header Raw `X-Forwarded-For` header value.
	 * @return string The client IP, or an empty string when it cannot be determined safely.
	 */
	private static function extract_forwarded_client_ip( string $header ): string {
		$hops = \array_values(
			\array_filter(
				\array_map( 'trim', \explode( ',', $header ) ),
				static fn( string $hop ): bool => '' !== $hop
			)
		);

		for ( $i = \count( $hops ) - 1; $i >= 0; $i-- ) {
			$hop = self::normalize_forwarded_address( $hops[ $i ] );
			if ( '' === $hop ) {
				return '';
			}
			if ( self::is_trusted_proxy( $hop ) ) {
				continue;
			}
			return $hop;
		}

		return '';
	}

	/**
	 * Normalize one `X-Forwarded-For` entry to a bare IP address
	 *
	 * Accepts a plain IPv4 or IPv6 address and the explicit port forms some proxies append
	 * (`203.0.113.7:54321`, `[2001:db8::1]:443`, `[2001:db8::1]`).
	 *
	 * @since 1.5.4
	 * @param string $hop Entry from the header.
	 * @return string Valid IP address, or an empty string.
	 */
	private static function normalize_forwarded_address( string $hop ): string {
		if ( \preg_match( '/^\[([0-9a-fA-F:.]+)\](?::\d{1,5})?$/', $hop, $matches ) ) {
			$hop = $matches[1];
		} elseif ( \preg_match( '/^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/', $hop, $matches ) ) {
			$hop = $matches[1];
		}

		return \filter_var( $hop, \FILTER_VALIDATE_IP ) ? $hop : '';
	}


	/**
	 * Send 404 Not Found response with security-focused headers
	 *
	 * Sends a proper 404 response to hide sensitive endpoints from bots,
	 * crawlers, and security scanners. Includes anti-indexing headers.
	 *
	 * @since 1.1.10
	 * @param bool $use_wordpress_template Whether to try loading WordPress 404 template.
	 * @return void
	 */
	public static function send_404_response( bool $use_wordpress_template = true ): void {
		// Send proper 404 headers.
		\status_header( 404 );
		\nocache_headers();

		// Additional security headers.
		header( 'X-Robots-Tag: noindex, nofollow, noarchive, nosnippet, noimageindex', true );

		if ( $use_wordpress_template ) {
			// Try to load WordPress 404 template for better integration.
			$template_404 = \get_404_template();
			if ( $template_404 ) {
				include $template_404;
				exit;
			}
		}

		// Fallback minimal 404 response.
		echo '<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
    <meta name="robots" content="noindex,nofollow,noarchive,nosnippet,noimageindex">
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
    <h1>Not Found</h1>
    <p>The requested URL was not found on this server.</p>
</body>
</html>';

		exit;
	}

	/**
	 * Check if password meets strong password requirements
	 *
	 * Validates password strength according to security best practices:
	 * - Minimum 8 characters
	 * - Contains uppercase letter
	 * - Contains lowercase letter
	 * - Contains number
	 * - Contains special character
	 *
	 * @since 1.1.10
	 * @param string $password Password to validate.
	 * @return bool True if password is strong
	 */
	public static function is_strong_password( string $password ): bool {
		// At least 8 characters.
		if ( strlen( $password ) < 8 ) {
			return false;
		}

		// Must contain uppercase letter.
		if ( ! preg_match( '/[A-Z]/', $password ) ) {
			return false;
		}

		// Must contain lowercase letter.
		if ( ! preg_match( '/[a-z]/', $password ) ) {
			return false;
		}

		// Must contain number.
		if ( ! preg_match( '/[0-9]/', $password ) ) {
			return false;
		}

		// Must contain special character.
		if ( ! preg_match( '/[^A-Za-z0-9]/', $password ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Log severity levels
	 *
	 * @since 1.1.15
	 */
	public const LOG_ERROR   = 'error';
	public const LOG_WARNING = 'warning';
	public const LOG_INFO    = 'info';

	/**
	 * Event types classified as errors (always logged when WP_DEBUG is on)
	 *
	 * @since 1.1.15
	 * @var array<string>
	 */
	private static array $error_events = array(
		'AJAX_ERROR',
		'UPDATE_CHECK_ERROR',
		'MANUAL_IP_BLOCK_ERROR',
		'MANUAL_IP_UNBLOCK_ERROR',
		'BOT_COUNT_ERROR',
		'SECURITY_LOGS_ERROR',
		'LOG_PARSE_ERROR',
		'IP_CLEANUP_ERROR',
		'SETTINGS_HUB_ERROR',
		'PLUGIN_INIT_ERROR',
		'GRAPHQL_DEPTH_ERROR',
		'GRAPHQL_ALIAS_ERROR',
		'GRAPHQL_DIRECTIVE_ERROR',
		'GRAPHQL_FIELD_DUPLICATE_ERROR',
		'GRAPHQL_TIMEOUT_ERROR',
		'ADMIN_PATH_VALIDATION_ERROR',
	);

	/**
	 * Event types classified as warnings (security events: blocks, violations, failures)
	 *
	 * @since 1.1.15
	 * @var array<string>
	 */
	private static array $warning_events = array(
		'LOGIN_LOCKOUT',
		'BOT_BLOCKED',
		'IP_BLACKLISTED',
		'IP_AUTO_BLACKLISTED',
		'NONCE_VALIDATION_FAILED',
		'NONCE_VERIFICATION_FAILED',
		'CAPABILITY_CHECK_FAILED',
		'AJAX_INVALID_METHOD',
		'SECURITY_VIOLATION_RECORDED',
		'ADMIN_PATH_VALIDATION_FAILED',
		'FORM_SPAM_BLOCKED',
		'SQL_INJECTION_DETECTED',
		'SPAM_PATTERN_DETECTED',
		'EXCESSIVE_CAPS_DETECTED',
		'CF7_IP_BLACKLISTED',
		'CF7_BLOCKED_BLACKLISTED_IP',
		'CF7_BLOCKED_HONEYPOT',
		'CF7_BLOCKED_TOO_FAST',
		'CF7_BLOCKED_RATE_LIMIT',
		'CF7_BLOCKED_OBSOLETE_BROWSER',
		'CF7_BLOCKED_SQL_INJECTION',
		'CF7_BLOCKED_SPAM_PATTERN',
		'CF7_SPAM_DETECTED',
		'GRAPHQL_DEPTH_EXCEEDED',
		'GRAPHQL_SUSPICIOUS_QUERY',
		'GRAPHQL_ALIAS_ABUSE',
		'GRAPHQL_DIRECTIVE_ABUSE',
		'GRAPHQL_FIELD_DUPLICATION',
		'GRAPHQL_QUERY_TIMEOUT',
	);

	/**
	 * Determine the severity level for a given event type
	 *
	 * @since 1.1.15
	 * @param string $event_type The event type identifier.
	 * @return string One of LOG_ERROR, LOG_WARNING, or LOG_INFO.
	 */
	private static function get_event_severity( string $event_type ): string {
		if ( in_array( $event_type, self::$error_events, true ) ) {
			return self::LOG_ERROR;
		}
		if ( in_array( $event_type, self::$warning_events, true ) ) {
			return self::LOG_WARNING;
		}
		return self::LOG_INFO;
	}

	/**
	 * Check if the current environment is a test environment
	 *
	 * @since 1.1.15
	 * @return bool
	 */
	private static function is_test_environment(): bool {
		return defined( 'WP_TESTS_DOMAIN' ) || defined( 'WP_RUN_CORE_TESTS' ) || ( defined( 'PHPUNIT_COMPOSER_INSTALL' ) );
	}

	/**
	 * Log security event with structured format
	 *
	 * Creates standardized security log entries with timestamp, IP,
	 * user agent, and context information for security monitoring.
	 *
	 * Logging behavior:
	 * - Only logs when WP_DEBUG is enabled (production stays silent).
	 * - In test environments, only error-level events are logged.
	 * - In development, all severity levels are logged.
	 *
	 * @since 1.1.10
	 * @param string $event_type Type of security event (e.g., 'LOGIN_FAILED', 'BOT_BLOCKED').
	 * @param string $message Human-readable event description.
	 * @param array  $context Additional context data (optional).
	 * @return void
	 */
	public static function log_security_event( string $event_type, string $message, array $context = array() ): void {
		/**
		 * Fires for every security event, before the WP_DEBUG and test environment gates below.
		 *
		 * Observation only: it does not change what is written to the log. Tests use it to assert an
		 * event was raised, since under PHPUnit only errors are written.
		 *
		 * @since 1.5.4
		 * @param string $event_type Type of security event.
		 * @param string $message    Human-readable event description.
		 * @param array  $context    Additional context data.
		 */
		\do_action( 'silver_assist_security_event', $event_type, $message, $context );

		// Only log when WP_DEBUG is enabled.
		if ( ! defined( 'WP_DEBUG' ) || ! WP_DEBUG ) {
			return;
		}

		$severity = self::get_event_severity( $event_type );

		// In test environments, only log errors to keep output clean.
		if ( self::is_test_environment() && self::LOG_ERROR !== $severity ) {
			return;
		}

		$log_data = array(
			'event_type'  => $event_type,
			'message'     => $message,
			'timestamp'   => \current_time( 'mysql' ),
			'ip'          => self::get_client_ip(),
			'user_agent'  => isset( $_SERVER['HTTP_USER_AGENT'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : 'Unknown',
			'request_uri' => isset( $_SERVER['REQUEST_URI'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
			'context'     => $context,
		);

		// Log as structured JSON for better parsing.
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Intentional security logging.
		error_log(
			sprintf(
				'SILVER_ASSIST_SECURITY: [%s] %s - %s',
				strtoupper( $severity ),
				$event_type,
				\wp_json_encode( $log_data, JSON_UNESCAPED_SLASHES )
			)
		);
	}

	/**
	 * Format time duration in human-readable format
	 *
	 * Converts seconds to human-readable time format (e.g., "5 minutes", "1 hour").
	 * Useful for displaying lockout durations and timeouts.
	 *
	 * @since 1.1.10
	 * @param int $seconds Duration in seconds.
	 * @return string Human-readable time format
	 */
	public static function format_time_duration( int $seconds ): string {
		if ( $seconds < 60 ) {
			return sprintf(
			/* translators: %d: number of seconds */
				\__( '%d seconds', 'silver-assist-security' ),
				$seconds
			);
		}

		$minutes = round( $seconds / 60 );
		if ( $minutes < 60 ) {
			return sprintf(
			/* translators: %d: number of minutes */
				\__( '%d minutes', 'silver-assist-security' ),
				$minutes
			);
		}

		$hours = round( $minutes / 60 );
		return sprintf(
		/* translators: %d: number of hours */
			\__( '%d hours', 'silver-assist-security' ),
			$hours
		);
	}

	/**
	 * Validate WordPress nonce with enhanced error handling
	 *
	 * Centralized nonce validation with proper error responses
	 * and security logging for failed attempts.
	 *
	 * @since 1.1.10
	 * @param string $nonce Nonce value to verify.
	 * @param string $action Nonce action name.
	 * @param bool   $die_on_failure Whether to wp_die() on failure.
	 * @return bool True if nonce is valid
	 */
	public static function verify_nonce( string $nonce, string $action, bool $die_on_failure = true ): bool {
		if ( ! \wp_verify_nonce( $nonce, $action ) ) {
			self::log_security_event(
				'NONCE_VALIDATION_FAILED',
				"Invalid nonce for action: {$action}",
				array(
					'action' => $action,
					'nonce'  => $nonce,
				)
			);

			if ( $die_on_failure ) {
					\wp_die( \esc_html__( 'Security check failed.', 'silver-assist-security' ) );
			}

			return false;
		}

		return true;
	}

	/**
	 * Check if user has required capability with security logging
	 *
	 * Centralized capability checking with security event logging
	 * for unauthorized access attempts.
	 *
	 * @since 1.1.10
	 * @param string $capability Required capability.
	 * @param bool   $die_on_failure Whether to wp_die() on failure.
	 * @return bool True if user has capability
	 */
	public static function check_user_capability( string $capability, bool $die_on_failure = true ): bool {
		if ( ! \current_user_can( $capability ) ) {
			$user_id = \get_current_user_id();
			$user    = $user_id ? \get_userdata( $user_id ) : null;

			self::log_security_event(
				'CAPABILITY_CHECK_FAILED',
				"User lacks required capability: {$capability}",
				array(
					'required_capability' => $capability,
					'user_id'             => $user_id,
					'user_login'          => $user ? $user->user_login : 'anonymous',
				)
			);

			if ( $die_on_failure ) {
					\wp_die( \esc_html__( 'You do not have sufficient permissions to access this page.', 'silver-assist-security' ) );
			}

			return false;
		}

		return true;
	}

	/**
	 * Reduce an IP address to the identity the limiters count
	 *
	 * An IPv4 address is its own identity. An IPv6 subscriber usually controls a whole /64 (or more), so
	 * keying on the exact address would hand an attacker 2^64 identities and make every limiter
	 * worthless. IPv6 addresses are therefore reduced to their network prefix, `/64` by default. An
	 * IPv4-mapped address (`::ffff:203.0.113.5`) is treated as the IPv4 address it carries.
	 *
	 * The prefix length is filterable with `silver_assist_security_ipv6_prefix_length`; 128 (or more)
	 * keeps the exact address. The value is only used to build limiter keys, displays keep the full IP.
	 *
	 * @since 1.5.4
	 * @param string $ip IP address.
	 * @return string The IPv4 address, `{network}/{prefix}` for IPv6, or the input when it is not an IP.
	 */
	public static function normalize_ip_for_limits( string $ip ): string {
		$packed = \filter_var( $ip, \FILTER_VALIDATE_IP ) ? \inet_pton( $ip ) : false;

		if ( false === $packed || 16 !== \strlen( $packed ) ) {
			return $ip;
		}

		// IPv4-mapped IPv6 address: ten zero bytes, then 0xffff, then the IPv4 address.
		if ( \str_repeat( \chr( 0 ), 10 ) . \str_repeat( \chr( 255 ), 2 ) === \substr( $packed, 0, 12 ) ) {
			return (string) \inet_ntop( \substr( $packed, 12 ) );
		}

		/**
		 * Filters the IPv6 prefix length the limiters group addresses by.
		 *
		 * @since 1.5.4
		 * @param int $prefix_length Prefix length in bits, 64 by default. 128 disables grouping.
		 */
		$prefix = (int) \apply_filters( 'silver_assist_security_ipv6_prefix_length', 64 );
		if ( $prefix < 1 ) {
			$prefix = 64;
		}
		$prefix = \min( $prefix, 128 );

		if ( 128 === $prefix ) {
			return (string) \inet_ntop( $packed );
		}

		$mask = \str_repeat( \chr( 255 ), \intdiv( $prefix, 8 ) );
		if ( 0 !== $prefix % 8 ) {
			$mask .= \chr( ( 255 << ( 8 - $prefix % 8 ) ) & 255 );
		}
		$mask = \str_pad( $mask, 16, \chr( 0 ) );

		return \inet_ntop( $packed & $mask ) . '/' . $prefix;
	}

	/**
	 * Hash that identifies an IP in limiter keys
	 *
	 * @since 1.5.4
	 * @param string $ip IP address.
	 * @return string MD5 of the normalized identity (see normalize_ip_for_limits()).
	 */
	public static function get_ip_key_hash( string $ip ): string {
		return md5( self::normalize_ip_for_limits( $ip ) );
	}

	/**
	 * Generate secure transient key for IP-based tracking
	 *
	 * Creates consistent, secure keys for IP-based transient storage
	 * used in rate limiting, lockouts, and tracking. IPv6 addresses share the
	 * key of their network prefix (see normalize_ip_for_limits()).
	 *
	 * @since 1.1.10
	 * @param string      $prefix Key prefix (e.g., 'login_attempts', 'lockout').
	 * @param string|null $ip IP address (uses current IP if null).
	 * @return string Secure transient key
	 */
	public static function generate_ip_transient_key( string $prefix, ?string $ip = null ): string {
		if ( null === $ip ) {
			$ip = self::get_client_ip();
		}

		return "{$prefix}_" . self::get_ip_key_hash( $ip );
	}

	/**
	 * Sanitize and validate admin path input
	 *
	 * Centralized path sanitization for admin hide functionality
	 * with proper validation and security checks.
	 *
	 * @since 1.1.10
	 * @param string $path Path to sanitize.
	 * @return string Sanitized path
	 */
	public static function sanitize_admin_path( string $path ): string {
		// Remove any potentially dangerous characters.
		$path = \sanitize_title( $path );

		// Ensure minimum length.
		if ( strlen( $path ) < 3 ) {
			$path = 'silver-admin';
		}

		// Ensure maximum length.
		if ( strlen( $path ) > 50 ) {
			$path = substr( $path, 0, 50 );
		}

		return $path;
	}

	/**
	 * Check if current request is from a known bot or crawler
	 *
	 * Analyzes user agent and request patterns to identify automated
	 * tools, security scanners, and malicious bots.
	 *
	 * @since 1.1.10
	 * @param string|null $user_agent User agent string (uses current if null).
	 * @return bool True if request appears to be from a bot
	 */
	public static function is_bot_request( ?string $user_agent = null ): bool {
		if ( null === $user_agent ) {
			$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		}

		if ( self::matches_bot_user_agent( $user_agent ) ) {
			return true;
		}

		// Additional bot detection patterns.
		if ( empty( $user_agent ) || strlen( $user_agent ) < 10 ) {
			return true;
		}

		// Check for missing common browser headers.
		if (
		! isset( $_SERVER['HTTP_ACCEPT'] ) &&
		! isset( $_SERVER['HTTP_ACCEPT_LANGUAGE'] ) &&
		! isset( $_SERVER['HTTP_ACCEPT_ENCODING'] )
		) {
			return true;
		}

		return false;
	}

	/**
	 * Whether a User-Agent string names a known bot, crawler, scanner or scripting client
	 *
	 * Short words are matched as whole words, not as substrings, so a phone brand such as CUBOT or a
	 * device model that merely contains `bot`, `scan`, `php` or `java` is not treated as a bot, while
	 * `Googlebot`, `AhrefsBot`, `python-requests`, `Java/17`, `PHP/8.2` and `libwww-perl` still are.
	 *
	 * @since 1.5.4
	 * @param string $user_agent User-Agent string.
	 * @return bool
	 */
	public static function matches_bot_user_agent( string $user_agent ): bool {
		// Device brands whose name ends in "bot" (CUBOT phones).
		$user_agent = \str_ireplace( 'cubot', '', $user_agent );

		// Standalone or suffixed `bot`, crawler words, scanner and scripting-client names, `Java/17` (not `JavaScript`), scanner tools.
		$patterns = array(
			'/(?:^|[^a-z])bot(?:[^a-z]|$)|[a-z]bot\b/i',
			'/crawler|spider|scraper/i',
			'/\b(?:scan|scanner|probe|wget|curl|python|php|perl|ruby)\b/i',
			'/\bjava(?:\/|\s|$)/i',
			'/masscan|nmap|nikto|sqlmap|gobuster|dirb|wpscan|nuclei|httpx/i',
		);

		foreach ( $patterns as $pattern ) {
			if ( 1 === \preg_match( $pattern, $user_agent ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Validate AJAX request with comprehensive security checks
	 *
	 * Performs complete AJAX request validation including nonce verification,
	 * capability checks, and request method validation.
	 *
	 * @since 1.1.10
	 * @param string $nonce_action Nonce action name.
	 * @param string $required_capability Required user capability.
	 * @param string $allowed_method Allowed HTTP method (default: POST).
	 * @return bool True if request is valid
	 */
	public static function validate_ajax_request(
		string $nonce_action,
		string $required_capability = 'manage_options',
		string $allowed_method = 'POST'
	): bool {
		// Check HTTP method.
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || $_SERVER['REQUEST_METHOD'] !== $allowed_method ) {
			$actual_method = isset( $_SERVER['REQUEST_METHOD'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'Unknown';
			self::log_security_event(
				'AJAX_INVALID_METHOD',
				'Invalid HTTP method for AJAX request',
				array(
					'expected' => $allowed_method,
					'actual'   => $actual_method,
				)
			);
			return false;
		}

		// Verify nonce.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing, WordPress.Security.NonceVerification.Recommended -- Nonce is validated right below.
		$nonce = isset( $_POST['nonce'] ) ? \sanitize_text_field( \wp_unslash( $_POST['nonce'] ) ) : ( isset( $_GET['nonce'] ) ? \sanitize_text_field( \wp_unslash( $_GET['nonce'] ) ) : '' );
		if ( ! self::verify_nonce( $nonce, $nonce_action, false ) ) {
			return false;
		}

		// Check user capability.
		if ( ! self::check_user_capability( $required_capability, false ) ) {
			return false;
		}

		return true;
	}

	/**
	 * Check if Contact Form 7 plugin is active and available
	 *
	 * Detects Contact Form 7 plugin activation by checking for the main class
	 * and version compatibility.
	 *
	 * @since 1.1.15
	 * @return bool True if CF7 is active and compatible, false otherwise
	 */
	public static function is_contact_form_7_active(): bool {
		// Check if Contact Form 7 main class exists.
		if ( ! \class_exists( 'WPCF7' ) ) {
			return false;
		}

		// Check minimum version requirement (CF7 5.0+).
		if ( \defined( 'WPCF7_VERSION' ) ) {
			return \version_compare( WPCF7_VERSION, '5.0', '>=' );
		}

		// If version constant not defined but class exists, assume it's compatible.
		return true;
	}

	/**
	 * Get Contact Form 7 plugin information
	 *
	 * Returns detailed information about the installed CF7 plugin
	 * for admin display and logging purposes.
	 *
	 * @since 1.1.15
	 * @return array CF7 plugin information
	 */
	/**
	 * Render a plugin template with the given variables.
	 *
	 * Loads a PHP template from the `templates/` directory, extracts the
	 * supplied data array into local variables, and returns the rendered HTML.
	 * Variables are scoped to the template — the caller's scope is not polluted.
	 *
	 * @since 1.1.15
	 * @param string               $template Filename inside `templates/` (e.g. 'captcha-field.php').
	 * @param array<string, mixed> $data     Key-value pairs available inside the template.
	 * @return string Rendered HTML.
	 */
	public static function render_template( string $template, array $data = array() ): string {
		// Prevent path traversal — only allow simple filenames.
		if ( basename( $template ) !== $template || strpos( $template, '..' ) !== false ) {
			return '';
		}

		$file = SILVER_ASSIST_SECURITY_PATH . 'templates/' . $template;

		if ( ! file_exists( $file ) ) {
			return '';
		}

		// phpcs:ignore WordPress.PHP.DontExtract.extract_extract -- Intentional: scoped variable extraction for template rendering.
		extract( $data, EXTR_SKIP );

		ob_start();
		include $file;
		return (string) ob_get_clean();
	}

	/**
	 * Get Contact Form 7 plugin status and version info
	 *
	 * @since 1.1.15
	 * @return array{active: bool, version: ?string, compatible?: bool, message: string}
	 */
	public static function get_contact_form_7_info(): array {
		if ( ! self::is_contact_form_7_active() ) {
			return array(
				'active'  => false,
				'version' => null,
				'message' => \__( 'Contact Form 7 plugin is not active', 'silver-assist-security' ),
			);
		}

		$version       = \defined( 'WPCF7_VERSION' ) ? WPCF7_VERSION : 'Unknown';
		$is_compatible = \version_compare( $version, '5.0', '>=' );

		return array(
			'active'     => true,
			'version'    => $version,
			'compatible' => $is_compatible,
			'message'    => $is_compatible
				? sprintf(
					/* translators: %s: Contact Form 7 version */
					\__( 'Contact Form 7 v%s is active and compatible', 'silver-assist-security' ),
					$version
				)
				: sprintf(
					/* translators: %s: Contact Form 7 version */
					\__( 'Contact Form 7 v%s detected but requires v5.0 or higher', 'silver-assist-security' ),
					$version
				),
		);
	}

	/**
	 * Check if IP is within CIDR ranges
	 *
	 * @since 1.5.0
	 * @param string $ip    The IP address to check.
	 * @param array  $cidrs Array of CIDR ranges to check against.
	 * @return bool True if IP is in range, false otherwise
	 */
	private static function is_ip_in_range( string $ip, array $cidrs ): bool {
		if ( ! \filter_var( $ip, \FILTER_VALIDATE_IP ) ) {
			return false;
		}

		foreach ( $cidrs as $cidr ) {
			if ( self::is_ip_in_cidr( $ip, $cidr ) ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Check if IP is within a specific CIDR range
	 *
	 * @since 1.5.0
	 * @param string $ip   The IP address to check.
	 * @param string $cidr The CIDR range (e.g., "192.168.1.0/24").
	 * @return bool True if IP is in range, false otherwise
	 */
	private static function is_ip_in_cidr( string $ip, string $cidr ): bool {
		// Handle IPv6.
		if ( \filter_var( $ip, \FILTER_VALIDATE_IP, \FILTER_FLAG_IPV6 ) ) {
			return self::is_ipv6_in_cidr( $ip, $cidr );
		}

		// Handle IPv4.
		if ( ! \strpos( $cidr, '/' ) ) {
			return $ip === $cidr;
		}

		$parts = \explode( '/', $cidr );

		// Reject CIDRs that contain extra slashes (e.g. "192.0.2.0/0/typo") so a
		// stray path component cannot be dropped and silently trust every address.
		if ( 2 !== \count( $parts ) ) {
			return false;
		}
		list( $subnet, $bits ) = $parts;

		// Reject non-numeric or out-of-range prefixes so a typo like "/foo" or "/99" cannot silently trust every IPv4.
		if ( ! \ctype_digit( $bits ) ) {
			return false;
		}
		$bits = (int) $bits;
		if ( $bits < 0 || $bits > 32 ) {
			return false;
		}

		$ip_long     = \ip2long( $ip );
		$subnet_long = \ip2long( $subnet );

		if ( false === $ip_long || false === $subnet_long ) {
			return false;
		}

		if ( 0 === $bits ) {
			return true;
		}

		$mask         = -1 << ( 32 - $bits );
		$subnet_long &= $mask;
		$ip_long     &= $mask;

		return $ip_long === $subnet_long;
	}

	/**
	 * Check if IPv6 is within CIDR range
	 *
	 * @since 1.5.0
	 * @param string $ip   The IPv6 address to check.
	 * @param string $cidr The IPv6 CIDR range.
	 * @return bool True if IP is in range, false otherwise
	 */
	private static function is_ipv6_in_cidr( string $ip, string $cidr ): bool {
		if ( ! \strpos( $cidr, '/' ) ) {
			return $ip === $cidr;
		}

		$parts = \explode( '/', $cidr );

		// Reject CIDRs with extra slashes (e.g. "2001:db8::/0/typo") so a stray
		// path component cannot be dropped and silently trust every IPv6 sender.
		if ( 2 !== \count( $parts ) ) {
			return false;
		}
		list( $subnet, $bits ) = $parts;

		// Reject non-numeric or out-of-range prefixes so a typo like "/foo" or "/200" cannot trust every IPv6 or raise a ValueError in str_repeat().
		if ( ! \ctype_digit( $bits ) ) {
			return false;
		}
		$bits = (int) $bits;
		if ( $bits < 0 || $bits > 128 ) {
			return false;
		}

		// Convert to binary representation.
		$ip_bin     = \inet_pton( $ip );
		$subnet_bin = \inet_pton( $subnet );

		if ( false === $ip_bin || false === $subnet_bin ) {
			return false;
		}

		// Create bitmask: calculate bytes and remainder bits.
		$bytes          = (int) ( $bits / 8 );       // Full bytes.
		$remainder_bits = $bits % 8;        // Remaining bits in last byte.

		$mask = \str_repeat( \chr( 255 ), $bytes );
		if ( $remainder_bits > 0 ) {
			// High-bit mask formula: 255 << (8 - remainder_bits).
			$mask .= \chr( 255 << ( 8 - $remainder_bits ) );
		}
		$mask .= \str_repeat( \chr( 0 ), 16 - \strlen( $mask ) );

		return ( $ip_bin & $mask ) === ( $subnet_bin & $mask );
	}
}
