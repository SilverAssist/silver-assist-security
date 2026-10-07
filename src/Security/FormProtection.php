<?php
/**
 * Silver Assist Security Essentials - Form Protection
 *
 * Provides comprehensive protection for all forms on the site including
 * rate limiting, obsolete browser detection, and SQL injection detection.
 *
 * @package SilverAssist\Security\Security
 * @since 1.1.15
 * @author Silver Assist
 * @version 1.5.4
 */

namespace SilverAssist\Security\Security;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * Form Protection class
 *
 * Handles protection for all form submissions across the site
 *
 * @since 1.1.15
 */
class FormProtection {

	/**
	 * Constructor
	 *
	 * @since 1.1.15
	 */
	public function __construct() {
		// Initialize if needed.
	}

	/**
	 * Check if form submission is allowed for given IP
	 *
	 * Implements rate limiting to prevent spam submissions. The limit and window are the
	 * `silver_assist_cf7_rate_limit` and `silver_assist_cf7_rate_window` options saved on the
	 * Form Protection tab (formerly read from `silver_assist_form_rate_*`, which no screen saved).
	 *
	 * @since 1.1.15
	 * @since 1.5.4 Reads the options the settings screen saves; uses the atomic fixed-window counter.
	 * @param string $ip The client IP address.
	 * @return bool True if submission is allowed, false if rate limited
	 */
	public function allow_form_submission( string $ip ): bool {
		$rate_limit  = $this->get_rate_limit();
		$rate_window = $this->get_rate_window();

		// Atomic fixed-window counter shared with the login, REST and GraphQL limiters: concurrent
		// submissions each get their own count, so they cannot overwrite each other and slip past the limit.
		// Every attempt counts, blocked ones included; the window is fixed and never extended.
		$submissions = SecurityHelper::increment_rate_window(
			SecurityHelper::generate_ip_transient_key( 'form_rate_window', $ip ),
			SecurityHelper::generate_ip_transient_key( 'form_rate', $ip ),
			time(),
			$rate_window
		);

		if ( $submissions > $rate_limit ) {
			SecurityHelper::log_security_event(
				'FORM_SPAM_BLOCKED',
				'Form submission rate limit exceeded',
				array(
					'ip'          => $ip,
					'submissions' => $submissions - 1,
					'limit'       => $rate_limit,
				)
			);
			return false;
		}

		return true;
	}

	/**
	 * Detect obsolete browsers and suspicious User-Agents
	 *
	 * Identifies old browsers, bots, and suspicious patterns that are
	 * commonly used in automated attacks.
	 *
	 * @since 1.1.15
	 * @param string $user_agent User agent string to analyze.
	 * @return bool True if browser appears obsolete or suspicious
	 */
	public static function is_obsolete_browser( string $user_agent ): bool {
		// Empty or very short user agents are suspicious.
		if ( empty( $user_agent ) || strlen( $user_agent ) < 10 ) {
			return true;
		}

		// Patterns for obsolete browsers and suspicious agents.
		$obsolete_patterns = array(
			'MSIE 6.0',
			'MSIE 7.0',
			'MSIE 8.0',
			'MSIE 9.0',
			'Mozilla/4.0',
			'Mozilla/3.0',
			'Mozilla/2.0',
			'Windows NT 5.1',
			'Windows NT 5.0',
			'Windows 98',
			'360SE',
			'QQBrowser',
			'Baidu',
			'SogouWeb',
			'compatible; MSIE', // General old IE pattern.
		);

		foreach ( $obsolete_patterns as $pattern ) {
			if ( stripos( $user_agent, $pattern ) !== false ) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Detect SQL injection attempts in request data
	 *
	 * Analyzes both GET and POST data for common SQL injection patterns.
	 *
	 * @since 1.1.15
	 * @return bool True if SQL injection attempt detected
	 */
	public static function has_sql_injection_attempt(): bool {
		// Get all request data.
		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Read-only attack-signature scan; must inspect raw request data (including requests with no/invalid nonce) to detect SQL injection attempts.
		$query_string = $_SERVER['QUERY_STRING'] ?? '';
		$post_data    = http_build_query( $_POST );
		// phpcs:enable WordPress.Security.NonceVerification.Missing
		$full_data = $query_string . '&' . $post_data;

		// Decode URL encoding to catch encoded attacks.
		$full_data = urldecode( $full_data );

		// Common SQL injection patterns.
		$sql_patterns = array(
			'PG_SLEEP',
			'SLEEP(',
			'WAITFOR DELAY',
			'UNION SELECT',
			'DROP TABLE',
			'DELETE FROM',
			'INSERT INTO',
			'UPDATE SET',
			'CREATE TABLE',
			'ALTER TABLE',
			'EXEC(',
			'EXECUTE(',
			'OR 1=1',
			'AND 1=1',
			'OR 128=128',
			'CONCAT(',
			'CHAR(',
			'ASCII(',
			'BENCHMARK(',
			'LOAD_FILE(',
			'INTO OUTFILE',
			'xp_cmdshell',
			'sp_executesql',
			"'; DROP",
			'\' OR \'',
			'" OR "',
		);

		// Comment markers only count right after a quote (the classic way to cut off the
		// rest of a query). A bare "--" or "/*" is ordinary text: a dash in a message.
		$comment_pattern = '/[\'"`]\s*(?:--|\/\*)/';

		/**
		 * Filters the SQL injection signatures scanned for in form submissions.
		 *
		 * @since 1.5.4
		 * @param string[] $sql_patterns Case-insensitive substrings.
		 */
		$sql_patterns = \apply_filters( 'silver_assist_security_sql_injection_patterns', $sql_patterns );

		$matched = null;
		foreach ( $sql_patterns as $pattern ) {
			if ( false !== stripos( $full_data, $pattern ) ) {
				$matched = $pattern;
				break;
			}
		}
		if ( null === $matched && 1 === preg_match( $comment_pattern, $full_data ) ) {
			$matched = 'quoted SQL comment';
		}

		if ( null === $matched ) {
			return false;
		}

		SecurityHelper::log_security_event(
			'SQL_INJECTION_DETECTED',
			'SQL injection pattern detected in request',
			array(
				'pattern'       => $matched,
				'ip'            => SecurityHelper::get_client_ip(),
				'user_agent'    => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
				'query_string'  => $query_string,
				// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Same read-only attack-signature scan as above.
				'has_post_data' => ! empty( $_POST ),
			)
		);
		return true;
	}

	/**
	 * Get current rate limit configuration
	 *
	 * @since 1.1.15
	 * @return int Current rate limit
	 */
	public function get_rate_limit(): int {
		return (int) DefaultConfig::get_option( 'silver_assist_cf7_rate_limit' );
	}

	/**
	 * Get rate limiting window in seconds
	 *
	 * @since 1.1.15
	 * @return int Rate limiting window
	 */
	public function get_rate_window(): int {
		return (int) DefaultConfig::get_option( 'silver_assist_cf7_rate_window' );
	}
}
