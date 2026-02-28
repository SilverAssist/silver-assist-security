<?php
/**
 * Silver Assist Security Essentials - Statistics Provider
 *
 * Provides statistical data for security dashboard including login attempts,
 * blocked IPs, and security events.
 *
 * @package SilverAssist\Security\Admin\Data
 * @since 1.1.15
 */

namespace SilverAssist\Security\Admin\Data;

use SilverAssist\Security\Security\IPBlacklist;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * Statistics Provider Class
 *
 * Generates statistical data for the security dashboard and reports.
 *
 * @since 1.1.15
 */
class StatisticsProvider {

	/**
	 * IP Blacklist instance
	 *
	 * @var IPBlacklist
	 * @since 1.1.15
	 */
	private IPBlacklist $ip_blacklist;

	/**
	 * Initialize statistics provider
	 *
	 * @since 1.1.15
	 */
	public function __construct() {
		$this->ip_blacklist = IPBlacklist::getInstance();
	}

	/**
	 * Get login statistics
	 *
	 * @since 1.1.15
	 * @return array Login statistics data
	 */
	public function get_login_statistics(): array {
		// Get statistics for the last 24 hours, 7 days, and 30 days
		$stats = array(
			'24_hours' => $this->get_period_stats( DAY_IN_SECONDS ),
			'7_days'   => $this->get_period_stats( WEEK_IN_SECONDS ),
			'30_days'  => $this->get_period_stats( MONTH_IN_SECONDS ),
		);

		return array(
			'stats'        => $stats,
			'last_updated' => \current_time( 'mysql' ),
		);
	}

	/**
	 * Get statistics for a specific time period
	 *
	 * @param int $period_seconds Time period in seconds
	 * @return array Period statistics
	 * @since 1.1.15
	 */
	private function get_period_stats( int $period_seconds ): array {
		$cutoff_time = time() - $period_seconds;

		// Count failed login attempts
		$failed_logins = $this->count_failed_logins_since( $cutoff_time );

		// Count blocked IPs
		$blocked_ips = $this->count_blocked_ips_since( $cutoff_time );

		// Count bot blocks
		$bot_blocks = $this->count_bot_blocks_since( $cutoff_time );

		return array(
			'period'        => SecurityHelper::format_time_duration( $period_seconds ),
			'failed_logins' => $failed_logins,
			'blocked_ips'   => $blocked_ips,
			'bot_blocks'    => $bot_blocks,
			'total_events'  => $failed_logins + $blocked_ips + $bot_blocks,
		);
	}

	/**
	 * Count failed login attempts since timestamp
	 *
	 * @param int $since_timestamp Timestamp to count from
	 * @return int Number of failed login attempts
	 * @since 1.1.15
	 */
	private function count_failed_logins_since( int $since_timestamp ): int {
		global $wpdb;

		// Check for transient-based login attempts
		$transient_count = 0;
		$results         = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT option_name, option_value FROM {$wpdb->options} 
				WHERE option_name LIKE %s 
				AND option_value > %d",
				'_transient_login_attempts_%',
				$since_timestamp
			)
		);

		return count( $results );
	}

	/**
	 * Count blocked IPs since timestamp
	 *
	 * @param int $since_timestamp Timestamp to count from
	 * @return int Number of IPs blocked
	 * @since 1.1.15
	 */
	private function count_blocked_ips_since( int $since_timestamp ): int {
		$all_blocked = $this->ip_blacklist->get_all_blacklisted_ips();
		$count       = 0;

		foreach ( $all_blocked as $ip => $data ) {
			$blocked_at = isset( $data['blocked_at'] ) ? (int) $data['blocked_at'] : 0;
			if ( $blocked_at >= $since_timestamp ) {
				++$count;
			}
		}

		return $count;
	}

	/**
	 * Count bot blocks since given timestamp
	 *
	 * @param int $since_timestamp Timestamp to count from
	 * @return int Number of bot blocks
	 * @since 1.1.15
	 */
	private function count_bot_blocks_since( int $since_timestamp ): int {
		try {
			// First check transients for recent bot blocks (performance optimization)
			$cache_key    = "bot_blocks_count_{$since_timestamp}";
			$cached_count = \get_transient( $cache_key );

			if ( false !== $cached_count ) {
				return (int) $cached_count;
			}

			$count = 0;

			// Method 1: Check for bot blocking transients (faster)
			$count += $this->count_bot_block_transients( $since_timestamp );

			// Method 2: Parse security logs for BOT_BLOCKED events (more comprehensive)
			$count += $this->count_bot_blocks_from_logs( $since_timestamp );

			// Cache result for 5 minutes to avoid repeated log parsing
			\set_transient( $cache_key, $count, 300 );

			return $count;

		} catch ( \Exception $e ) {
			SecurityHelper::log_security_event(
				'BOT_COUNT_ERROR',
				"Failed to count bot blocks: {$e->getMessage()}",
				array(
					'since_timestamp' => $since_timestamp,
					'error'           => $e->getMessage(),
				)
			);

			return 0;
		}
	}

	/**
	 * Count bot blocks from transient entries
	 *
	 * @param int $since_timestamp Timestamp to count from
	 * @return int Number of bot blocks found in transients
	 * @since 1.1.15
	 */
	private function count_bot_block_transients( int $since_timestamp ): int {
		global $wpdb;

		try {
			// Look for bot-related transients created since timestamp
			$count = $wpdb->get_var(
				$wpdb->prepare(
					"SELECT COUNT(*) 
					 FROM {$wpdb->options} 
					 WHERE option_name LIKE %s 
					 AND option_name LIKE %s 
					 AND UNIX_TIMESTAMP(STR_TO_DATE(SUBSTRING(option_name, LENGTH('_transient_timeout_') + 1), '%%Y-%%m-%%d %%H:%%i:%%s')) >= %d",
					'_transient_timeout_%',
					'%bot_block%',
					$since_timestamp
				)
			);

			return (int) $count;

		} catch ( \Exception $e ) {
			// Fallback to simpler query if complex one fails
			$count = $wpdb->get_var(
				"SELECT COUNT(*) 
				 FROM {$wpdb->options} 
				 WHERE option_name LIKE '_transient_%bot_block%'"
			);

			return (int) $count;
		}
	}

	/**
	 * Count bot blocks from security logs
	 *
	 * @param int $since_timestamp Timestamp to count from
	 * @return int Number of BOT_BLOCKED events in logs
	 * @since 1.1.15
	 */
	private function count_bot_blocks_from_logs( int $since_timestamp ): int {
		$count = 0;

		// Get log file paths directly to avoid circular dependency with SecurityDataProvider
		$log_files = $this->get_log_file_paths();

		foreach ( $log_files as $log_file ) {
			if ( ! file_exists( $log_file ) || ! is_readable( $log_file ) ) {
				continue;
			}

			$count += $this->count_bot_blocks_in_file( $log_file, $since_timestamp );
		}

		return $count;
	}

	/**
	 * Get possible log file paths
	 *
	 * @since 1.1.15
	 * @return array List of potential log file paths
	 */
	private function get_log_file_paths(): array {
		$paths = array();

		if ( defined( 'WP_DEBUG_LOG' ) && ! \is_bool( WP_DEBUG_LOG ) && \is_string( WP_DEBUG_LOG ) && WP_DEBUG_LOG !== '' ) {
			$paths[] = WP_DEBUG_LOG;
		}

		$paths[] = WP_CONTENT_DIR . '/debug.log';
		$paths[] = ABSPATH . 'wp-content/debug.log';
		$paths[] = ini_get( 'error_log' );

		return array_filter( $paths );
	}

	/**
	 * Count BOT_BLOCKED events in a specific log file
	 *
	 * @since 1.1.15
	 * @param string $log_file Path to log file
	 * @param int    $since_timestamp Only count events after this timestamp
	 * @return int Count of BOT_BLOCKED events
	 */
	private function count_bot_blocks_in_file( string $log_file, int $since_timestamp ): int {
		$count = 0;

		try {
			$handle = @fopen( $log_file, 'r' );
			if ( ! $handle ) {
				return 0;
			}

			// Read file line by line to handle large files
			while ( ( $line = fgets( $handle ) ) !== false ) {
				if ( strpos( $line, 'SILVER_ASSIST_SECURITY:' ) === false ) {
					continue;
				}
				if ( strpos( $line, 'BOT_BLOCKED' ) === false ) {
					continue;
				}

				// Extract timestamp from log line: [YYYY-MM-DD HH:MM:SS]
				if ( preg_match( '/\[([^\]]+)\]/', $line, $matches ) ) {
					$log_timestamp = strtotime( $matches[1] );
					if ( $log_timestamp && $log_timestamp >= $since_timestamp ) {
						++$count;
					}
				}
			}

			fclose( $handle );
		} catch ( \Exception $e ) {
			// Silently fail - don't break statistics for log read errors
		}

		return $count;
	}

	/**
	 * Get count of blocked IPs
	 *
	 * @since 1.1.15
	 * @return int Number of currently blocked IPs
	 */
	public function get_blocked_ips_count(): int {
		global $wpdb;

		// Try to get from cache first
		$cache_key = 'silver_assist_blocked_ips_count';
		$count     = \wp_cache_get( $cache_key, 'silver-assist-security' );

		if ( false === $count ) {
			$count = $wpdb->get_var(
				"SELECT COUNT(*) 
             FROM {$wpdb->options} 
             WHERE option_name LIKE \"_transient_lockout_%\" 
             AND option_value = \"1\""
			);

			// Cache for 60 seconds
			\wp_cache_set( $cache_key, $count, 'silver-assist-security', 60 );
		}

		return (int) $count;
	}

	/**
	 * Get recent failed login attempts count
	 *
	 * @since 1.1.15
	 * @return int Number of failed attempts in last 24 hours
	 */
	public function get_recent_failed_attempts(): int {
		global $wpdb;

		// Try to get from cache first
		$cache_key = 'silver_assist_failed_attempts_count';
		$count     = \wp_cache_get( $cache_key, 'silver-assist-security' );

		if ( false === $count ) {
			// Count active login attempt transients
			$count = $wpdb->get_var(
				"SELECT COUNT(*) 
             FROM {$wpdb->options} 
             WHERE option_name LIKE \"_transient_login_attempts_%\""
			);

			// Cache for 60 seconds
			\wp_cache_set( $cache_key, $count, 'silver-assist-security', 60 );
		}

		return (int) $count;
	}

	/**
	 * Get recent security logs
	 *
	 * @since 1.1.15
	 * @return array Recent security events
	 */
	public function get_recent_security_logs(): array {
		global $wpdb;

		$logs = array();

		// Try to get from cache first
		$cache_key          = 'silver_assist_attempt_transients';
		$attempt_transients = \wp_cache_get( $cache_key, 'silver-assist-security' );

		if ( false === $attempt_transients ) {
			// Get recent login attempts (transients)
			$attempt_transients = $wpdb->get_results(
				"SELECT option_name, option_value 
             FROM {$wpdb->options} 
             WHERE option_name LIKE \"_transient_login_attempts_%\" 
             ORDER BY option_id DESC 
             LIMIT 10"
			);

			// Cache for 60 seconds
			\wp_cache_set( $cache_key, $attempt_transients, 'silver-assist-security', 60 );
		}

		foreach ( $attempt_transients as $transient ) {
			$ip_hash  = str_replace( '_transient_login_attempts_', '', $transient->option_name );
			$attempts = (int) $transient->option_value;

			$logs[] = array(
				'type'      => 'failed_login',
				'ip_hash'   => substr( $ip_hash, 0, 8 ) . '...',
				'attempts'  => $attempts,
				'timestamp' => \current_time( 'mysql' ),
				'status'    => $attempts >= \SilverAssist\Security\Core\DefaultConfig::get_option( 'silver_assist_login_attempts' ) ? 'blocked' : 'monitoring',
			);
		}

		// Try to get from cache first
		$lockout_cache_key  = 'silver_assist_recent_lockouts';
		$lockout_transients = \wp_cache_get( $lockout_cache_key, 'silver-assist-security' );

		if ( false === $lockout_transients ) {
			// Get recent lockouts
			$lockout_transients = $wpdb->get_results(
				"SELECT option_name, option_value 
             FROM {$wpdb->options} 
             WHERE option_name LIKE \"_transient_lockout_%\" 
             AND option_value = \"1\"
             ORDER BY option_id DESC 
             LIMIT 5"
			);

			// Cache for 60 seconds
			\wp_cache_set( $lockout_cache_key, $lockout_transients, 'silver-assist-security', 60 );
		}

		foreach ( $lockout_transients as $lockout ) {
			$ip_hash = str_replace( '_transient_lockout_', '', $lockout->option_name );

			$logs[] = array(
				'type'      => 'ip_blocked',
				'ip_hash'   => substr( $ip_hash, 0, 8 ) . '...',
				'timestamp' => \current_time( 'mysql' ),
				'status'    => 'active',
				'action'    => 'IP blocked due to excessive failed login attempts',
			);
		}

		// Sort by timestamp (most recent first)
		usort(
			$logs,
			function ( $a, $b ) {
				return strcmp( $b['timestamp'], $a['timestamp'] );
			}
		);

		return array_slice( $logs, 0, 15 ); // Return max 15 recent logs
	}
}
