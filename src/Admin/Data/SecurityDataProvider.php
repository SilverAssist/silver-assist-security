<?php

/**
 * Silver Assist Security Essentials - Security Data Provider
 *
 * Provides security-related data including status, blocked IPs, and security logs.
 * Extracted from AdminPanel.php to separate data logic from presentation.
 *
 * @package SilverAssist\Security\Admin\Data
 * @since 1.1.15
 */

namespace SilverAssist\Security\Admin\Data;

use SilverAssist\Security\Security\LoginSecurity;
use SilverAssist\Security\Security\GeneralSecurity;
use SilverAssist\Security\Security\AdminHideSecurity;
use SilverAssist\Security\Security\IPBlacklist;
use SilverAssist\Security\GraphQL\GraphQLSecurity;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * Security Data Provider Class
 *
 * Centralized provider for all security-related data including status checks,
 * blocked IP management, and security event logs.
 *
 * @since 1.1.15
 */
class SecurityDataProvider {

	/**
	 * Login security instance
	 *
	 * @var LoginSecurity
	 * @since 1.1.15
	 */
	private LoginSecurity $login_security;

	/**
	 * General security instance
	 *
	 * @var GeneralSecurity
	 * @since 1.1.15
	 */
	private GeneralSecurity $general_security;

	/**
	 * Admin hide security instance
	 *
	 * @var AdminHideSecurity
	 * @since 1.1.15
	 */
	private AdminHideSecurity $admin_hide_security;

	/**
	 * IP Blacklist instance
	 *
	 * @var IPBlacklist
	 * @since 1.1.15
	 */
	private IPBlacklist $ip_blacklist;

	/**
	 * Initialize data provider with security components
	 *
	 * @since 1.1.15
	 */
	public function __construct() {
		$this->login_security      = new LoginSecurity();
		$this->general_security    = new GeneralSecurity();
		$this->admin_hide_security = new AdminHideSecurity();
		$this->ip_blacklist        = IPBlacklist::getInstance();
	}

	/**
	 * Get comprehensive security status
	 *
	 * @since 1.1.15
	 * @return array Security status data
	 */
	public function get_security_status(): array {
		$login_protection  = DefaultConfig::get_option( 'silver_assist_login_attempts' ) > 0;
		$password_strength = DefaultConfig::get_option( 'silver_assist_password_strength_enforcement' );
		$bot_protection    = DefaultConfig::get_option( 'silver_assist_bot_protection' );
		$cookie_security   = true; // Always enabled in GeneralSecurity
		$admin_hide        = DefaultConfig::get_option( 'silver_assist_admin_path' ) !== 'wp-admin';

		// GraphQL security status
		$graphql_active = false;
		$graphql_secure = false;
		if ( \class_exists( 'WPGraphQL' ) ) {
			$graphql_active   = true;
			$config_manager   = GraphQLConfigManager::getInstance();
			$introspection    = \get_graphql_setting( 'public_introspection_enabled', 'off' );
			$query_depth      = DefaultConfig::get_option( 'silver_assist_graphql_query_depth' );
			$query_complexity = DefaultConfig::get_option( 'silver_assist_graphql_query_complexity' );
			$graphql_secure   = ( 'off' === $introspection && $query_depth <= 10 && $query_complexity <= 200 );
		}

		$active_features = 0;
		if ( $login_protection ) {
			++$active_features;
		}
		if ( $password_strength ) {
			++$active_features;
		}
		if ( $bot_protection ) {
			++$active_features;
		}
		if ( $cookie_security ) {
			++$active_features;
		}
		if ( $admin_hide ) {
			++$active_features;
		}
		if ( $graphql_active && $graphql_secure ) {
			++$active_features;
		}

		$total_features = 6; // Total possible features
		$security_score = round( ( $active_features / $total_features ) * 100 );

		return array(
			'login_security'   => array(
				'status'                        => $login_protection ? 'active' : 'inactive',
				'max_attempts'                  => DefaultConfig::get_option( 'silver_assist_login_attempts' ),
				'lockout_duration'              => DefaultConfig::get_option( 'silver_assist_lockout_duration' ),
				'password_strength_enforcement' => (bool) $password_strength,
				'bot_protection'                => (bool) $bot_protection,
			),
			'admin_security'   => array(
				'status'                        => $admin_hide ? 'active' : 'inactive',
				'password_strength_enforcement' => (bool) $password_strength,
				'bot_protection'                => (bool) $bot_protection,
			),
			'graphql_security' => array(
				'status'  => $graphql_active ? ( $graphql_secure ? 'active' : 'warning' ) : 'inactive',
				'enabled' => $graphql_active,
				'secure'  => $graphql_secure,
			),
			'general_security' => array(
				'status'           => $cookie_security ? 'active' : 'inactive',
				'cookie_security'  => $cookie_security,
				'httponly_cookies' => true, // Always enabled
				'secure_cookies'   => \is_ssl(),
				'ssl_enabled'      => \is_ssl(),
			),
			'overall'          => array(
				'active_features'   => $active_features,
				'total_features'    => $total_features,
				'security_score'    => $security_score,
				'blocked_ips_count' => $this->get_blocked_ips_count(),
				'last_updated'      => \current_time( 'mysql' ),
			),
		);
	}

	/**
	 * Get blocked IPs data
	 *
	 * @since 1.1.15
	 * @return array Blocked IPs information
	 */
	public function get_blocked_ips(): array {
		$blocked_ips = array();
		$raw_blocked = $this->ip_blacklist->get_all_blacklisted_ips();

		foreach ( $raw_blocked as $ip => $data ) {
			$blocked_at = isset( $data['blocked_at'] ) ? $data['blocked_at'] : time();
			$reason     = isset( $data['reason'] ) ? $data['reason'] : 'Multiple failed login attempts';
			$violations = isset( $data['violations'] ) ? (int) $data['violations'] : 1;
			$expires    = isset( $data['expires'] ) ? $data['expires'] : ( $blocked_at + ( 15 * MINUTE_IN_SECONDS ) );

			$blocked_ips[] = array(
				'ip'            => $ip,
				'reason'        => $reason,
				'violations'    => $violations,
				'blocked_at'    => \gmdate( 'Y-m-d H:i:s', $blocked_at ),
				'expires_at'    => \gmdate( 'Y-m-d H:i:s', $expires ),
				'time_left'     => max( 0, $expires - time() ),
				'time_left_str' => SecurityHelper::format_time_duration( (int) max( 0, $expires - time() ) ),
			);
		}

		// Sort by blocked_at descending (most recent first)
		usort(
			$blocked_ips,
			function ( $a, $b ) {
				return strtotime( $b['blocked_at'] ) - strtotime( $a['blocked_at'] );
			}
		);

		return array(
			'blocked_ips' => array_slice( $blocked_ips, 0, 50 ), // Limit to 50 most recent
			'total_count' => count( $raw_blocked ),
		);
	}

	/**
	 * Get security logs from WordPress error logs
	 *
	 * Reads and parses security events from WordPress error.log file.
	 * Returns the most recent security events for the dashboard.
	 *
	 * @since 1.1.15
	 * @param int $limit Maximum number of logs to return (default: 50)
	 * @return array Security logs data
	 */
	public function get_security_logs( int $limit = 50 ): array {
		try {
			$logs = array();

			// Try to locate WordPress error log
			$log_files = $this->get_log_file_paths();

			foreach ( $log_files as $log_file ) {
				if ( ! file_exists( $log_file ) || ! is_readable( $log_file ) ) {
					continue;
				}

				$parsed_logs = $this->parse_log_file( $log_file, $limit );
				$logs        = array_merge( $logs, $parsed_logs );
			}

			// Sort by timestamp (most recent first) and limit
			usort(
				$logs,
				function ( $a, $b ) {
					return strtotime( $b['timestamp'] ) - strtotime( $a['timestamp'] );
				}
			);

			$logs = array_slice( $logs, 0, $limit );

			return array(
				'logs'        => $logs,
				'total_count' => count( $logs ),
				'message'     => sprintf(
					/* translators: %d: number of security logs found */
					\__( 'Found %d recent security events', 'silver-assist-security' ),
					count( $logs )
				),
				'log_files'   => array_filter( $log_files, 'file_exists' ),
			);

		} catch ( \Exception $e ) {
			SecurityHelper::log_security_event(
				'SECURITY_LOGS_ERROR',
				"Failed to retrieve security logs: {$e->getMessage()}",
				array( 'error' => $e->getMessage() )
			);

			return array(
				'logs'        => array(),
				'total_count' => 0,
				'message'     => \__( 'Unable to retrieve security logs', 'silver-assist-security' ),
				'error'       => $e->getMessage(),
			);
		}
	}

	/**
	 * Get possible WordPress error log file paths
	 *
	 * @since 1.1.15
	 * @return array List of potential log file paths
	 */
	private function get_log_file_paths(): array {
		$paths = array();

		// WP_DEBUG_LOG file location - can be a string path or boolean true (default location)
		if ( defined( 'WP_DEBUG_LOG' ) && \is_string( WP_DEBUG_LOG ) && WP_DEBUG_LOG !== '' ) {
			$paths[] = WP_DEBUG_LOG;
		}

		// Default WordPress debug.log locations
		$paths[] = WP_CONTENT_DIR . '/debug.log';
		$paths[] = ABSPATH . 'wp-content/debug.log';

		// Common server error log locations
		$paths[] = ini_get( 'error_log' );
		$paths[] = '/var/log/php_errors.log';
		$paths[] = '/var/log/apache2/error.log';
		$paths[] = '/var/log/nginx/error.log';

		// Remove empty/false values
		return array_filter( $paths );
	}

	/**
	 * Parse security events from a log file
	 *
	 * @since 1.1.15
	 * @param string $log_file Path to log file
	 * @param int    $limit Maximum entries to parse
	 * @return array Parsed security log entries
	 */
	private function parse_log_file( string $log_file, int $limit ): array {
		$logs = array();

		try {
			// Read last N lines efficiently for large files
			$lines = $this->tail_file( $log_file, $limit * 2 ); // Read more than limit to ensure we get enough Silver Assist entries

			foreach ( $lines as $line ) {
				// Look for Silver Assist Security events
				if ( strpos( $line, 'SILVER_ASSIST_SECURITY:' ) === false ) {
					continue;
				}

				$parsed_log = $this->parse_log_line( $line );
				if ( $parsed_log ) {
					$logs[] = $parsed_log;
				}

				// Stop if we have enough logs
				if ( count( $logs ) >= $limit ) {
					break;
				}
			}
		} catch ( \Exception $e ) {
			// Log parsing error but don't break the entire function
			SecurityHelper::log_security_event(
				'LOG_PARSE_ERROR',
				"Failed to parse log file {$log_file}: {$e->getMessage()}",
				array(
					'log_file' => $log_file,
					'error'    => $e->getMessage(),
				)
			);
		}

		return $logs;
	}

	/**
	 * Parse a single log line for security events
	 *
	 * @since 1.1.15
	 * @param string $line Log line to parse
	 * @return array|null Parsed log entry or null if invalid
	 */
	private function parse_log_line( string $line ): ?array {
		// Pattern: [timestamp] SILVER_ASSIST_SECURITY: EVENT_TYPE - {...JSON...}
		$pattern = '/\[([^\]]+)\].*SILVER_ASSIST_SECURITY:\s*([^-]+)\s*-\s*(.+)/';

		if ( ! preg_match( $pattern, $line, $matches ) ) {
			return null;
		}

		$timestamp  = trim( $matches[1] );
		$event_type = trim( $matches[2] );
		$json_data  = trim( $matches[3] );

		// Try to decode JSON data
		$data = json_decode( $json_data, true );
		if ( json_last_error() !== JSON_ERROR_NONE ) {
			// If JSON parsing fails, create basic entry
			$data = array(
				'message' => $json_data,
				'context' => array(),
			);
		}

		return array(
			'timestamp'   => $timestamp,
			'event_type'  => $event_type,
			'message'     => $data['message'] ?? $json_data,
			'ip'          => $data['ip'] ?? 'Unknown',
			'user_agent'  => $data['user_agent'] ?? 'Unknown',
			'request_uri' => $data['request_uri'] ?? '',
			'context'     => $data['context'] ?? array(),
			'severity'    => $this->get_event_severity( $event_type ),
		);
	}

	/**
	 * Read last N lines from a file efficiently
	 *
	 * @since 1.1.15
	 * @param string $file File path
	 * @param int    $lines Number of lines to read
	 * @return array Array of lines
	 */
	private function tail_file( string $file, int $lines ): array {
		$handle = fopen( $file, 'r' );
		if ( ! $handle ) {
			return array();
		}

		$result = array();

		// For small files, just read all lines
		if ( filesize( $file ) < 1024 * 1024 ) { // 1MB
			while ( ( $line = fgets( $handle ) ) !== false ) {
				$result[] = $line;
			}
			fclose( $handle );
			return array_slice( $result, -$lines );
		}

		// For large files, seek to end and read backwards
		fseek( $handle, -1, SEEK_END );
		$pos        = ftell( $handle );
		$line_count = 0;

		while ( $pos >= 0 && $line_count < $lines ) {
			$char = fgetc( $handle );
			if ( $char === "\n" ) {
				++$line_count;
			}

			if ( $pos > 0 ) {
				fseek( $handle, --$pos );
			} else {
				break;
			}
		}

		// Read remaining lines
		while ( ( $line = fgets( $handle ) ) !== false ) {
			$result[] = $line;
		}

		fclose( $handle );
		return $result;
	}

	/**
	 * Determine severity level for event type
	 *
	 * @since 1.1.15
	 * @param string $event_type Event type identifier
	 * @return string Severity level (critical, warning, info)
	 */
	private function get_event_severity( string $event_type ): string {
		$critical_events = array(
			'LOGIN_BRUTE_FORCE',
			'IP_BLOCKED',
			'BOT_BLOCKED',
			'ATTACK_DETECTED',
			'SECURITY_VIOLATION',
		);

		$warning_events = array(
			'LOGIN_FAILED',
			'INVALID_ADMIN_PATH',
			'RATE_LIMIT_EXCEEDED',
			'SUSPICIOUS_ACTIVITY',
		);

		if ( in_array( $event_type, $critical_events, true ) ) {
			return 'critical';
		}

		if ( in_array( $event_type, $warning_events, true ) ) {
			return 'warning';
		}

		return 'info';
	}

	/**
	 * Get count of blocked IPs
	 *
	 * @since 1.1.15
	 * @return int Number of currently blocked IPs
	 */
	private function get_blocked_ips_count(): int {
		return count( $this->ip_blacklist->get_all_blacklisted_ips() );
	}

	/**
	 * Count active security features
	 *
	 * @since 1.1.15
	 * @return int Number of active features
	 */
	public function count_active_features(): int {
		$count = 0;

		// Login security (always active)
		++$count;

		// Password enforcement
		if ( DefaultConfig::get_option( 'silver_assist_password_strength_enforcement' ) ) {
			++$count;
		}

		// GraphQL security
		if ( \class_exists( 'WPGraphQL' ) ) {
			++$count;
		}

		// General security features (always active)
		$count += 4; // HTTPOnly cookies, XML-RPC disabled, version hiding, SSL status

		return $count;
	}

	/**
	 * Get admin security status based on feature activation
	 *
	 * @since 1.1.15
	 * @return string Status (active|disabled)
	 */
	public function get_admin_security_status(): string {
		$password_enforcement = (bool) DefaultConfig::get_option( 'silver_assist_password_strength_enforcement' );
		$bot_protection       = (bool) DefaultConfig::get_option( 'silver_assist_bot_protection' );

		// Return active if any admin security feature is enabled
		return ( $password_enforcement || $bot_protection ) ? 'active' : 'disabled';
	}
}
