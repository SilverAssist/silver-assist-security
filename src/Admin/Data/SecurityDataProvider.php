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
		if (\class_exists( 'WPGraphQL' )) {
			$graphql_active   = true;
			$config_manager   = GraphQLConfigManager::getInstance();
			$introspection    = \get_graphql_setting( 'public_introspection_enabled', 'off' );
			$query_depth      = DefaultConfig::get_option( 'silver_assist_graphql_query_depth' );
			$query_complexity = DefaultConfig::get_option( 'silver_assist_graphql_query_complexity' );
			$graphql_secure   = ( 'off' === $introspection && $query_depth <= 10 && $query_complexity <= 200 );
		}

		$active_features = 0;
		if ($login_protection) {
			++$active_features;
		}
		if ($password_strength) {
			++$active_features;
		}
		if ($bot_protection) {
			++$active_features;
		}
		if ($cookie_security) {
			++$active_features;
		}
		if ($admin_hide) {
			++$active_features;
		}
		if ($graphql_active && $graphql_secure) {
			++$active_features;
		}

		$total_features = 6; // Total possible features
		$security_score = round( ( $active_features / $total_features ) * 100 );

		return [
			'login_security'    => [
				'status'                        => $login_protection ? 'active' : 'inactive',
				'max_attempts'                  => DefaultConfig::get_option( 'silver_assist_login_attempts' ),
				'lockout_duration'              => DefaultConfig::get_option( 'silver_assist_lockout_duration' ),
				'password_strength_enforcement' => (bool) $password_strength,
				'bot_protection'                => (bool) $bot_protection,
			],
			'admin_security'    => [
				'status'                        => $admin_hide ? 'active' : 'inactive',
				'password_strength_enforcement' => (bool) $password_strength,
				'bot_protection'                => (bool) $bot_protection,
			],
			'graphql_security'  => [
				'status'  => $graphql_active ? ( $graphql_secure ? 'active' : 'warning' ) : 'inactive',
				'enabled' => $graphql_active,
				'secure'  => $graphql_secure,
			],
			'general_security'  => [
				'status'           => $cookie_security ? 'active' : 'inactive',
				'cookie_security'  => $cookie_security,
				'httponly_cookies' => true, // Always enabled
				'secure_cookies'   => \is_ssl(),
				'ssl_enabled'      => \is_ssl(),
			],
			'overall'           => [
				'active_features'   => $active_features,
				'total_features'    => $total_features,
				'security_score'    => $security_score,
				'blocked_ips_count' => $this->get_blocked_ips_count(),
				'last_updated'      => \current_time( 'mysql' ),
			],
		];
	}

	/**
	 * Get blocked IPs data
	 *
	 * @since 1.1.15
	 * @return array Blocked IPs information
	 */
	public function get_blocked_ips(): array {
		$blocked_ips = [];
		$raw_blocked = $this->ip_blacklist->get_all_blacklisted_ips();

		foreach ($raw_blocked as $ip => $data) {
			$blocked_at = isset( $data['blocked_at'] ) ? $data['blocked_at'] : time();
			$reason     = isset( $data['reason'] ) ? $data['reason'] : 'Multiple failed login attempts';
			$violations = isset( $data['violations'] ) ? (int) $data['violations'] : 1;
			$expires    = isset( $data['expires'] ) ? $data['expires'] : ( $blocked_at + ( 15 * MINUTE_IN_SECONDS ) );

			$blocked_ips[] = [
				'ip'            => $ip,
				'reason'        => $reason,
				'violations'    => $violations,
				'blocked_at'    => \gmdate( 'Y-m-d H:i:s', $blocked_at ),
				'expires_at'    => \gmdate( 'Y-m-d H:i:s', $expires ),
				'time_left'     => max( 0, $expires - time() ),
				'time_left_str' => SecurityHelper::format_time_duration( max( 0, $expires - time() ) ),
			];
		}

		// Sort by blocked_at descending (most recent first)
		usort(
			$blocked_ips,
			function ( $a, $b ) {
				return strtotime( $b['blocked_at'] ) - strtotime( $a['blocked_at'] );
			}
		);

		return [
			'blocked_ips' => array_slice( $blocked_ips, 0, 50 ), // Limit to 50 most recent
			'total_count' => count( $raw_blocked ),
		];
	}

	/**
	 * Get security logs (placeholder for future implementation)
	 *
	 * @since 1.1.15
	 * @return array Security logs data
	 */
	public function get_security_logs(): array {
		// TODO: Implement security logs retrieval
		// This would read from WordPress error logs or a custom logging system
		return [
			'logs'        => [],
			'total_count' => 0,
			'message'     => \__( 'Security logs feature coming soon', 'silver-assist-security' ),
		];
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
