<?php

/**
 * Silver Assist Security Essentials - Security AJAX Handler
 *
 * Handles all AJAX requests related to security status, statistics, and general security operations.
 * Extracted from AdminPanel.php to improve maintainability and follow single responsibility principle.
 *
 * @package SilverAssist\Security\Admin\Ajax
 * @since 1.1.15
 */

namespace SilverAssist\Security\Admin\Ajax;

use SilverAssist\Security\Core\PathValidator;
use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use SilverAssist\Security\Admin\Data\StatisticsProvider;
use SilverAssist\Security\Security\IPBlacklist;

/**
 * Security AJAX Handler Class
 *
 * Manages AJAX endpoints for security-related operations including status checks,
 * statistics retrieval, IP management, and security logs.
 *
 * @since 1.1.15
 */
class SecurityAjaxHandler {

	/**
	 * Security data provider instance
	 *
	 * @var SecurityDataProvider
	 * @since 1.1.15
	 */
	private SecurityDataProvider $security_data;

	/**
	 * Statistics provider instance
	 *
	 * @var StatisticsProvider
	 * @since 1.1.15
	 */
	private StatisticsProvider $statistics;

	/**
	 * Initialize AJAX handler with data providers
	 *
	 * @param SecurityDataProvider $security_data Security data provider
	 * @param StatisticsProvider   $statistics    Statistics provider
	 * @since 1.1.15
	 */
	public function __construct( SecurityDataProvider $security_data, StatisticsProvider $statistics ) {
		$this->security_data = $security_data;
		$this->statistics    = $statistics;

		// Auto-register AJAX handlers
		$this->register_ajax_handlers();
	}

	/**
	 * Register all security AJAX handlers
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function register_ajax_handlers(): void {
		\add_action( 'wp_ajax_silver_assist_get_security_status', array( $this, 'get_security_status' ) );
		\add_action( 'wp_ajax_silver_assist_get_login_stats', array( $this, 'get_login_stats' ) );
		\add_action( 'wp_ajax_silver_assist_get_blocked_ips', array( $this, 'get_blocked_ips' ) );
		\add_action( 'wp_ajax_silver_assist_get_security_logs', array( $this, 'get_security_logs' ) );
		\add_action( 'wp_ajax_silver_assist_auto_save', array( $this, 'auto_save' ) );
		\add_action( 'wp_ajax_silver_assist_validate_admin_path', array( $this, 'validate_admin_path' ) );
		\add_action( 'wp_ajax_silver_assist_add_manual_ip', array( $this, 'add_manual_ip' ) );
		\add_action( 'wp_ajax_silver_assist_unblock_ip', array( $this, 'unblock_ip' ) );
	}

	/**
	 * AJAX handler for security status
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function get_security_status(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ) );
		}

		if ( ! \current_user_can( 'manage_options' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ) );
		}

		try {
			$status = $this->security_data->get_security_status();
			\wp_send_json_success( $status );
		} catch ( \Exception $e ) {
			SecurityHelper::log_security_event(
				'AJAX_ERROR',
				"Security status retrieval failed: {$e->getMessage()}",
				array( 'function' => __FUNCTION__ )
			);
			\wp_send_json_error( array( 'error' => \__( 'Failed to retrieve security status', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * AJAX handler for login statistics
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function get_login_stats(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ) );
		}

		if ( ! \current_user_can( 'manage_options' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ) );
		}

		try {
			$stats = $this->statistics->get_login_statistics();
			\wp_send_json_success( $stats );
		} catch ( \Exception $e ) {
			SecurityHelper::log_security_event(
				'AJAX_ERROR',
				"Login statistics retrieval failed: {$e->getMessage()}",
				array( 'function' => __FUNCTION__ )
			);
			\wp_send_json_error( array( 'error' => \__( 'Failed to retrieve login statistics', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * AJAX handler for blocked IPs
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function get_blocked_ips(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ) );
		}

		if ( ! \current_user_can( 'manage_options' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ) );
		}

		try {
			$blocked_ips = $this->security_data->get_blocked_ips();
			\wp_send_json_success( $blocked_ips );
		} catch ( \Exception $e ) {
			SecurityHelper::log_security_event(
				'AJAX_ERROR',
				"Blocked IPs retrieval failed: {$e->getMessage()}",
				array( 'function' => __FUNCTION__ )
			);
			\wp_send_json_error( array( 'error' => \__( 'Failed to retrieve blocked IPs', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * AJAX handler for security logs
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function get_security_logs(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ) );
		}

		if ( ! \current_user_can( 'manage_options' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ) );
		}

		try {
			$logs = $this->security_data->get_security_logs();
			\wp_send_json_success( $logs );
		} catch ( \Exception $e ) {
			SecurityHelper::log_security_event(
				'AJAX_ERROR',
				"Security logs retrieval failed: {$e->getMessage()}",
				array( 'function' => __FUNCTION__ )
			);
			\wp_send_json_error( array( 'error' => \__( 'Failed to retrieve security logs', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * AJAX handler for auto-save settings
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function auto_save(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ) );
		}

		if ( ! \current_user_can( 'manage_options' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ) );
		}

		try {
			$saved_settings = array();

			// Auto-save login security settings
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_request above
			if ( isset( $_POST['silver_assist_login_attempts'] ) ) {
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Input sanitized below
				$login_attempts = \intval( \sanitize_text_field( \wp_unslash( $_POST['silver_assist_login_attempts'] ) ) );
				$login_attempts = \max( 1, \min( 20, $login_attempts ) );
				\update_option( 'silver_assist_login_attempts', $login_attempts );
				$saved_settings['login_attempts'] = $login_attempts;
			}

			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_request above
			if ( isset( $_POST['silver_assist_lockout_duration'] ) ) {
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Input sanitized below
				$lockout_duration = \intval( \sanitize_text_field( \wp_unslash( $_POST['silver_assist_lockout_duration'] ) ) );
				$lockout_duration = \max( 60, \min( 3600, $lockout_duration ) );
				\update_option( 'silver_assist_lockout_duration', $lockout_duration );
				$saved_settings['lockout_duration'] = $lockout_duration;
			}

			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_request above
			if ( isset( $_POST['silver_assist_session_timeout'] ) ) {
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Input sanitized below
				$session_timeout = \intval( \sanitize_text_field( \wp_unslash( $_POST['silver_assist_session_timeout'] ) ) );
				$session_timeout = \max( 5, \min( 120, $session_timeout ) );
				\update_option( 'silver_assist_session_timeout', $session_timeout );
				$saved_settings['session_timeout'] = $session_timeout;
			}

			// Auto-save GraphQL settings
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_request above
			if ( isset( $_POST['silver_assist_graphql_query_depth'] ) ) {
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Input sanitized below
				$query_depth = \intval( \sanitize_text_field( \wp_unslash( $_POST['silver_assist_graphql_query_depth'] ) ) );
				$query_depth = \max( 1, \min( 20, $query_depth ) );
				\update_option( 'silver_assist_graphql_query_depth', $query_depth );
				$saved_settings['graphql_query_depth'] = $query_depth;
			}

			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_request above
			if ( isset( $_POST['silver_assist_graphql_query_complexity'] ) ) {
				// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Input sanitized below
				$query_complexity = \intval( \sanitize_text_field( \wp_unslash( $_POST['silver_assist_graphql_query_complexity'] ) ) );
				$query_complexity = \max( 10, \min( 1000, $query_complexity ) );
				\update_option( 'silver_assist_graphql_query_complexity', $query_complexity );
				$saved_settings['graphql_query_complexity'] = $query_complexity;
			}

			// Auto-save toggle settings (checkboxes)
			$toggle_settings = array(
				'silver_assist_password_strength_enforcement',
				'silver_assist_bot_protection',
				'silver_assist_graphql_headless_mode',
				'silver_assist_admin_hide_enabled',
				'silver_assist_ip_blacklist_enabled',
				'silver_assist_under_attack_enabled',
			);

			foreach ( $toggle_settings as $setting ) {
				// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_request above
				if ( isset( $_POST[ $setting ] ) ) {
					// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Input sanitized below
					$value = \sanitize_text_field( \wp_unslash( $_POST[ $setting ] ) ) === '1' ? 1 : 0;
					\update_option( $setting, $value );
					$saved_settings[ str_replace( 'silver_assist_', '', $setting ) ] = $value;
				}
			}

			SecurityHelper::log_security_event(
				'SETTINGS_AUTO_SAVE',
				'Security settings auto-saved successfully',
				array(
					'saved_count' => count( $saved_settings ),
					'settings'    => array_keys( $saved_settings ),
					'user_id'     => \get_current_user_id(),
				)
			);

			\wp_send_json_success(
				array(
					'message'        => sprintf(
						/* translators: %d: number of settings saved */
						\__( '%d settings auto-saved successfully', 'silver-assist-security' ),
						count( $saved_settings )
					),
					'saved_settings' => $saved_settings,
					'timestamp'      => \current_time( 'mysql' ),
				)
			);

		} catch ( \Exception $e ) {
			SecurityHelper::log_security_event(
				'SETTINGS_AUTO_SAVE_ERROR',
				"Auto-save failed: {$e->getMessage()}",
				array(
					'function' => __FUNCTION__,
					'error'    => $e->getMessage(),
				)
			);
			\wp_send_json_error( array( 'error' => \__( 'Failed to save settings', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * AJAX handler for admin path validation
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function validate_admin_path(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ) );
		}

		if ( ! \current_user_can( 'manage_options' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ) );
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verified in validate_ajax_request above
		if ( ! isset( $_POST['admin_path'] ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Admin path is required', 'silver-assist-security' ) ) );
		}

		try {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Input sanitized in PathValidator
			$admin_path = \wp_unslash( $_POST['admin_path'] );

			// Validate using PathValidator
			$validation_result = PathValidator::validate_admin_path( $admin_path );

			if ( ! $validation_result['is_valid'] ) {
				SecurityHelper::log_security_event(
					'ADMIN_PATH_VALIDATION_FAILED',
					'Invalid admin path validation attempt',
					array(
						'path'       => $admin_path,
						'error_type' => $validation_result['error_type'],
						'error'      => $validation_result['error_message'],
						'user_id'    => \get_current_user_id(),
					)
				);

				\wp_send_json_error(
					array(
						'error'      => $validation_result['error_message'],
						'error_type' => $validation_result['error_type'],
						'valid'      => false,
					)
				);
			}

			SecurityHelper::log_security_event(
				'ADMIN_PATH_VALIDATION_SUCCESS',
				'Admin path validation successful',
				array(
					'path'           => $admin_path,
					'sanitized_path' => $validation_result['sanitized_path'],
					'user_id'        => \get_current_user_id(),
				)
			);

			\wp_send_json_success(
				array(
					'valid'          => true,
					'sanitized_path' => $validation_result['sanitized_path'],
					'message'        => \__( 'Admin path is valid', 'silver-assist-security' ),
				)
			);

		} catch ( \Exception $e ) {
			SecurityHelper::log_security_event(
				'ADMIN_PATH_VALIDATION_ERROR',
				"Admin path validation failed: {$e->getMessage()}",
				array(
					'function' => __FUNCTION__,
					'error'    => $e->getMessage(),
					'user_id'  => \get_current_user_id(),
				)
			);
			\wp_send_json_error( array( 'error' => \__( 'Failed to validate admin path', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * AJAX handler for adding manual IP to blacklist
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function add_manual_ip(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ) );
		}

		if ( ! \current_user_can( 'manage_options' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ) );
		}

		try {
			// Get and validate IP address
			$ip_address = \sanitize_text_field( \wp_unslash( $_POST['ip_address'] ?? '' ) );

			if ( empty( $ip_address ) ) {
				\wp_send_json_error( array( 'error' => \__( 'IP address is required', 'silver-assist-security' ) ) );
				return;
			}

			// Validate IP format
			if ( ! filter_var( $ip_address, FILTER_VALIDATE_IP ) ) {
				\wp_send_json_error( array( 'error' => \__( 'Invalid IP address format', 'silver-assist-security' ) ) );
				return;
			}

			// Get reason (optional)
			$reason = \sanitize_text_field( \wp_unslash( $_POST['reason'] ?? '' ) );
			if ( empty( $reason ) ) {
				$reason = \__( 'Manually blocked by administrator', 'silver-assist-security' );
			}

			// Add IP to blacklist
			$ip_blacklist = new IPBlacklist();
			$duration     = 86400 * 30; // 30 days default
			$ip_blacklist->add_to_blacklist( $ip_address, $reason, $duration );

			SecurityHelper::log_security_event(
				'MANUAL_IP_BLOCKED',
				"Administrator manually blocked IP: {$ip_address}",
				array(
					'function' => __FUNCTION__,
					'ip'       => $ip_address,
					'reason'   => $reason,
					'user_id'  => \get_current_user_id(),
				)
			);

			\wp_send_json_success(
				array(
					'message' => sprintf(
						/* translators: %s: IP address */
						\__( 'IP address %s has been successfully blocked', 'silver-assist-security' ),
						$ip_address
					),
					'ip'      => $ip_address,
				)
			);

		} catch ( \Exception $e ) {
			SecurityHelper::log_security_event(
				'MANUAL_IP_BLOCK_ERROR',
				"Failed to manually block IP: {$e->getMessage()}",
				array(
					'function' => __FUNCTION__,
					'error'    => $e->getMessage(),
					'user_id'  => \get_current_user_id(),
				)
			);
			\wp_send_json_error( array( 'error' => \__( 'Failed to block IP address', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * AJAX handler for removing IP from blacklist
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function unblock_ip(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ) );
		}

		if ( ! \current_user_can( 'manage_options' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ) );
		}

		try {
			$ip_address = \sanitize_text_field( \wp_unslash( $_POST['ip_address'] ?? '' ) );

			if ( empty( $ip_address ) ) {
				\wp_send_json_error( array( 'error' => \__( 'IP address is required', 'silver-assist-security' ) ) );
				return;
			}

			$ip_blacklist = new IPBlacklist();
			$removed      = $ip_blacklist->remove_from_blacklist( $ip_address );

			if ( $removed ) {
				SecurityHelper::log_security_event(
					'MANUAL_IP_UNBLOCKED',
					"Administrator manually unblocked IP: {$ip_address}",
					array(
						'function' => __FUNCTION__,
						'ip'       => $ip_address,
						'user_id'  => \get_current_user_id(),
					)
				);

				\wp_send_json_success(
					array(
						'message' => sprintf(
							/* translators: %s: IP address */
							\__( 'IP address %s has been unblocked', 'silver-assist-security' ),
							$ip_address
						),
					)
				);
			} else {
				\wp_send_json_error( array( 'error' => \__( 'IP address was not found in the blacklist', 'silver-assist-security' ) ) );
			}
		} catch ( \Exception $e ) {
			SecurityHelper::log_security_event(
				'MANUAL_IP_UNBLOCK_ERROR',
				"Failed to unblock IP: {$e->getMessage()}",
				array(
					'function' => __FUNCTION__,
					'error'    => $e->getMessage(),
					'user_id'  => \get_current_user_id(),
				)
			);
			\wp_send_json_error( array( 'error' => \__( 'Failed to unblock IP address', 'silver-assist-security' ) ) );
		}
	}
}
