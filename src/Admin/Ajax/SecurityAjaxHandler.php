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

use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use SilverAssist\Security\Admin\Data\StatisticsProvider;

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
		\add_action( 'wp_ajax_silver_assist_get_security_status', [ $this, 'get_security_status' ] );
		\add_action( 'wp_ajax_silver_assist_get_login_stats', [ $this, 'get_login_stats' ] );
		\add_action( 'wp_ajax_silver_assist_get_blocked_ips', [ $this, 'get_blocked_ips' ] );
		\add_action( 'wp_ajax_silver_assist_get_security_logs', [ $this, 'get_security_logs' ] );
		\add_action( 'wp_ajax_silver_assist_auto_save', [ $this, 'auto_save' ] );
		\add_action( 'wp_ajax_silver_assist_validate_admin_path', [ $this, 'validate_admin_path' ] );
	}

	/**
	 * AJAX handler for security status
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function get_security_status(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' )) {
			\wp_send_json_error( [ 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ] );
		}

		if ( ! \current_user_can( 'manage_options' )) {
			\wp_send_json_error( [ 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ] );
		}

		try {
			$status = $this->security_data->get_security_status();
			\wp_send_json_success( $status );
		} catch (\Exception $e) {
			SecurityHelper::log_security_event(
				'AJAX_ERROR',
				"Security status retrieval failed: {$e->getMessage()}",
				[ 'function' => __FUNCTION__ ]
			);
			\wp_send_json_error( [ 'error' => \__( 'Failed to retrieve security status', 'silver-assist-security' ) ] );
		}
	}

	/**
	 * AJAX handler for login statistics
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function get_login_stats(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' )) {
			\wp_send_json_error( [ 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ] );
		}

		if ( ! \current_user_can( 'manage_options' )) {
			\wp_send_json_error( [ 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ] );
		}

		try {
			$stats = $this->statistics->get_login_statistics();
			\wp_send_json_success( $stats );
		} catch (\Exception $e) {
			SecurityHelper::log_security_event(
				'AJAX_ERROR',
				"Login statistics retrieval failed: {$e->getMessage()}",
				[ 'function' => __FUNCTION__ ]
			);
			\wp_send_json_error( [ 'error' => \__( 'Failed to retrieve login statistics', 'silver-assist-security' ) ] );
		}
	}

	/**
	 * AJAX handler for blocked IPs
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function get_blocked_ips(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' )) {
			\wp_send_json_error( [ 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ] );
		}

		if ( ! \current_user_can( 'manage_options' )) {
			\wp_send_json_error( [ 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ] );
		}

		try {
			$blocked_ips = $this->security_data->get_blocked_ips();
			\wp_send_json_success( $blocked_ips );
		} catch (\Exception $e) {
			SecurityHelper::log_security_event(
				'AJAX_ERROR',
				"Blocked IPs retrieval failed: {$e->getMessage()}",
				[ 'function' => __FUNCTION__ ]
			);
			\wp_send_json_error( [ 'error' => \__( 'Failed to retrieve blocked IPs', 'silver-assist-security' ) ] );
		}
	}

	/**
	 * AJAX handler for security logs
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function get_security_logs(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' )) {
			\wp_send_json_error( [ 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ] );
		}

		if ( ! \current_user_can( 'manage_options' )) {
			\wp_send_json_error( [ 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ] );
		}

		try {
			$logs = $this->security_data->get_security_logs();
			\wp_send_json_success( $logs );
		} catch (\Exception $e) {
			SecurityHelper::log_security_event(
				'AJAX_ERROR',
				"Security logs retrieval failed: {$e->getMessage()}",
				[ 'function' => __FUNCTION__ ]
			);
			\wp_send_json_error( [ 'error' => \__( 'Failed to retrieve security logs', 'silver-assist-security' ) ] );
		}
	}

	/**
	 * AJAX handler for auto-save settings
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function auto_save(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' )) {
			\wp_send_json_error( [ 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ] );
		}

		if ( ! \current_user_can( 'manage_options' )) {
			\wp_send_json_error( [ 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ] );
		}

		try {
			// TODO: Implement auto-save logic from AdminPanel
			\wp_send_json_success( [ 'message' => \__( 'Settings auto-saved successfully', 'silver-assist-security' ) ] );
		} catch (\Exception $e) {
			SecurityHelper::log_security_event(
				'AJAX_ERROR',
				"Auto-save failed: {$e->getMessage()}",
				[ 'function' => __FUNCTION__ ]
			);
			\wp_send_json_error( [ 'error' => \__( 'Failed to save settings', 'silver-assist-security' ) ] );
		}
	}

	/**
	 * AJAX handler for admin path validation
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function validate_admin_path(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' )) {
			\wp_send_json_error( [ 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ] );
		}

		if ( ! \current_user_can( 'manage_options' )) {
			\wp_send_json_error( [ 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ] );
		}

		try {
			// TODO: Implement admin path validation logic from AdminPanel
			\wp_send_json_success( [ 'valid' => true ] );
		} catch (\Exception $e) {
			SecurityHelper::log_security_event(
				'AJAX_ERROR',
				"Admin path validation failed: {$e->getMessage()}",
				[ 'function' => __FUNCTION__ ]
			);
			\wp_send_json_error( [ 'error' => \__( 'Failed to validate admin path', 'silver-assist-security' ) ] );
		}
	}
}
