<?php
/**
 * Silver Assist Security Essentials - Contact Form 7 AJAX Handler
 *
 * Handles Contact Form 7 specific AJAX requests for blocked IP management,
 * including getting, blocking, unblocking, clearing, and exporting blocked IPs.
 * Provides specialized security management for CF7 forms.
 *
 * @package SilverAssist\Security\Admin\Ajax
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Admin\Ajax;

use Exception;
use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\Security\IPBlacklist;

/**
 * Contact Form 7 AJAX Handler class
 *
 * Manages all Contact Form 7 related AJAX endpoints for IP management
 * with proper security validation and error handling.
 *
 * @since 1.1.15
 */
class ContactForm7AjaxHandler {

	/**
	 * Constructor
	 *
	 * @since 1.1.15
	 */
	public function __construct() {
		$this->init();
	}

	/**
	 * Initialize CF7 AJAX handlers
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function init(): void {
		// Only register CF7 AJAX handlers if CF7 is active
		if ( SecurityHelper::is_contact_form_7_active() ) {
			\add_action( 'wp_ajax_silver_assist_get_cf7_blocked_ips', array( $this, 'get_blocked_ips' ) );
			\add_action( 'wp_ajax_silver_assist_block_cf7_ip', array( $this, 'block_ip' ) );
			\add_action( 'wp_ajax_silver_assist_unblock_cf7_ip', array( $this, 'unblock_ip' ) );
			\add_action( 'wp_ajax_silver_assist_clear_cf7_blocked_ips', array( $this, 'clear_blocked_ips' ) );
			\add_action( 'wp_ajax_silver_assist_export_cf7_blocked_ips', array( $this, 'export_blocked_ips' ) );
		}
	}

	/**
	 * AJAX handler to get CF7 blocked IPs
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
			$blacklist     = IPBlacklist::getInstance();
			$blocked_ips   = $blacklist->get_cf7_blocked_ips();
			$total_attacks = $blacklist->get_cf7_attack_count();

			$html = '';
			if ( ! empty( $blocked_ips ) ) {
				$html .= '<div class="blocked-ips">';
				foreach ( $blocked_ips as $ip => $data ) {
					$blocked_at = isset( $data['blocked_at'] ) ? \date_i18n( 'M j, Y H:i', $data['blocked_at'] ) : \__( 'Unknown', 'silver-assist-security' );
					$reason     = isset( $data['reason'] ) ? \esc_html( $data['reason'] ) : \__( 'Form security violation', 'silver-assist-security' );
					$violations = isset( $data['violations'] ) ? (int) $data['violations'] : 1;

					$html .= \sprintf(
						'<div class="blocked-ip-item cf7-ip-item" data-ip="%s">',
						\esc_attr( $ip )
					);
					$html .= \sprintf( '<span class="ip-address">%s</span>', \esc_html( $ip ) );
					$html .= \sprintf( '<span class="block-reason">%s</span>', $reason );
					$html .= \sprintf( '<span class="block-time">%s</span>', $blocked_at );
					$html .= \sprintf(
						'<span class="violation-count">%d %s</span>',
						$violations,
						\__( 'violations', 'silver-assist-security' )
					);
					$html .= \sprintf(
						'<button type="button" class="unblock-cf7-ip button button-small" data-ip="%s">%s</button>',
						\esc_attr( $ip ),
						\__( 'Unblock', 'silver-assist-security' )
					);
					$html .= '</div>';
				}
				$html .= '</div>';
			} else {
				$html = \sprintf(
					'<p class="no-threats">%s</p>',
					\__( 'No CF7 blocked IPs found.', 'silver-assist-security' )
				);
			}

			\wp_send_json_success(
				array(
					'html'          => $html,
					'count'         => \count( $blocked_ips ),
					'total_attacks' => $total_attacks,
				)
			);

		} catch ( Exception $e ) {
			SecurityHelper::log_security_event( 'AJAX_ERROR', "CF7 blocked IPs retrieval failed: {$e->getMessage()}", array( 'function' => __FUNCTION__ ) );
			\wp_send_json_error( array( 'error' => \__( 'Failed to retrieve blocked IPs', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * AJAX handler to manually block CF7 IP
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function block_ip(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ) );
		}

		if ( ! \current_user_can( 'manage_options' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ) );
		}

		$ip = \sanitize_text_field( \wp_unslash( $_POST['ip'] ?? '' ) );
		if ( empty( $ip ) || ! \filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Invalid IP address', 'silver-assist-security' ) ) );
		}

		try {
			$blacklist = IPBlacklist::getInstance();
			$success   = $blacklist->add_to_cf7_blacklist(
				$ip,
				\__( 'Manually blocked via admin panel', 'silver-assist-security' ),
				'cf7_manual'
			);

			if ( $success ) {
				SecurityHelper::log_security_event( 'CF7_IP_BLOCKED', "IP {$ip} manually blocked via admin panel", array( 'ip' => $ip ) );
				\wp_send_json_success(
					array(
						'message' => \sprintf(
							/* translators: %s: IP address that was blocked */
							\__( 'IP %s successfully blocked for CF7 forms', 'silver-assist-security' ),
							$ip
						),
					)
				);
			} else {
				\wp_send_json_error( array( 'error' => \__( 'Failed to block IP address', 'silver-assist-security' ) ) );
			}
		} catch ( Exception $e ) {
			SecurityHelper::log_security_event( 'AJAX_ERROR', "CF7 IP blocking failed: {$e->getMessage()}", array( 'ip' => $ip ) );
			\wp_send_json_error( array( 'error' => \__( 'Failed to block IP address', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * AJAX handler to unblock CF7 IP
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

		$ip = \sanitize_text_field( \wp_unslash( $_POST['ip'] ?? '' ) );
		if ( empty( $ip ) ) {
			\wp_send_json_error( array( 'error' => \__( 'IP address required', 'silver-assist-security' ) ) );
		}

		try {
			$blacklist = IPBlacklist::getInstance();
			$success   = $blacklist->remove_from_blacklist( $ip );

			if ( $success ) {
				SecurityHelper::log_security_event( 'CF7_IP_UNBLOCKED', "IP {$ip} unblocked via admin panel", array( 'ip' => $ip ) );
				\wp_send_json_success(
					array(
						'message' => \sprintf(
							/* translators: %s: IP address that was unblocked */
							\__( 'IP %s successfully unblocked', 'silver-assist-security' ),
							$ip
						),
					)
				);
			} else {
				\wp_send_json_error( array( 'error' => \__( 'Failed to unblock IP address', 'silver-assist-security' ) ) );
			}
		} catch ( Exception $e ) {
			SecurityHelper::log_security_event( 'AJAX_ERROR', "CF7 IP unblocking failed: {$e->getMessage()}", array( 'ip' => $ip ) );
			\wp_send_json_error( array( 'error' => \__( 'Failed to unblock IP address', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * AJAX handler to clear all CF7 blocked IPs
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function clear_blocked_ips(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ) );
		}

		if ( ! \current_user_can( 'manage_options' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ) );
		}

		try {
			$blacklist     = IPBlacklist::getInstance();
			$cleared_count = $blacklist->clear_cf7_blacklist();

			SecurityHelper::log_security_event( 'CF7_BLACKLIST_CLEARED', 'All CF7 blocked IPs cleared via admin panel', array( 'count' => $cleared_count ) );
			\wp_send_json_success(
				array(
					'message' => \sprintf(
						/* translators: %d: number of IP addresses that were cleared */
						\__( 'Successfully cleared %d CF7 blocked IPs', 'silver-assist-security' ),
						$cleared_count
					),
					'count'   => $cleared_count,
				)
			);

		} catch ( Exception $e ) {
			SecurityHelper::log_security_event( 'AJAX_ERROR', "CF7 blacklist clearing failed: {$e->getMessage()}", array( 'function' => __FUNCTION__ ) );
			\wp_send_json_error( array( 'error' => \__( 'Failed to clear blocked IPs', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * AJAX handler to export CF7 blocked IPs
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function export_blocked_ips(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ) );
		}

		if ( ! \current_user_can( 'manage_options' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ) );
		}

		try {
			$blacklist   = IPBlacklist::getInstance();
			$blocked_ips = $blacklist->get_cf7_blocked_ips();

			$csv_data = "IP Address,Reason,Blocked At,Violations\n";
			foreach ( $blocked_ips as $ip => $data ) {
				$blocked_at = isset( $data['blocked_at'] ) ? \gmdate( 'Y-m-d H:i:s', $data['blocked_at'] ) : 'Unknown';
				$reason     = isset( $data['reason'] ) ? $data['reason'] : 'Form security violation';
				$violations = isset( $data['violations'] ) ? $data['violations'] : 1;

				$csv_data .= \sprintf(
					'"%s","%s","%s","%d"\n',
					$ip,
					\str_replace( '"', '""', $reason ),
					$blocked_at,
					$violations
				);
			}

			$filename = 'cf7-blocked-ips-' . \gmdate( 'Y-m-d-H-i-s' ) . '.csv';

			\wp_send_json_success(
				array(
					'csv_data' => $csv_data,
					'filename' => $filename,
					'count'    => \count( $blocked_ips ),
				)
			);

		} catch ( Exception $e ) {
			SecurityHelper::log_security_event( 'AJAX_ERROR', "CF7 blocked IPs export failed: {$e->getMessage()}", array( 'function' => __FUNCTION__ ) );
			\wp_send_json_error( array( 'error' => \__( 'Failed to export blocked IPs', 'silver-assist-security' ) ) );
		}
	}
}
