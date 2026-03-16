<?php
/**
 * Silver Assist Security Essentials - GraphQL API Key AJAX Handler
 *
 * Handles AJAX requests for GraphQL API key management including
 * generation, regeneration, and revocation of API keys.
 *
 * @package SilverAssist\Security\Admin\Ajax
 * @since 1.3.0
 * @author Silver Assist
 */

namespace SilverAssist\Security\Admin\Ajax;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * GraphQL API Key AJAX Handler class
 *
 * Manages AJAX endpoints for API key generation and revocation
 * with proper security validation and error handling.
 *
 * @since 1.3.0
 */
class GraphQLApiKeyAjaxHandler {

	/**
	 * Constructor
	 *
	 * @since 1.3.0
	 */
	public function __construct() {
		$this->register_ajax_handlers();
	}

	/**
	 * Register AJAX handlers for API key management
	 *
	 * @since 1.3.0
	 * @return void
	 */
	private function register_ajax_handlers(): void {
		\add_action( 'wp_ajax_silver_assist_generate_graphql_api_key', array( $this, 'generate_api_key' ) );
		\add_action( 'wp_ajax_silver_assist_revoke_graphql_api_key', array( $this, 'revoke_api_key' ) );
	}

	/**
	 * AJAX handler for generating a new GraphQL API key
	 *
	 * @since 1.3.0
	 * @return void
	 */
	public function generate_api_key(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ) );
		}

		if ( ! \current_user_can( 'manage_options' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ) );
		}

		try {
			$bytes   = \random_bytes( 32 );
			$api_key = \bin2hex( $bytes );
		} catch ( \Throwable $e ) {
			SecurityHelper::log_security_event(
				'graphql_api_key_error',
				'Failed to generate GraphQL API key using random_bytes().',
				array(
					'exception_message' => $e->getMessage(),
					'file'              => __FILE__,
					'line'              => __LINE__,
				)
			);

			\wp_send_json_error(
				array(
					'error' => \__(
						'Failed to generate a new GraphQL API key. Please check your server\'s randomness configuration.',
						'silver-assist-security'
					),
				)
			);
		}

		// Store only the hash.
		\update_option( 'silver_assist_graphql_api_key', \wp_hash_password( $api_key ) );

		// Check if a service user is configured.
		$current_service_user = (int) DefaultConfig::get_option( 'silver_assist_graphql_service_user_id' );
		$needs_service_user   = $current_service_user <= 0 || ! \get_userdata( $current_service_user );

		\wp_send_json_success(
			array(
				'api_key'            => $api_key,
				'message'            => \__( 'API key generated successfully. Copy it now — it will not be shown again.', 'silver-assist-security' ),
				'needs_service_user' => $needs_service_user,
			)
		);
	}

	/**
	 * AJAX handler for revoking the GraphQL API key
	 *
	 * @since 1.3.0
	 * @return void
	 */
	public function revoke_api_key(): void {
		if ( ! SecurityHelper::validate_ajax_request( 'silver_assist_security_ajax' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Security validation failed', 'silver-assist-security' ) ) );
		}

		if ( ! \current_user_can( 'manage_options' ) ) {
			\wp_send_json_error( array( 'error' => \__( 'Insufficient permissions', 'silver-assist-security' ) ) );
		}

		\update_option( 'silver_assist_graphql_api_key', '' );
		\update_option( 'silver_assist_graphql_service_user_id', 0 );

		\wp_send_json_success(
			array(
				'message' => \__( 'API key has been revoked successfully.', 'silver-assist-security' ),
			)
		);
	}
}
