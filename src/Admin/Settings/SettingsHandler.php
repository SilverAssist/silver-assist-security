<?php
/**
 * Silver Assist Security Essentials - Settings Handler
 *
 * Authorizes a settings form submission (gate field, capability, nonce) and
 * delegates the save of the submitted section to SettingsSaver.
 *
 * @package SilverAssist\Security\Admin\Settings
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Admin\Settings;

/**
 * Settings Handler class
 *
 * Authorizes the request and hands the submitted section to SettingsSaver, which owns
 * sanitizing, clamping and writing.
 *
 * @since 1.1.15
 */
class SettingsHandler {

	/**
	 * Settings saver
	 *
	 * @var SettingsSaver
	 */
	private SettingsSaver $saver;

	/**
	 * Constructor
	 *
	 * @since 1.1.15
	 * @param SettingsSaver|null $saver Settings saver (defaults to a new one).
	 */
	public function __construct( ?SettingsSaver $saver = null ) {
		$this->saver = $saver ?? new SettingsSaver();
	}

	/**
	 * Main settings processing method
	 *
	 * Requires the gate field, `manage_options` and a valid nonce, then saves the section named in
	 * `settings_section`. A missing or unknown section writes nothing and shows an error notice.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function save_security_settings(): void {
		if ( ! isset( $_POST['save_silver_assist_security'] ) || ! \current_user_can( 'manage_options' ) ) {
			return;
		}

		// Verify nonce.
		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized,WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Nonce verification doesn't require unslashing or sanitization
		if ( ! isset( $_POST['_wpnonce'] ) || ! \wp_verify_nonce( $_POST['_wpnonce'], 'silver_assist_security_settings' ) ) {
			\wp_die( \esc_html__( 'Security check failed.', 'silver-assist-security' ) );
		}

		$section = isset( $_POST['settings_section'] ) ? \sanitize_text_field( \wp_unslash( $_POST['settings_section'] ) ) : '';

		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce and capability verified above; SettingsSaver unslashes, sanitizes and clamps every value.
		$result = $this->saver->save( $_POST, $section, SettingsSaver::MODE_FORM );

		if ( isset( $result->errors['section'] ) ) {
			$this->add_notice( 'error', $result->errors['section'] );
			return;
		}

		if ( empty( $result->errors ) ) {
			$this->add_notice( 'success', \__( 'Security settings have been saved successfully.', 'silver-assist-security' ) );
		} else {
			foreach ( $result->errors as $option => $message ) {
				$this->add_notice(
					'error',
					sprintf(
						/* translators: 1: setting name, 2: reason */
						\__( '%1$s was not saved: %2$s.', 'silver-assist-security' ),
						str_replace( 'silver_assist_', '', $option ),
						rtrim( $message, '.' )
					)
				);
			}
			if ( $result->saved_count() > 0 ) {
				$this->add_notice( 'success', \__( 'The other settings were saved.', 'silver-assist-security' ) );
			}
		}

		if ( ! empty( $result->adjusted ) ) {
			$this->add_notice(
				'warning',
				sprintf(
					/* translators: %s: list of setting names */
					\__( 'Some values were adjusted to what is allowed: %s.', 'silver-assist-security' ),
					implode( ', ', str_replace( 'silver_assist_', '', array_keys( $result->adjusted ) ) )
				)
			);
		}
	}

	/**
	 * Show an admin notice after the settings save
	 *
	 * @since 1.1.15
	 * @param string $type    Notice type: success, warning or error.
	 * @param string $message Notice text.
	 * @return void
	 */
	private function add_notice( string $type, string $message ): void {
		\add_action(
			'admin_notices',
			function () use ( $type, $message ) {
				echo '<div class="notice notice-' . \esc_attr( $type ) . ' is-dismissible">';
				echo '<p>' . \esc_html( $message ) . '</p>';
				echo '</div>';
			}
		);
	}
}
