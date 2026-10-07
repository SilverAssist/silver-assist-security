<?php
/**
 * Silver Assist Security Essentials - Settings Handler
 *
 * Authorizes a settings form submission (gate field, capability, nonce) and
 * delegates the save of the submitted tab to SettingsSaver, then keeps the result
 * for the renderer, which shows each message next to its field.
 *
 * @package SilverAssist\Security\Admin\Settings
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Admin\Settings;

/**
 * Settings Handler class
 *
 * Authorizes the request and hands the submitted tab to SettingsSaver, which owns
 * sanitizing, clamping and writing.
 *
 * @since 1.1.15
 */
class SettingsHandler {

	/**
	 * Result of the save handled in this request, for the renderer
	 *
	 * @var SaveResult|null
	 */
	private static ?SaveResult $last_result = null;

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
	 * What the save handled in this request did, or null when the request was not a save
	 *
	 * The settings screen renders after the handler runs (same request, no redirect), so it reads this to
	 * show an error or an adjusted value next to its field and to keep what the user typed.
	 *
	 * @since 1.5.4
	 * @return SaveResult|null
	 */
	public static function last_result(): ?SaveResult {
		return self::$last_result;
	}

	/**
	 * Forget the last result (a new request starts clean; tests call it between cases)
	 *
	 * @since 1.5.4
	 * @return void
	 */
	public static function clear_last_result(): void {
		self::$last_result = null;
	}

	/**
	 * Main settings processing method
	 *
	 * Requires the gate field, `manage_options` and a valid nonce, then saves the tab named in
	 * `settings_tab` (one form per tab) or, for a single-section post, the section named in
	 * `settings_section`. A missing or unknown tab or section writes nothing and shows an error notice.
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

		$tab     = isset( $_POST['settings_tab'] ) ? \sanitize_text_field( \wp_unslash( $_POST['settings_tab'] ) ) : '';
		$section = isset( $_POST['settings_section'] ) ? \sanitize_text_field( \wp_unslash( $_POST['settings_section'] ) ) : '';

		// phpcs:disable WordPress.Security.NonceVerification.Missing,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Nonce and capability verified above; SettingsSaver unslashes, sanitizes and clamps every value.
		$result = isset( $_POST['settings_tab'] )
			? $this->saver->save_tab( $_POST, $tab )
			: $this->saver->save( $_POST, $section );
		// phpcs:enable

		self::$last_result = $result;

		if ( isset( $result->errors['section'] ) ) {
			$this->add_notice( 'error', $result->errors['section'] );
			return;
		}

		if ( empty( $result->errors ) ) {
			$this->add_notice( 'success', \__( 'Security settings have been saved successfully.', 'silver-assist-security' ) );
		} else {
			$this->add_notice( 'error', \__( 'Some settings were not saved. Fix the fields marked below and save again.', 'silver-assist-security' ) );
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

		if ( $result->rewrite_flushed && '' !== $result->admin_url ) {
			$this->add_notice(
				'warning',
				sprintf(
					/* translators: %s: URL of the admin */
					\__( 'Admin Hide is on. Your admin is reachable at %s. Keep this URL: /wp-admin and /wp-login.php do not open without it.', 'silver-assist-security' ),
					$result->admin_url
				)
			);
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
