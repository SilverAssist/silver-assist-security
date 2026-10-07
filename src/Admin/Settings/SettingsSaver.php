<?php
/**
 * Silver Assist Security Essentials - Settings Saver
 *
 * The only place that unslashes and writes the options the settings screen
 * manages; SettingsSanitizer sanitizes and clamps each value. The settings form
 * handler delegates here, driven by SettingsRegistry, and the Admin Hide section
 * goes through a safety flow so a save cannot lock the administrator out.
 *
 * @package SilverAssist\Security\Admin\Settings
 * @since 1.5.4
 * @author Silver Assist
 */

namespace SilverAssist\Security\Admin\Settings;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\PathValidator;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * Settings Saver class
 *
 * @since 1.5.4
 */
class SettingsSaver {

	/**
	 * Name of the checkbox that confirms the admin URL before Admin Hide takes effect
	 *
	 * It is not an option: it is only read while saving the Admin Hide section.
	 */
	public const ADMIN_HIDE_CONFIRM_FIELD = 'silver_assist_admin_hide_confirm';

	private const OPTION_ADMIN_HIDE_ENABLED = 'silver_assist_admin_hide_enabled';
	private const OPTION_ADMIN_HIDE_PATH    = 'silver_assist_admin_hide_path';

	/**
	 * Save the submission of one tab form
	 *
	 * Every section of the tab is saved, so the bools of the tab that are absent from `$input` are saved
	 * as off (checkbox semantics). An unknown tab writes nothing and reports an error.
	 *
	 * @since 1.5.4
	 * @param array<string, mixed> $input Raw (slashed) submission, for example `$_POST`.
	 * @param string               $tab   Tab slug from SettingsRegistry::tabs().
	 * @return SaveResult
	 */
	public function save_tab( array $input, string $tab ): SaveResult {
		$result   = new SaveResult();
		$sections = SettingsRegistry::sections_for_tab( $tab );

		if ( empty( $sections ) ) {
			$result->errors['section'] = \__( 'Unknown settings tab, nothing was saved.', 'silver-assist-security' );
			$result->ignored           = array_map( 'strval', array_keys( $input ) );
			return $result;
		}

		$known = array( self::ADMIN_HIDE_CONFIRM_FIELD );
		foreach ( $sections as $section ) {
			$result->merge( $this->save_section( $input, $section ) );
			$known = array_merge( $known, array_keys( $this->writable_options( $section ) ) );
		}

		foreach ( array_keys( $input ) as $key ) {
			if ( ! in_array( (string) $key, $known, true ) ) {
				$result->ignored[] = (string) $key;
			}
		}

		return $result;
	}

	/**
	 * Save the submission of one section
	 *
	 * `$input` is the raw (slashed) request data, for example `$_POST`; this method unslashes it. The caller
	 * authorizes the request (capability and nonce) before calling. `$section` must be a registry section:
	 * only that section's options are written, and a bool with a field on the screen that
	 * is absent from the input is saved as off (checkbox semantics). Any other section, including an empty
	 * one, writes nothing and reports an error.
	 *
	 * A value that cannot be stored (an admin path that is empty, reserved or collides with a page or route)
	 * is not written: the stored value stays and the reason is in `SaveResult::$errors`, keyed by option name.
	 *
	 * @since 1.5.4
	 * @param array<string, mixed> $input   Raw submission.
	 * @param string               $section Section slug.
	 * @return SaveResult
	 */
	public function save( array $input, string $section ): SaveResult {
		if ( ! SettingsRegistry::has_section( $section ) ) {
			$result                    = new SaveResult();
			$result->errors['section'] = \__( 'Unknown settings section, nothing was saved.', 'silver-assist-security' );
			$result->ignored           = array_map( 'strval', array_keys( $input ) );
			return $result;
		}

		$result   = $this->save_section( $input, $section );
		$writable = $this->writable_options( $section );

		foreach ( array_keys( $input ) as $key ) {
			if ( ! isset( $writable[ $key ] ) && self::ADMIN_HIDE_CONFIRM_FIELD !== $key ) {
				$result->ignored[] = (string) $key;
			}
		}

		return $result;
	}

	/**
	 * The URL the admin is reachable at for a custom path
	 *
	 * @since 1.5.4
	 * @param string $path Custom admin path.
	 * @return string
	 */
	public static function admin_url_for_path( string $path ): string {
		return \home_url( '/' . $path );
	}

	/**
	 * Save one known section
	 *
	 * @param array<string, mixed> $input   Raw submission.
	 * @param string               $section Section slug.
	 * @return SaveResult
	 */
	private function save_section( array $input, string $section ): SaveResult {
		$result = new SaveResult();

		if ( SettingsRegistry::SECTION_CF7 === $section && ! SecurityHelper::is_contact_form_7_active() ) {
			$result->errors['section'] = \__( 'Contact Form 7 is not active, nothing was saved.', 'silver-assist-security' );
			return $result;
		}

		if ( SettingsRegistry::SECTION_ADMIN_HIDE === $section ) {
			$this->save_admin_hide( $input, $result );
			return $result;
		}

		foreach ( $this->writable_options( $section ) as $option => $declaration ) {
			if ( array_key_exists( $option, $input ) ) {
				$this->save_option( $declaration, $input[ $option ], $result );
			} elseif ( SettingsRegistry::TYPE_BOOL === $declaration['type'] && $declaration['ui'] ) {
				// An unchecked checkbox is not sent at all.
				$this->write( $option, 0, $result );
			}
		}

		return $result;
	}

	/**
	 * The options a save of this section may write
	 *
	 * @param string $section Section slug.
	 * @return array<string, array<string, mixed>>
	 */
	private function writable_options( string $section ): array {
		return SettingsRegistry::for_section( $section );
	}

	/**
	 * Save the Admin Hide section without being able to lock the administrator out
	 *
	 * - A path that fails validation is never written and never enables Admin Hide; turning it off is never blocked.
	 * - Turning it on, or changing the path while it is on, takes effect only when the confirmation checkbox is
	 *   posted (the form shows the resulting URL next to it); otherwise nothing of the section is written.
	 * - When the toggle or the path changes, the rewrite rules are flushed.
	 *
	 * @param array<string, mixed> $input  Raw submission.
	 * @param SaveResult           $result Result to record into.
	 * @return void
	 */
	private function save_admin_hide( array $input, SaveResult $result ): void {
		$enabled_decl = SettingsRegistry::get( self::OPTION_ADMIN_HIDE_ENABLED );
		$path_decl    = SettingsRegistry::get( self::OPTION_ADMIN_HIDE_PATH );
		if ( null === $enabled_decl || null === $path_decl ) {
			return;
		}

		$old_enabled = (int) \get_option( self::OPTION_ADMIN_HIDE_ENABLED, 0 );
		$old_path    = $this->effective_path( \get_option( self::OPTION_ADMIN_HIDE_PATH, '' ) );

		$want_enabled = array_key_exists( self::OPTION_ADMIN_HIDE_ENABLED, $input )
			&& 1 === SettingsSanitizer::normalize( $enabled_decl, \wp_unslash( $input[ self::OPTION_ADMIN_HIDE_ENABLED ] ) )['value'];

		$path_submitted = array_key_exists( self::OPTION_ADMIN_HIDE_PATH, $input );
		$outcome        = $path_submitted
			? SettingsSanitizer::normalize( $path_decl, \wp_unslash( $input[ self::OPTION_ADMIN_HIDE_PATH ] ) )
			: array(
				'value'     => $old_path,
				'submitted' => $old_path,
				'error'     => '',
			);
		$typed_path     = is_scalar( $outcome['submitted'] ) ? (string) $outcome['submitted'] : '';

		if ( '' !== $outcome['error'] ) {
			// Never write a bad path, and never turn Admin Hide on with it.
			$result->errors[ self::OPTION_ADMIN_HIDE_PATH ]    = $outcome['error'];
			$result->submitted[ self::OPTION_ADMIN_HIDE_PATH ] = $typed_path;
			if ( $want_enabled ) {
				$result->submitted[ self::OPTION_ADMIN_HIDE_ENABLED ] = '1';
				if ( ! $old_enabled ) {
					$result->errors[ self::OPTION_ADMIN_HIDE_ENABLED ] = \__( 'Admin Hide was not turned on: fix the admin path first.', 'silver-assist-security' );
				}
			} elseif ( $old_enabled ) {
				// Turning it off is never blocked.
				$this->write( self::OPTION_ADMIN_HIDE_ENABLED, 0, $result );
			}
			$this->finish_admin_hide( $result, $old_enabled, $old_path );
			return;
		}

		$new_path     = (string) $outcome['value'];
		$takes_effect = $want_enabled && ( ! $old_enabled || $new_path !== $old_path );
		if ( $takes_effect && ! $this->is_confirmed( $input ) ) {
			$key                    = $old_enabled ? self::OPTION_ADMIN_HIDE_PATH : self::OPTION_ADMIN_HIDE_ENABLED;
			$result->errors[ $key ] = sprintf(
				/* translators: %s: URL of the admin once Admin Hide is on */
				\__( 'Not changed: confirm that you saved the admin URL %s before Admin Hide takes effect.', 'silver-assist-security' ),
				self::admin_url_for_path( $new_path )
			);
			$result->submitted[ self::OPTION_ADMIN_HIDE_ENABLED ] = '1';
			$result->submitted[ self::OPTION_ADMIN_HIDE_PATH ]    = $typed_path;
			return;
		}

		$this->write( self::OPTION_ADMIN_HIDE_ENABLED, $want_enabled ? 1 : 0, $result );
		if ( $path_submitted ) {
			$this->write( self::OPTION_ADMIN_HIDE_PATH, $new_path, $result, $typed_path );
		}
		$this->finish_admin_hide( $result, $old_enabled, $old_path );
	}

	/**
	 * Flush the rewrite rules when the toggle or the path changed, and record the resulting admin URL
	 *
	 * @param SaveResult $result      Result to record into.
	 * @param int        $old_enabled Toggle before the save.
	 * @param string     $old_path    Effective path before the save.
	 * @return void
	 */
	private function finish_admin_hide( SaveResult $result, int $old_enabled, string $old_path ): void {
		$enabled = (int) \get_option( self::OPTION_ADMIN_HIDE_ENABLED, 0 );
		$path    = $this->effective_path( \get_option( self::OPTION_ADMIN_HIDE_PATH, '' ) );

		if ( $enabled !== $old_enabled || $path !== $old_path ) {
			\flush_rewrite_rules();
			$result->rewrite_flushed = true;
		}

		if ( $enabled ) {
			$result->admin_url = self::admin_url_for_path( $path );
		}
	}

	/**
	 * Whether the confirmation checkbox was posted
	 *
	 * @param array<string, mixed> $input Raw submission.
	 * @return bool
	 */
	private function is_confirmed( array $input ): bool {
		$value = $input[ self::ADMIN_HIDE_CONFIRM_FIELD ] ?? '';

		return is_scalar( $value ) && '1' === \sanitize_text_field( (string) \wp_unslash( $value ) );
	}

	/**
	 * The path the plugin will actually use for a stored value
	 *
	 * Mirrors AdminHideSecurity: an empty or forbidden stored path falls back to the default.
	 *
	 * @param mixed $stored Stored option value.
	 * @return string
	 */
	private function effective_path( $stored ): string {
		$path = \sanitize_title( is_scalar( $stored ) ? (string) $stored : '' );
		if ( '' === $path || PathValidator::is_forbidden_path( $path ) ) {
			return (string) DefaultConfig::get_default( self::OPTION_ADMIN_HIDE_PATH );
		}

		return $path;
	}

	/**
	 * Sanitize, clamp and write one submitted value
	 *
	 * @param array<string, mixed> $declaration Registry declaration.
	 * @param mixed                $raw         Raw submitted value.
	 * @param SaveResult           $result      Result to record into.
	 * @return void
	 */
	private function save_option( array $declaration, $raw, SaveResult $result ): void {
		$option  = $declaration['option'];
		$outcome = SettingsSanitizer::normalize( $declaration, \wp_unslash( $raw ) );

		if ( '' !== $outcome['error'] ) {
			// Rejected, not written: the stored value stays and the caller reports why.
			$result->errors[ $option ]    = $outcome['error'];
			$result->submitted[ $option ] = is_scalar( $outcome['submitted'] ) ? (string) $outcome['submitted'] : '';
			return;
		}

		$this->write( $option, $outcome['value'], $result, $outcome['submitted'] );
	}

	/**
	 * Write an option and record it
	 *
	 * @param string     $option    Option name.
	 * @param mixed      $value     Value to store.
	 * @param SaveResult $result    Result to record into.
	 * @param mixed      $submitted What was submitted, when it can differ from the stored value.
	 * @return void
	 */
	private function write( string $option, $value, SaveResult $result, $submitted = null ): void {
		\update_option( $option, $value );
		$result->saved[ $option ] = $value;

		if ( null !== $submitted && (string) $submitted !== (string) $value ) {
			$result->adjusted[ $option ] = array(
				'submitted' => $submitted,
				'saved'     => $value,
			);
		}
	}
}
