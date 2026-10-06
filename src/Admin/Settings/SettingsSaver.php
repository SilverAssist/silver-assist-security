<?php
/**
 * Silver Assist Security Essentials - Settings Saver
 *
 * The only place that unslashes, sanitizes, clamps and writes the options the
 * settings screen manages. The settings form handler and the auto-save AJAX
 * endpoint both delegate here, driven by SettingsRegistry, so the two paths
 * cannot disagree.
 *
 * @package SilverAssist\Security\Admin\Settings
 * @since 1.5.4
 * @author Silver Assist
 */

namespace SilverAssist\Security\Admin\Settings;

use SilverAssist\Security\Core\PathValidator;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * Settings Saver class
 *
 * @since 1.5.4
 */
class SettingsSaver {

	/**
	 * A section form was submitted: bools of the section that are absent are saved as off
	 */
	public const MODE_FORM = 'form';

	/**
	 * Auto-save: only submitted keys of auto-save eligible options are touched
	 */
	public const MODE_AUTOSAVE = 'autosave';

	/**
	 * Path stored when an admin path is empty or invalid
	 */
	private const FALLBACK_ADMIN_PATH = 'silver-admin';

	/**
	 * Save a submission
	 *
	 * `$input` is the raw (slashed) request data, for example `$_POST`; this method unslashes it. The caller
	 * authorizes the request (capability and nonce) before calling.
	 *
	 * In `form` mode `$section` must be a registry section: only that section's options are written, and a
	 * bool of the section that is absent from the input is saved as off (checkbox semantics). Any other
	 * section, including an empty one, writes nothing and reports an error. In `autosave` mode `$section`
	 * may be empty (all sections) or limit the save to one section; only submitted keys of auto-save
	 * eligible options are written, and a bool is on only when it is "1".
	 *
	 * @since 1.5.4
	 * @param array<string, mixed> $input   Raw submission.
	 * @param string               $section Section slug.
	 * @param string               $mode    One of the MODE_* constants.
	 * @return SaveResult
	 */
	public function save( array $input, string $section, string $mode ): SaveResult {
		$result = new SaveResult();

		if ( self::MODE_FORM !== $mode && self::MODE_AUTOSAVE !== $mode ) {
			$result->errors['mode'] = \__( 'Unknown save mode.', 'silver-assist-security' );
			$result->ignored        = array_map( 'strval', array_keys( $input ) );
			return $result;
		}

		$section_known = SettingsRegistry::has_section( $section );
		if ( ( self::MODE_FORM === $mode && ! $section_known ) || ( '' !== $section && ! $section_known ) ) {
			$result->errors['section'] = \__( 'Unknown settings section, nothing was saved.', 'silver-assist-security' );
			$result->ignored           = array_map( 'strval', array_keys( $input ) );
			return $result;
		}

		if ( self::MODE_FORM === $mode && SettingsRegistry::SECTION_CF7 === $section && ! SecurityHelper::is_contact_form_7_active() ) {
			$result->errors['section'] = \__( 'Contact Form 7 is not active, nothing was saved.', 'silver-assist-security' );
			$result->ignored           = array_map( 'strval', array_keys( $input ) );
			return $result;
		}

		foreach ( array_keys( $input ) as $key ) {
			$declaration = SettingsRegistry::get( (string) $key );
			if ( null === $declaration || ! $this->is_in_scope( $declaration, $section, $mode ) ) {
				$result->ignored[] = (string) $key;
			}
		}

		foreach ( SettingsRegistry::all() as $option => $declaration ) {
			if ( ! $this->is_in_scope( $declaration, $section, $mode ) ) {
				continue;
			}

			if ( array_key_exists( $option, $input ) ) {
				$this->save_option( $declaration, $input[ $option ], $result );
			} elseif ( self::MODE_FORM === $mode && SettingsRegistry::TYPE_BOOL === $declaration['type'] && $declaration['ui'] ) {
				// An unchecked checkbox is not sent at all.
				$this->write( $option, 0, $result );
			}
		}

		if ( self::MODE_FORM === $mode && SettingsRegistry::SECTION_ADMIN_HIDE === $section && (int) \get_option( 'silver_assist_admin_hide_enabled', 0 ) ) {
			\flush_rewrite_rules();
		}

		return $result;
	}

	/**
	 * Whether an option can be written in this section and mode
	 *
	 * @param array<string, mixed> $declaration Registry declaration.
	 * @param string               $section     Section slug ('' = any, auto-save only).
	 * @param string               $mode        Save mode.
	 * @return bool
	 */
	private function is_in_scope( array $declaration, string $section, string $mode ): bool {
		if ( '' !== $section && $declaration['section'] !== $section ) {
			return false;
		}

		return self::MODE_FORM === $mode || true === $declaration['autosave'];
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
		$option = $declaration['option'];

		if ( ! is_scalar( $raw ) ) {
			$result->errors[ $option ] = \__( 'Invalid value.', 'silver-assist-security' );
			return;
		}

		$submitted = \sanitize_text_field( \wp_unslash( (string) $raw ) );

		switch ( $declaration['type'] ) {
			case SettingsRegistry::TYPE_BOOL:
				$this->write( $option, '1' === $submitted ? 1 : 0, $result );
				break;

			case SettingsRegistry::TYPE_INT:
				$value = (int) $submitted;
				$min   = $declaration['min'] ?? null;
				$max   = SettingsRegistry::resolve_max( $declaration );
				if ( null !== $min ) {
					$value = max( (int) $min, $value );
				}
				if ( null !== $max ) {
					$value = min( $max, $value );
				}
				$this->write( $option, $value, $result, (int) $submitted );
				break;

			case SettingsRegistry::TYPE_URL:
				$url   = trim( \wp_unslash( (string) $raw ) );
				$value = \esc_url_raw( $url );
				$this->write( $option, $value, $result, $url );
				break;

			case SettingsRegistry::TYPE_HEX_COLOR:
				$value = \sanitize_hex_color( \wp_unslash( (string) $raw ) );
				$this->write( $option, $value ?? '', $result, trim( \wp_unslash( (string) $raw ) ) );
				break;

			case SettingsRegistry::TYPE_USER_ID:
				$value = \absint( $submitted );
				if ( $value > 0 && ! \get_userdata( $value ) ) {
					$value = 0;
				}
				$this->write( $option, $value, $result, \absint( $submitted ) );
				break;

			case SettingsRegistry::TYPE_ADMIN_PATH:
				$path  = \sanitize_title( \wp_unslash( (string) $raw ) );
				$value = ( '' !== $path && PathValidator::validate_admin_path( $path )['is_valid'] ) ? $path : self::FALLBACK_ADMIN_PATH;
				$this->write( $option, $value, $result, trim( \wp_unslash( (string) $raw ) ) );
				break;
		}
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
