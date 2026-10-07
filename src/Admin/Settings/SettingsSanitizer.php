<?php
/**
 * Silver Assist Security Essentials - Settings Sanitizer
 *
 * The one place that turns a raw value into what a registered option may store, driven by
 * SettingsRegistry. SettingsSaver uses it for the settings screen and the auto-save endpoint, and
 * `register()` attaches it as the `sanitize_callback` of every registered option, so values written
 * outside the saver (core's options.php, the REST settings route, WP-CLI, imports) are sanitized the same way.
 *
 * @package SilverAssist\Security\Admin\Settings
 * @since 1.5.4
 * @author Silver Assist
 */

namespace SilverAssist\Security\Admin\Settings;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\PathValidator;

/**
 * Settings Sanitizer class
 *
 * @since 1.5.4
 */
class SettingsSanitizer {

	/**
	 * Prefix of the option group each registry section is registered under
	 */
	private const GROUP_PREFIX = 'silver_assist_security_';

	/**
	 * One callback instance per option, so registering again replaces the filter instead of stacking a second one
	 *
	 * @var array<string, callable>
	 */
	private static array $callbacks = array();

	/**
	 * Sanitize and clamp one value
	 *
	 * `$raw` must already be unslashed. The result has `value` (what to store), `submitted` (what was
	 * submitted, to report an adjustment when it differs from `value`, null when there is nothing to
	 * compare) and `error` (a message when the value cannot be stored at all; `value` is then meaningless).
	 *
	 * @since 1.5.4
	 * @param array<string, mixed> $declaration Registry declaration.
	 * @param mixed                $raw         Unslashed value.
	 * @return array{value: mixed, submitted: mixed, error: string}
	 */
	public static function normalize( array $declaration, $raw ): array {
		$outcome = array(
			'value'     => null,
			'submitted' => null,
			'error'     => '',
		);

		if ( ! is_scalar( $raw ) ) {
			$outcome['error'] = \__( 'Invalid value.', 'silver-assist-security' );
			return $outcome;
		}

		$submitted = \sanitize_text_field( (string) $raw );

		switch ( $declaration['type'] ) {
			case SettingsRegistry::TYPE_BOOL:
				$outcome['value'] = '1' === $submitted ? 1 : 0;
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
				$outcome['value']     = $value;
				$outcome['submitted'] = (int) $submitted;
				break;

			case SettingsRegistry::TYPE_URL:
				$url                  = trim( (string) $raw );
				$outcome['value']     = \esc_url_raw( $url );
				$outcome['submitted'] = $url;
				break;

			case SettingsRegistry::TYPE_HEX_COLOR:
				$outcome['value']     = \sanitize_hex_color( (string) $raw ) ?? '';
				$outcome['submitted'] = trim( (string) $raw );
				break;

			case SettingsRegistry::TYPE_USER_ID:
				$value = \absint( $submitted );
				if ( $value > 0 && ! \get_userdata( $value ) ) {
					$value = 0;
				}
				$outcome['value']     = $value;
				$outcome['submitted'] = \absint( $submitted );
				break;

			case SettingsRegistry::TYPE_ADMIN_PATH:
				$path                 = \sanitize_title( (string) $raw );
				$validation           = PathValidator::validate_admin_path( $path );
				$outcome['submitted'] = trim( (string) $raw );
				if ( $validation['is_valid'] ) {
					$outcome['value'] = $path;
				} else {
					$outcome['error'] = $validation['error_message'];
				}
				break;
		}

		return $outcome;
	}

	/**
	 * Register every registry option with a sanitize callback
	 *
	 * Hooked on `init` so the callbacks exist for REST requests, WP-CLI and cron as well as wp-admin. The
	 * options are not exposed to the REST settings route (`show_in_rest` stays false); a site that exposes
	 * one still goes through the callback. Safe to call again.
	 *
	 * @since 1.5.4
	 * @return void
	 */
	public static function register(): void {
		$registered = \get_registered_settings();

		foreach ( SettingsRegistry::all() as $option => $declaration ) {
			$group = self::GROUP_PREFIX . $declaration['section'];

			if ( isset( $registered[ $option ] ) ) {
				\unregister_setting( $group, $option );
			}

			\register_setting(
				$group,
				$option,
				array(
					'type'              => self::rest_type( $declaration['type'] ),
					'sanitize_callback' => self::callback_for( $option ),
					'show_in_rest'      => false,
				)
			);
		}
	}

	/**
	 * The callback instance registered for an option
	 *
	 * @param string $option Option name.
	 * @return callable
	 */
	private static function callback_for( string $option ): callable {
		if ( ! isset( self::$callbacks[ $option ] ) ) {
			self::$callbacks[ $option ] = static fn( $value ) => self::sanitize_registered( $option, $value );
		}

		return self::$callbacks[ $option ];
	}

	/**
	 * The `sanitize_callback` of a registered option
	 *
	 * A value that cannot be stored (an admin path that is reserved or collides, a non-scalar) keeps the
	 * value stored today, or the default when there is none, and queues a settings error that options.php shows.
	 *
	 * @since 1.5.4
	 * @param string $option Option name.
	 * @param mixed  $value  Value being written.
	 * @return mixed Value to store.
	 */
	public static function sanitize_registered( string $option, $value ) {
		$declaration = SettingsRegistry::get( $option );
		if ( null === $declaration ) {
			return $value;
		}

		$outcome = self::normalize( $declaration, $value );
		if ( '' === $outcome['error'] ) {
			return $outcome['value'];
		}

		if ( function_exists( 'add_settings_error' ) ) {
			\add_settings_error( $option, 'silver_assist_invalid_' . $option, $outcome['error'] );
		}

		return self::fallback_value( $declaration );
	}

	/**
	 * Value to keep when a write is refused: the stored one when it is acceptable, else the default
	 *
	 * @param array<string, mixed> $declaration Registry declaration.
	 * @return mixed
	 */
	private static function fallback_value( array $declaration ) {
		$option  = $declaration['option'];
		$default = DefaultConfig::get_default( $option );
		$stored  = \get_option( $option, $default );

		if ( SettingsRegistry::TYPE_ADMIN_PATH === $declaration['type'] ) {
			// An old install may hold a path that is no longer allowed; never keep a reserved one.
			return ( is_string( $stored ) && ! PathValidator::is_forbidden_path( $stored ) ) ? $stored : $default;
		}

		return $stored;
	}

	/**
	 * REST schema type of a registry type
	 *
	 * @param string $type One of the SettingsRegistry TYPE_* constants.
	 * @return string
	 */
	private static function rest_type( string $type ): string {
		switch ( $type ) {
			case SettingsRegistry::TYPE_BOOL:
				return 'boolean';
			case SettingsRegistry::TYPE_INT:
			case SettingsRegistry::TYPE_USER_ID:
				return 'integer';
			default:
				return 'string';
		}
	}
}
