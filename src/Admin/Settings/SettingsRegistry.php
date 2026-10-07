<?php
/**
 * Silver Assist Security Essentials - Settings Registry
 *
 * Declares, once, every option the settings screen saves: its section, type,
 * allowed range and whether the screen renders a field for it, plus which tab
 * of the screen each section is saved from. SettingsSaver is the only consumer that
 * writes; renderers, tests and documentation read the same declarations.
 *
 * @package SilverAssist\Security\Admin\Settings
 * @since 1.5.4
 * @author Silver Assist
 */

namespace SilverAssist\Security\Admin\Settings;

use SilverAssist\Security\GraphQL\GraphQLConfigManager;

/**
 * Settings Registry class
 *
 * @since 1.5.4
 */
class SettingsRegistry {

	public const TYPE_BOOL       = 'bool';
	public const TYPE_INT        = 'int';
	public const TYPE_URL        = 'url';
	public const TYPE_HEX_COLOR  = 'hex_color';
	public const TYPE_ADMIN_PATH = 'admin_path';
	public const TYPE_USER_ID    = 'user_id';

	public const SECTION_LOGIN          = 'login';
	public const SECTION_REST_API       = 'rest_api';
	public const SECTION_LOGIN_BRANDING = 'login_branding';
	public const SECTION_ADMIN_HIDE     = 'admin_hide';
	public const SECTION_GRAPHQL        = 'graphql';
	public const SECTION_GRAPHQL_AUTH   = 'graphql_auth';
	public const SECTION_CF7            = 'cf7';
	public const SECTION_IP             = 'ip';

	/**
	 * Tabs of the settings screen and the sections each one saves
	 *
	 * Each tab renders one form and one Save button; the form posts every section of its tab. The slug
	 * is the id prefix of the tab panel (`{slug}-content`) and the form (`{slug}-form`).
	 *
	 * @var array<string, string[]>
	 */
	private const TABS = array(
		'login-security'    => array( self::SECTION_LOGIN, self::SECTION_ADMIN_HIDE, self::SECTION_LOGIN_BRANDING ),
		'rest-api-security' => array( self::SECTION_REST_API ),
		'graphql-security'  => array( self::SECTION_GRAPHQL, self::SECTION_GRAPHQL_AUTH ),
		'cf7-security'      => array( self::SECTION_CF7 ),
		'ip-management'     => array( self::SECTION_IP ),
	);

	/**
	 * Option declarations, keyed by option name (built on first use)
	 *
	 * @var array<string, array<string, mixed>>|null
	 */
	private static ?array $options = null;

	/**
	 * Every declared option
	 *
	 * Each entry has: `option`, `section`, `type`, `min` (int|null), `max` (int|callable|null),
	 * and `ui` (the settings screen renders a field for it).
	 *
	 * @since 1.5.4
	 * @return array<string, array<string, mixed>>
	 */
	public static function all(): array {
		if ( null !== self::$options ) {
			return self::$options;
		}

		$declarations = array(
			// Login protection.
			self::declare_option( 'silver_assist_login_attempts', self::SECTION_LOGIN, self::TYPE_INT, 1, 20, true ),
			self::declare_option( 'silver_assist_lockout_duration', self::SECTION_LOGIN, self::TYPE_INT, 60, 3600, true ),
			self::declare_option( 'silver_assist_session_timeout', self::SECTION_LOGIN, self::TYPE_INT, 5, 120, true ),
			self::declare_option( 'silver_assist_password_strength_enforcement', self::SECTION_LOGIN, self::TYPE_BOOL, null, null, true ),
			self::declare_option( 'silver_assist_bot_protection', self::SECTION_LOGIN, self::TYPE_BOOL, null, null, true ),
			// REST API.
			self::declare_option( 'silver_assist_rest_batch_endpoint_protection', self::SECTION_REST_API, self::TYPE_BOOL, null, null, true ),
			self::declare_option( 'silver_assist_rest_rate_limiting_enabled', self::SECTION_REST_API, self::TYPE_BOOL, null, null, true ),
			self::declare_option( 'silver_assist_rest_rate_limit_requests', self::SECTION_REST_API, self::TYPE_INT, 10, 1000, true ),
			self::declare_option( 'silver_assist_rest_rate_limit_window', self::SECTION_REST_API, self::TYPE_INT, 30, 300, true ),
			// Login branding.
			self::declare_option( 'silver_assist_login_branding_enabled', self::SECTION_LOGIN_BRANDING, self::TYPE_BOOL, null, null, true ),
			self::declare_option( 'silver_assist_login_branding_show_illustration', self::SECTION_LOGIN_BRANDING, self::TYPE_BOOL, null, null, true ),
			self::declare_option( 'silver_assist_login_branding_logo_url', self::SECTION_LOGIN_BRANDING, self::TYPE_URL, null, null, true ),
			self::declare_option( 'silver_assist_login_branding_bg_color', self::SECTION_LOGIN_BRANDING, self::TYPE_HEX_COLOR, null, null, true ),
			// Admin hide. Enabling it goes through the confirmation in SettingsSaver (#160).
			self::declare_option( 'silver_assist_admin_hide_enabled', self::SECTION_ADMIN_HIDE, self::TYPE_BOOL, null, null, true ),
			self::declare_option( 'silver_assist_admin_hide_path', self::SECTION_ADMIN_HIDE, self::TYPE_ADMIN_PATH, null, null, true ),
			// GraphQL. Depth and complexity have no field on the screen.
			self::declare_option( 'silver_assist_graphql_headless_mode', self::SECTION_GRAPHQL, self::TYPE_BOOL, null, null, true ),
			self::declare_option( 'silver_assist_graphql_query_timeout', self::SECTION_GRAPHQL, self::TYPE_INT, 1, array( self::class, 'graphql_timeout_max' ), true ),
			self::declare_option( 'silver_assist_graphql_query_depth', self::SECTION_GRAPHQL, self::TYPE_INT, 1, 20, false ),
			self::declare_option( 'silver_assist_graphql_query_complexity', self::SECTION_GRAPHQL, self::TYPE_INT, 10, 1000, false ),
			// GraphQL authentication.
			self::declare_option( 'silver_assist_graphql_service_user_id', self::SECTION_GRAPHQL_AUTH, self::TYPE_USER_ID, null, null, true ),
			// Contact Form 7. The rate window has no field on the screen.
			self::declare_option( 'silver_assist_cf7_protection_enabled', self::SECTION_CF7, self::TYPE_BOOL, null, null, true ),
			self::declare_option( 'silver_assist_cf7_rate_limit', self::SECTION_CF7, self::TYPE_INT, 1, 10, true ),
			self::declare_option( 'silver_assist_cf7_rate_window', self::SECTION_CF7, self::TYPE_INT, 30, 300, false ),
			// IP management. The blacklist duration has no field on the screen.
			self::declare_option( 'silver_assist_ip_blacklist_enabled', self::SECTION_IP, self::TYPE_BOOL, null, null, true ),
			self::declare_option( 'silver_assist_ip_blacklist_threshold', self::SECTION_IP, self::TYPE_INT, 3, 20, true ),
			self::declare_option( 'silver_assist_ip_blacklist_duration', self::SECTION_IP, self::TYPE_INT, 3600, 604800, false ),
		);

		self::$options = array();
		foreach ( $declarations as $declaration ) {
			self::$options[ $declaration['option'] ] = $declaration;
		}

		return self::$options;
	}

	/**
	 * One option's declaration
	 *
	 * @since 1.5.4
	 * @param string $option Option name.
	 * @return array<string, mixed>|null Null when the option is not registered.
	 */
	public static function get( string $option ): ?array {
		return self::all()[ $option ] ?? null;
	}

	/**
	 * Section slugs, in declaration order
	 *
	 * @since 1.5.4
	 * @return string[]
	 */
	public static function sections(): array {
		return array_values( array_unique( array_column( self::all(), 'section' ) ) );
	}

	/**
	 * Whether a section exists
	 *
	 * @since 1.5.4
	 * @param string $section Section slug.
	 * @return bool
	 */
	public static function has_section( string $section ): bool {
		return in_array( $section, self::sections(), true );
	}

	/**
	 * The settings tabs and the sections each saves
	 *
	 * @since 1.5.4
	 * @return array<string, string[]> Section slugs keyed by tab slug.
	 */
	public static function tabs(): array {
		return self::TABS;
	}

	/**
	 * Sections saved from one tab
	 *
	 * @since 1.5.4
	 * @param string $tab Tab slug.
	 * @return string[] Empty when the tab is unknown.
	 */
	public static function sections_for_tab( string $tab ): array {
		return self::TABS[ $tab ] ?? array();
	}

	/**
	 * Options of one section
	 *
	 * @since 1.5.4
	 * @param string $section Section slug.
	 * @return array<string, array<string, mixed>> Declarations keyed by option name.
	 */
	public static function for_section( string $section ): array {
		return array_filter(
			self::all(),
			static fn( array $declaration ): bool => $declaration['section'] === $section
		);
	}

	/**
	 * Resolve the upper bound of an integer option
	 *
	 * @since 1.5.4
	 * @param array<string, mixed> $declaration Option declaration.
	 * @return int|null
	 */
	public static function resolve_max( array $declaration ): ?int {
		$max = $declaration['max'] ?? null;
		if ( is_callable( $max ) ) {
			$max = $max();
		}

		return null === $max ? null : (int) $max;
	}

	/**
	 * Upper bound of the GraphQL query timeout
	 *
	 * The PHP execution time limit, or 30 seconds (the slider maximum) when PHP has no limit.
	 *
	 * @since 1.5.4
	 * @return int Seconds.
	 */
	public static function graphql_timeout_max(): int {
		$php_timeout = GraphQLConfigManager::get_instance()->get_php_execution_timeout();

		return $php_timeout > 0 ? $php_timeout : 30;
	}

	/**
	 * Build one declaration
	 *
	 * @param string            $option   Option name.
	 * @param string            $section  Section slug.
	 * @param string            $type     One of the TYPE_* constants.
	 * @param int|null          $min      Lower bound (int type).
	 * @param int|callable|null $max      Upper bound or a callable returning it (int type).
	 * @param bool              $ui       Whether the settings screen renders a field for it.
	 * @return array<string, mixed>
	 */
	private static function declare_option( string $option, string $section, string $type, ?int $min, $max, bool $ui ): array {
		return array(
			'option'  => $option,
			'section' => $section,
			'type'    => $type,
			'min'     => $min,
			'max'     => $max,
			'ui'      => $ui,
		);
	}
}
