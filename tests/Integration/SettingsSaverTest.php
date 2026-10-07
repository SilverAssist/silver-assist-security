<?php
/**
 * SettingsSaver tests
 *
 * The saver is the only code that sanitizes, clamps and writes the settings the screen manages.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Admin\Settings\SaveResult;
use SilverAssist\Security\Admin\Settings\SettingsRegistry;
use SilverAssist\Security\Admin\Settings\SettingsSaver;
use WP_UnitTestCase;

/**
 * Saver behavior per type, per mode
 */
class SettingsSaverTest extends WP_UnitTestCase {

	/**
	 * Saver under test
	 *
	 * @var SettingsSaver
	 */
	private SettingsSaver $saver;

	/**
	 * Fresh saver and no stored values
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();
		$this->saver = new SettingsSaver();
		foreach ( \array_keys( SettingsRegistry::all() ) as $option ) {
			\delete_option( $option );
		}
	}

	/**
	 * Save in form mode
	 *
	 * @param array<string, mixed> $input   Input.
	 * @param string               $section Section.
	 * @return SaveResult
	 */
	private function form( array $input, string $section ): SaveResult {
		return $this->saver->save( $input, $section, SettingsSaver::MODE_FORM );
	}

	/**
	 * Save in auto-save mode
	 *
	 * @param array<string, mixed> $input Input.
	 * @return SaveResult
	 */
	private function autosave( array $input ): SaveResult {
		return $this->saver->save( $input, '', SettingsSaver::MODE_AUTOSAVE );
	}

	/**
	 * Every integer option keeps today's clamping range
	 *
	 * @return array<string, array{string, string, int, int}>
	 */
	public function int_ranges(): array {
		return array(
			'login attempts'      => array( 'silver_assist_login_attempts', 'login', 1, 20 ),
			'lockout duration'    => array( 'silver_assist_lockout_duration', 'login', 60, 3600 ),
			'session timeout'     => array( 'silver_assist_session_timeout', 'login', 5, 120 ),
			'rest limit requests' => array( 'silver_assist_rest_rate_limit_requests', 'rest_api', 10, 1000 ),
			'rest limit window'   => array( 'silver_assist_rest_rate_limit_window', 'rest_api', 30, 300 ),
			'graphql timeout'     => array( 'silver_assist_graphql_query_timeout', 'graphql', 1, 30 ),
			'graphql depth'       => array( 'silver_assist_graphql_query_depth', 'graphql', 1, 20 ),
			'graphql complexity'  => array( 'silver_assist_graphql_query_complexity', 'graphql', 10, 1000 ),
			'cf7 rate limit'      => array( 'silver_assist_cf7_rate_limit', 'cf7', 1, 10 ),
			'cf7 rate window'     => array( 'silver_assist_cf7_rate_window', 'cf7', 30, 300 ),
			'ip threshold'        => array( 'silver_assist_ip_blacklist_threshold', 'ip', 3, 20 ),
			'ip duration'         => array( 'silver_assist_ip_blacklist_duration', 'ip', 3600, 604800 ),
		);
	}

	/**
	 * Integers clamp to the range and report the adjustment
	 *
	 * @dataProvider int_ranges
	 * @param string $option  Option.
	 * @param string $section Section.
	 * @param int    $min     Minimum.
	 * @param int    $max     Maximum.
	 * @return void
	 */
	public function test_ints_clamp_and_report_adjustments( string $option, string $section, int $min, int $max ): void {
		$this->ensure_cf7_active( $section );
		$inside = (int) \floor( ( $min + $max ) / 2 );

		$result = $this->form( array( $option => (string) $inside ), $section );
		$this->assertSame( $inside, (int) \get_option( $option ) );
		$this->assertArrayNotHasKey( $option, $result->adjusted, 'A value inside the range is not an adjustment.' );

		$result = $this->form( array( $option => (string) ( $min - 1 ) ), $section );
		$this->assertSame( $min, (int) \get_option( $option ) );
		$this->assertSame( $min - 1, $result->adjusted[ $option ]['submitted'] );
		$this->assertSame( $min, $result->adjusted[ $option ]['saved'] );

		$result = $this->form( array( $option => (string) ( $max + 1 ) ), $section );
		$this->assertSame( $max, (int) \get_option( $option ) );
		$this->assertSame( $max + 1, $result->adjusted[ $option ]['submitted'] );

		$result = $this->form( array( $option => 'abc' ), $section );
		$this->assertSame( $min, (int) \get_option( $option ), 'A non-numeric value falls to the minimum, as before.' );
		$this->assertArrayHasKey( $option, $result->adjusted );

		$this->assertSame( $min, $result->saved[ $option ] );
	}

	/**
	 * The GraphQL timeout never exceeds the PHP execution limit
	 *
	 * @return void
	 */
	public function test_graphql_timeout_is_capped_by_the_php_limit(): void {
		$php_limit = (int) \ini_get( 'max_execution_time' );
		$expected  = $php_limit > 0 ? $php_limit : 30;

		$this->form( array( 'silver_assist_graphql_query_timeout' => '9999' ), 'graphql' );

		$this->assertSame( $expected, (int) \get_option( 'silver_assist_graphql_query_timeout' ) );
		$this->assertSame( $expected, SettingsRegistry::graphql_timeout_max() );
	}

	/**
	 * A tag-laden number is sanitized before it is read
	 *
	 * @return void
	 */
	public function test_int_input_is_sanitized(): void {
		$this->form( array( 'silver_assist_login_attempts' => '<script>alert("xss")</script>7' ), 'login' );

		$this->assertSame( 7, \get_option( 'silver_assist_login_attempts' ) );
	}

	/**
	 * Input is unslashed exactly once, here
	 *
	 * @return void
	 */
	public function test_input_is_unslashed(): void {
		$this->form( array( 'silver_assist_login_branding_logo_url' => 'https://example.com/a\\b.png' ), 'login_branding' );

		$this->assertSame( 'https://example.com/ab.png', \get_option( 'silver_assist_login_branding_logo_url' ) );
	}

	/**
	 * In a section save a bool that is absent is saved as off, a bool that is present as on
	 *
	 * @return void
	 */
	public function test_form_mode_absent_bools_of_the_section_are_saved_as_off(): void {
		\update_option( 'silver_assist_bot_protection', 1 );
		\update_option( 'silver_assist_password_strength_enforcement', 1 );
		\update_option( 'silver_assist_rest_rate_limiting_enabled', 1 );

		$result = $this->form( array( 'silver_assist_password_strength_enforcement' => '1' ), 'login' );

		$this->assertSame( 1, (int) \get_option( 'silver_assist_password_strength_enforcement' ) );
		$this->assertSame( 0, (int) \get_option( 'silver_assist_bot_protection' ) );
		$this->assertSame( 1, (int) \get_option( 'silver_assist_rest_rate_limiting_enabled' ), 'Another section is untouched.' );
		$this->assertArrayHasKey( 'silver_assist_bot_protection', $result->saved );
	}

	/**
	 * In auto-save only submitted keys are touched, and only "1" means on
	 *
	 * @return void
	 */
	public function test_autosave_mode_touches_only_submitted_keys(): void {
		\update_option( 'silver_assist_bot_protection', 1 );
		\update_option( 'silver_assist_password_strength_enforcement', 1 );

		$this->autosave( array( 'silver_assist_password_strength_enforcement' => '' ) );
		$this->assertSame( 0, (int) \get_option( 'silver_assist_password_strength_enforcement' ), 'An empty string is an unchecked box.' );
		$this->assertSame( 1, (int) \get_option( 'silver_assist_bot_protection' ), 'A key that was not submitted is untouched.' );

		$this->autosave( array( 'silver_assist_password_strength_enforcement' => '1' ) );
		$this->assertSame( 1, (int) \get_option( 'silver_assist_password_strength_enforcement' ) );

		$this->autosave( array( 'silver_assist_password_strength_enforcement' => 'yes' ) );
		$this->assertSame( 0, (int) \get_option( 'silver_assist_password_strength_enforcement' ), 'Anything but "1" is off.' );
	}

	/**
	 * Unknown keys and keys of another section are ignored in a section save
	 *
	 * @return void
	 */
	public function test_unknown_and_foreign_keys_are_ignored_in_form_mode(): void {
		$result = $this->form(
			array(
				'silver_assist_login_attempts'          => '9',
				'silver_assist_rest_rate_limit_window'  => '99',
				'silver_assist_not_an_option'           => 'x',
				'settings_section'                      => 'login',
			),
			'login'
		);

		$this->assertSame( 9, (int) \get_option( 'silver_assist_login_attempts' ) );
		$this->assertFalse( \get_option( 'silver_assist_rest_rate_limit_window' ) );
		$this->assertContains( 'silver_assist_rest_rate_limit_window', $result->ignored );
		$this->assertContains( 'silver_assist_not_an_option', $result->ignored );
		$this->assertContains( 'settings_section', $result->ignored );
		$this->assertNotContains( 'silver_assist_login_attempts', $result->ignored );
	}

	/**
	 * Auto-save accepts only the eligible options and reports the rest as ignored
	 *
	 * @return void
	 */
	public function test_autosave_ignores_ineligible_options(): void {
		$result = $this->autosave(
			array(
				'silver_assist_login_attempts'                 => '8',
				'silver_assist_rest_rate_limit_requests'       => '500',
				'silver_assist_login_branding_logo_url'        => 'https://example.com/l.png',
				'silver_assist_admin_hide_path'                => 'my-private-door',
				'silver_assist_graphql_service_user_id'        => '1',
				'silver_assist_graphql_query_timeout'          => '5',
				'silver_assist_cf7_rate_limit'                 => '4',
				'silver_assist_nonsense'                       => '1',
			)
		);

		$this->assertSame( array( 'silver_assist_login_attempts' ), \array_keys( $result->saved ) );
		$this->assertSame( 1, $result->saved_count() );
		$this->assertEqualsCanonicalizing(
			array(
				'silver_assist_rest_rate_limit_requests',
				'silver_assist_login_branding_logo_url',
				'silver_assist_admin_hide_path',
				'silver_assist_graphql_service_user_id',
				'silver_assist_graphql_query_timeout',
				'silver_assist_cf7_rate_limit',
				'silver_assist_nonsense',
			),
			$result->ignored
		);
		$this->assertFalse( \get_option( 'silver_assist_rest_rate_limit_requests' ) );
		$this->assertFalse( \get_option( 'silver_assist_admin_hide_path' ) );
	}

	/**
	 * Auto-save of nothing eligible saves nothing
	 *
	 * @return void
	 */
	public function test_autosave_with_nothing_eligible_saves_nothing(): void {
		$result = $this->autosave( array( 'silver_assist_rest_rate_limit_window' => '60' ) );

		$this->assertSame( 0, $result->saved_count() );
		$this->assertSame( array(), $result->saved );
	}

	/**
	 * A user id that does not exist is saved as 0 and reported
	 *
	 * @return void
	 */
	public function test_user_id_must_exist(): void {
		$user = $this->factory()->user->create( array( 'role' => 'subscriber' ) );

		$result = $this->form( array( 'silver_assist_graphql_service_user_id' => (string) $user ), 'graphql_auth' );
		$this->assertSame( $user, (int) \get_option( 'silver_assist_graphql_service_user_id' ) );
		$this->assertArrayNotHasKey( 'silver_assist_graphql_service_user_id', $result->adjusted );

		$result = $this->form( array( 'silver_assist_graphql_service_user_id' => '999999' ), 'graphql_auth' );
		$this->assertSame( 0, (int) \get_option( 'silver_assist_graphql_service_user_id' ) );
		$this->assertSame( 999999, $result->adjusted['silver_assist_graphql_service_user_id']['submitted'] );

		$this->form( array( 'silver_assist_graphql_service_user_id' => '-' . $user ), 'graphql_auth' );
		$this->assertSame( $user, (int) \get_option( 'silver_assist_graphql_service_user_id' ), 'A sign is dropped, as absint() always did.' );
	}

	/**
	 * URL and color are sanitized
	 *
	 * @return void
	 */
	public function test_url_and_hex_color_are_sanitized(): void {
		$this->form(
			array(
				'silver_assist_login_branding_logo_url' => 'javascript:alert(1)',
				'silver_assist_login_branding_bg_color' => 'red',
			),
			'login_branding'
		);
		$this->assertSame( '', \get_option( 'silver_assist_login_branding_logo_url' ) );
		$this->assertSame( '', \get_option( 'silver_assist_login_branding_bg_color' ) );

		$result = $this->form(
			array(
				'silver_assist_login_branding_logo_url' => ' https://example.com/logo.png ',
				'silver_assist_login_branding_bg_color' => '#0A1628',
			),
			'login_branding'
		);
		$this->assertSame( 'https://example.com/logo.png', \get_option( 'silver_assist_login_branding_logo_url' ) );
		$this->assertSame( '#0A1628', \get_option( 'silver_assist_login_branding_bg_color' ) );
		$this->assertSame( array(), $result->adjusted );
	}

	/**
	 * An invalid admin path is rejected and reported, the stored one stays (#153)
	 *
	 * @return void
	 */
	public function test_invalid_admin_path_is_rejected_and_reported(): void {
		$result = $this->form( array( 'silver_assist_admin_hide_path' => 'my-private-door' ), 'admin_hide' );
		$this->assertSame( 'my-private-door', \get_option( 'silver_assist_admin_hide_path' ) );
		$this->assertSame( array(), $result->adjusted );
		$this->assertSame( array(), $result->errors );

		foreach ( array( 'wp-admin', 'ab', '', '!!!', 'login' ) as $bad ) {
			$result = $this->form( array( 'silver_assist_admin_hide_path' => $bad ), 'admin_hide' );
			$this->assertSame( 'my-private-door', \get_option( 'silver_assist_admin_hide_path' ), "'{$bad}' must not replace the stored path." );
			$this->assertArrayHasKey( 'silver_assist_admin_hide_path', $result->errors, "'{$bad}' must be reported." );
			$this->assertArrayNotHasKey( 'silver_assist_admin_hide_path', $result->saved );
		}
	}

	/**
	 * A path that is not submitted is left alone
	 *
	 * @return void
	 */
	public function test_admin_path_not_submitted_is_untouched(): void {
		\update_option( 'silver_assist_admin_hide_path', 'my-private-door' );

		$this->form( array( 'silver_assist_admin_hide_enabled' => '1' ), 'admin_hide' );

		$this->assertSame( 'my-private-door', \get_option( 'silver_assist_admin_hide_path' ) );
	}

	/**
	 * Rewrite rules are flushed when an admin hide save leaves hiding enabled
	 *
	 * @return void
	 */
	public function test_admin_hide_form_save_flushes_rewrite_rules_when_enabled(): void {
		\update_option( 'rewrite_rules', 'a:0:{}' );
		$this->form( array( 'silver_assist_admin_hide_path' => 'my-private-door' ), 'admin_hide' );
		$this->assertSame( 0, (int) \get_option( 'silver_assist_admin_hide_enabled' ) );
		$this->assertSame( 'a:0:{}', \get_option( 'rewrite_rules' ), 'No flush while hiding is off.' );

		$this->form(
			array(
				'silver_assist_admin_hide_enabled' => '1',
				'silver_assist_admin_hide_path'    => 'my-private-door',
			),
			'admin_hide'
		);
		$this->assertNotSame( 'a:0:{}', \get_option( 'rewrite_rules' ), 'Rewrite rules were flushed.' );
	}

	/**
	 * Section rules: unknown, empty and "all" write nothing in form mode
	 *
	 * @return void
	 */
	public function test_form_mode_requires_a_known_section(): void {
		foreach ( array( '', 'all', 'nope' ) as $section ) {
			$result = $this->form(
				array(
					'silver_assist_login_attempts' => '9',
					'silver_assist_bot_protection' => '1',
				),
				$section
			);

			$this->assertSame( 0, $result->saved_count() );
			$this->assertArrayHasKey( 'section', $result->errors );
			$this->assertFalse( \get_option( 'silver_assist_login_attempts' ) );
			$this->assertFalse( \get_option( 'silver_assist_bot_protection' ) );
		}
	}

	/**
	 * An unknown mode writes nothing
	 *
	 * @return void
	 */
	public function test_unknown_mode_writes_nothing(): void {
		$result = $this->saver->save( array( 'silver_assist_login_attempts' => '9' ), 'login', 'whatever' );

		$this->assertSame( 0, $result->saved_count() );
		$this->assertArrayHasKey( 'mode', $result->errors );
		$this->assertFalse( \get_option( 'silver_assist_login_attempts' ) );
	}

	/**
	 * Array values are rejected, not cast
	 *
	 * @return void
	 */
	public function test_non_scalar_values_are_rejected(): void {
		$result = $this->form( array( 'silver_assist_login_attempts' => array( '9' ) ), 'login' );

		$this->assertArrayHasKey( 'silver_assist_login_attempts', $result->errors );
		$this->assertFalse( \get_option( 'silver_assist_login_attempts' ) );
	}

	/**
	 * The CF7 section writes nothing while Contact Form 7 is not active
	 *
	 * @return void
	 */
	public function test_cf7_section_needs_contact_form_7(): void {
		if ( \class_exists( 'WPCF7' ) ) {
			$this->markTestSkipped( 'A WPCF7 stub is loaded in this process.' );
		}

		$result = $this->form( array( 'silver_assist_cf7_rate_limit' => '4' ), 'cf7' );

		$this->assertSame( 0, $result->saved_count() );
		$this->assertArrayHasKey( 'section', $result->errors );
		$this->assertFalse( \get_option( 'silver_assist_cf7_rate_limit' ) );
	}

	/**
	 * The CF7 section is only writable while Contact Form 7 is active
	 *
	 * @param string $section Section under test.
	 * @return void
	 */
	private function ensure_cf7_active( string $section ): void {
		if ( 'cf7' !== $section || \class_exists( 'WPCF7' ) ) {
			return;
		}
		if ( ! \defined( 'WPCF7_VERSION' ) ) {
			\define( 'WPCF7_VERSION', '5.8' );
		}
		eval( 'class WPCF7 {}' ); // phpcs:ignore Squiz.PHP.Eval.Discouraged -- Test-only CF7 class stub; excluded from the eval() security scan via --exclude-dir=tests.
	}
}
