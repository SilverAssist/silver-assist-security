<?php
/**
 * CF7 protection options tests
 *
 * The honeypot switch, the minimum submission time and the manual block duration are saved on the
 * Form Protection tab and must change what the plugin does (#178). Every submit goes through the real
 * `wpcf7_validate` filter, every save through the real SettingsSaver.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Admin\Settings\SaveResult;
use SilverAssist\Security\Admin\Settings\SettingsRegistry;
use SilverAssist\Security\Admin\Settings\SettingsSaver;
use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Security\ContactForm7Integration;
use SilverAssist\Security\Security\IPBlacklist;
use WP_UnitTestCase;

/**
 * Honeypot, submission delay and block duration, end to end
 */
class CF7ProtectionOptionsTest extends WP_UnitTestCase {

	/**
	 * Options that were removed because nothing read them
	 *
	 * @var string[]
	 */
	private const DEAD_OPTIONS = array(
		'silver_assist_obsolete_browser_detection',
		'silver_assist_sql_injection_detection',
		'silver_assist_cf7_spam_threshold',
		'silver_assist_cf7_auto_block_bots',
	);

	/**
	 * Previous REMOTE_ADDR and user agent
	 *
	 * @var array<string, mixed>
	 */
	private array $server = array();

	/**
	 * Stub CF7, clean options and counters, modern client
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();

		if ( ! \defined( 'WPCF7_VERSION' ) ) {
			\define( 'WPCF7_VERSION', '5.8' );
		}
		if ( ! \class_exists( 'WPCF7' ) ) {
			eval( 'class WPCF7 {}' ); // phpcs:ignore Squiz.PHP.Eval.Discouraged -- Test-only CF7 class stub.
		}

		foreach ( array( 'cf7_protection_enabled', 'cf7_rate_limit', 'cf7_rate_window', 'cf7_honeypot_enabled', 'cf7_submission_delay', 'cf7_ip_block_duration' ) as $name ) {
			\delete_option( 'silver_assist_' . $name );
		}
		$this->clean_counters();

		$this->server               = array(
			'REMOTE_ADDR'     => $_SERVER['REMOTE_ADDR'] ?? null,
			'HTTP_USER_AGENT' => $_SERVER['HTTP_USER_AGENT'] ?? null,
		);
		$_SERVER['REMOTE_ADDR']     = '203.0.113.70';
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
		$_POST                      = array();
	}

	/**
	 * Restore the request
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		foreach ( $this->server as $key => $value ) {
			if ( null === $value ) {
				unset( $_SERVER[ $key ] );
			} else {
				$_SERVER[ $key ] = $value;
			}
		}
		$_POST = array();
		$this->clean_counters();
		\remove_all_filters( 'wpcf7_validate' );
		\remove_all_filters( 'wpcf7_form_elements' );
		parent::tearDown();
	}

	/**
	 * Delete the form rate counters
	 *
	 * @return void
	 */
	private function clean_counters(): void {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_%form\_rate\_%' OR option_name LIKE '\_transient\_timeout\_%form\_rate\_%'" );
		\wp_cache_flush();
	}

	/**
	 * Save the Form Protection tab through the real saver, then wire the integration like a request would
	 *
	 * @param array<string, string> $values Posted values besides the protection toggle.
	 * @return SaveResult
	 */
	private function save_and_boot( array $values ): SaveResult {
		$result = ( new SettingsSaver() )->save(
			\array_merge( array( 'silver_assist_cf7_protection_enabled' => '1' ), $values ),
			'cf7'
		);

		\remove_all_filters( 'wpcf7_validate' );
		\remove_all_filters( 'wpcf7_form_elements' );
		new ContactForm7Integration();

		return $result;
	}

	/**
	 * Render a form the way CF7 does and read the hidden timing field the plugin put in it
	 *
	 * @return string The field value, empty when the plugin added none.
	 */
	private function render_timing_token(): string {
		$html = (string) \apply_filters( 'wpcf7_form_elements', '<input type="submit" value="Send" />' );

		return 1 === \preg_match( '/name="silver_form_ts"[^>]*value="([^"]*)"/', $html, $matches ) ? $matches[1] : '';
	}

	/**
	 * Submit once through the real wpcf7_validate filter
	 *
	 * @return bool True when the submission passed validation.
	 */
	private function submit(): bool {
		$result = new class() {
			/**
			 * Whether a field was invalidated
			 *
			 * @var bool
			 */
			public bool $invalid = false;

			/**
			 * CF7 result API
			 *
			 * @param string $name    Field.
			 * @param string $message Message.
			 * @return void
			 */
			public function invalidate( $name, $message ): void {
				unset( $name, $message );
				$this->invalid = true;
			}
		};

		\apply_filters( 'wpcf7_validate', $result, array() );
		return ! $result->invalid;
	}

	/**
	 * The three options are registered with a field, a range and a default inside the range
	 *
	 * @return void
	 */
	public function test_live_options_are_registered_with_a_range(): void {
		foreach ( array( 'silver_assist_cf7_honeypot_enabled', 'silver_assist_cf7_submission_delay', 'silver_assist_cf7_ip_block_duration' ) as $option ) {
			$declaration = SettingsRegistry::get( $option );
			$this->assertNotNull( $declaration, "{$option} must be registered" );
			$this->assertSame( SettingsRegistry::SECTION_CF7, $declaration['section'] );
			$this->assertTrue( $declaration['ui'], "{$option} has a field on the Form Protection tab" );
		}

		$delay = SettingsRegistry::get( 'silver_assist_cf7_submission_delay' );
		$this->assertSame( 0, $delay['min'], 'Zero turns the minimum time off' );
		$this->assertSame( 10000, $delay['max'] );

		$duration = SettingsRegistry::get( 'silver_assist_cf7_ip_block_duration' );
		$this->assertSame( 60, $duration['min'] );
		$this->assertSame( 86400, $duration['max'] );

		$defaults = DefaultConfig::get_defaults();
		$this->assertGreaterThanOrEqual( $delay['min'], $defaults['silver_assist_cf7_submission_delay'] );
		$this->assertLessThanOrEqual( $delay['max'], $defaults['silver_assist_cf7_submission_delay'] );
		$this->assertGreaterThanOrEqual( $duration['min'], $defaults['silver_assist_cf7_ip_block_duration'] );
		$this->assertLessThanOrEqual( $duration['max'], $defaults['silver_assist_cf7_ip_block_duration'] );
	}

	/**
	 * The options nothing read are gone from the defaults
	 *
	 * @return void
	 */
	public function test_dead_options_are_not_defaults_any_more(): void {
		$defaults = DefaultConfig::get_defaults();
		foreach ( self::DEAD_OPTIONS as $option ) {
			$this->assertArrayNotHasKey( $option, $defaults, "{$option} promised a switch that did nothing" );
			$this->assertContains( $option, DefaultConfig::get_legacy_option_names(), "{$option} stays in the legacy cleanup so uninstall removes it" );
		}
	}

	/**
	 * The migration removes the dead rows an earlier version stored
	 *
	 * @return void
	 */
	public function test_migration_drops_the_dead_options(): void {
		foreach ( self::DEAD_OPTIONS as $option ) {
			\add_option( $option, 1 );
		}

		DefaultConfig::migrate_legacy_options();

		foreach ( self::DEAD_OPTIONS as $option ) {
			$this->assertFalse( \get_option( $option ), "{$option} is deleted" );
		}
	}

	/**
	 * Values saved through the real saver are clamped to the registered ranges
	 *
	 * @return void
	 */
	public function test_saver_clamps_the_live_options(): void {
		$result = ( new SettingsSaver() )->save(
			array(
				'silver_assist_cf7_protection_enabled' => '1',
				'silver_assist_cf7_honeypot_enabled'   => '1',
				'silver_assist_cf7_submission_delay'   => '999999',
				'silver_assist_cf7_ip_block_duration'  => '5',
			),
			'cf7'
		);

		$this->assertSame( 10000, (int) \get_option( 'silver_assist_cf7_submission_delay' ) );
		$this->assertSame( 60, (int) \get_option( 'silver_assist_cf7_ip_block_duration' ) );
		$this->assertSame( 1, (int) \get_option( 'silver_assist_cf7_honeypot_enabled' ) );
		$this->assertArrayHasKey( 'silver_assist_cf7_submission_delay', $result->adjusted, 'The admin is told the value was adjusted' );
		$this->assertArrayHasKey( 'silver_assist_cf7_ip_block_duration', $result->adjusted );
	}

	/**
	 * A field filled in the honeypot blocks the submission while the honeypot is on
	 *
	 * @return void
	 */
	public function test_honeypot_on_blocks_a_filled_honeypot(): void {
		$this->save_and_boot( array( 'silver_assist_cf7_honeypot_enabled' => '1' ) );

		$_POST = array( 'silver_honeypot_field' => 'http://spam.example' );
		$this->assertFalse( $this->submit() );

		$_POST = array();
		$this->assertTrue( $this->submit(), 'An empty honeypot passes' );
	}

	/**
	 * With the honeypot off the field is neither injected nor enforced
	 *
	 * @return void
	 */
	public function test_honeypot_off_lets_the_field_pass_and_is_not_injected(): void {
		$this->save_and_boot( array() ); // The honeypot checkbox is absent: saved as off.
		$this->assertSame( 0, (int) \get_option( 'silver_assist_cf7_honeypot_enabled' ) );

		$_POST = array( 'silver_honeypot_field' => 'http://spam.example' );
		$this->assertTrue( $this->submit() );

		$html = (string) \apply_filters( 'wpcf7_form_elements', '<input type="submit" value="Send" />' );
		$this->assertStringNotContainsString( 'silver_honeypot_field', $html );
	}

	/**
	 * A form submitted sooner than the saved delay is blocked, later passes (milliseconds)
	 *
	 * @return void
	 */
	public function test_submission_delay_is_honored_in_milliseconds(): void {
		$this->save_and_boot( array( 'silver_assist_cf7_submission_delay' => '1500' ) );
		$token = $this->render_timing_token();
		$this->assertNotSame( '', $token, 'The rendered form carries the timing field' );

		usleep( 600000 );
		$_POST = array( 'silver_form_ts' => $token );
		$this->assertFalse( $this->submit(), '0.6s is under the saved 1500 ms' );

		$this->save_and_boot( array( 'silver_assist_cf7_submission_delay' => '500' ) );
		$token = $this->render_timing_token();
		usleep( 600000 );
		$_POST = array( 'silver_form_ts' => $token );
		$this->assertTrue( $this->submit(), '0.6s is over the saved 500 ms' );
	}

	/**
	 * A delay of zero turns the timing check off
	 *
	 * @return void
	 */
	public function test_zero_delay_disables_the_timing_check(): void {
		$this->save_and_boot( array( 'silver_assist_cf7_submission_delay' => '0' ) );
		$token = $this->render_timing_token();

		$_POST = array( 'silver_form_ts' => $token );
		$this->assertTrue( $this->submit(), 'An instant submit passes with the delay off' );
	}

	/**
	 * A forged or missing timing field never blocks a visitor (cached pages, no field)
	 *
	 * @return void
	 */
	public function test_unsigned_or_missing_timing_field_is_ignored(): void {
		$this->save_and_boot( array( 'silver_assist_cf7_submission_delay' => '10000' ) );

		$_POST = array( 'silver_form_ts' => sprintf( '%.3f.%s', microtime( true ), 'forged' ) );
		$this->assertTrue( $this->submit(), 'A forged token is ignored, not trusted' );

		$_POST = array();
		$this->assertTrue( $this->submit(), 'A submission without the field passes' );
	}

	/**
	 * The manual block lasts the configured number of seconds
	 *
	 * @return void
	 */
	public function test_manual_block_uses_the_configured_duration(): void {
		$this->save_and_boot( array( 'silver_assist_cf7_ip_block_duration' => '1800' ) );

		$blacklist = IPBlacklist::get_instance();
		$this->assertTrue( $blacklist->add_to_cf7_blacklist( '198.51.100.7', 'Manual test', 'cf7_manual' ) );
		$this->assertArrayHasKey( '198.51.100.7', $blacklist->get_cf7_blocked_ips() );

		$key = $this->block_key( $blacklist, '198.51.100.7' );
		$data = \get_transient( $key );
		$this->assertIsArray( $data );
		$this->assertSame( 1800, (int) $data['duration'] );

		$remaining = (int) \get_option( '_transient_timeout_' . $key ) - time();
		$this->assertGreaterThan( 1700, $remaining );
		$this->assertLessThanOrEqual( 1800, $remaining );

		$blacklist->remove_from_blacklist( '198.51.100.7' );
	}

	/**
	 * Transient name of an IP block
	 *
	 * @param IPBlacklist $blacklist Blacklist.
	 * @param string      $ip        IP address.
	 * @return string
	 */
	private function block_key( IPBlacklist $blacklist, string $ip ): string {
		$method = new \ReflectionMethod( $blacklist, 'blacklist_key' );
		$method->setAccessible( true );

		return (string) $method->invoke( $blacklist, $ip );
	}
}
