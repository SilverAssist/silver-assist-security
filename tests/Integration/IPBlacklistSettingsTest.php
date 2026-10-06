<?php
/**
 * IP blacklist settings behavior tests
 *
 * The admin shows an "IP Blacklist" toggle, and saved settings must change what the
 * blacklist does (#147). Also guards the options a settings save must not touch.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use SilverAssist\Security\Admin\Settings\SettingsHandler;
use SilverAssist\Security\Security\IPBlacklist;
use WP_UnitTestCase;

/**
 * Test that the IP blacklist settings are honored
 */
class IPBlacklistSettingsTest extends WP_UnitTestCase {

	/**
	 * IP used by the tests
	 *
	 * @var string
	 */
	private string $ip = '198.51.100.77';

	/**
	 * Settings handler
	 *
	 * @var SettingsHandler
	 */
	private SettingsHandler $handler;

	/**
	 * Prepare an administrator and clean state
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();
		\wp_set_current_user( $this->factory()->user->create( array( 'role' => 'administrator' ) ) );
		$this->handler = new SettingsHandler();
		\delete_transient( 'ip_blacklist_' . md5( $this->ip ) );
		\delete_transient( 'ip_violations_' . md5( $this->ip ) );
		\delete_option( 'silver_assist_ip_blacklist_enabled' );
		\delete_option( 'silver_assist_ip_blacklist_threshold' );
	}

	/**
	 * Clean state
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		\delete_transient( 'ip_blacklist_' . md5( $this->ip ) );
		\delete_transient( 'ip_violations_' . md5( $this->ip ) );
		$_POST = array();
		parent::tearDown();
	}

	/**
	 * Submit the settings form the way the admin does
	 *
	 * @param array $fields Form fields.
	 * @return void
	 */
	private function submit( array $fields ): void {
		$_POST = array_merge(
			$fields,
			array(
				'save_silver_assist_security' => '1',
				'_wpnonce'                    => \wp_create_nonce( 'silver_assist_security_settings' ),
			)
		);
		$this->handler->save_security_settings();
	}

	/**
	 * Record several violations for the test IP
	 *
	 * @param int $count Number of violations.
	 * @return void
	 */
	private function violate( int $count ): void {
		$blacklist = new IPBlacklist();
		for ( $i = 0; $i < $count; $i++ ) {
			$blacklist->record_violation( $this->ip, 'test_violation' );
		}
	}

	/**
	 * Out of the box repeat offenders are blacklisted at the default threshold
	 *
	 * @return void
	 */
	public function test_repeat_offenders_are_blacklisted_by_default(): void {
		$this->violate( 4 );
		$this->assertFalse( ( new IPBlacklist() )->is_blacklisted( $this->ip ) );

		$this->violate( 1 );
		$this->assertTrue( ( new IPBlacklist() )->is_blacklisted( $this->ip ), 'The 5th violation should blacklist the IP.' );
	}

	/**
	 * The admin toggle turns automatic blacklisting off
	 *
	 * @return void
	 */
	public function test_turning_the_toggle_off_stops_automatic_blacklisting(): void {
		\update_option( 'silver_assist_ip_blacklist_enabled', 0 );

		$this->violate( 12 );

		$this->assertFalse( ( new IPBlacklist() )->is_blacklisted( $this->ip ), 'Automatic blacklisting is off, so violations must not blacklist.' );
	}

	/**
	 * A manual block still applies when automatic blacklisting is off
	 *
	 * @return void
	 */
	public function test_manual_blocks_still_apply_when_automatic_blacklisting_is_off(): void {
		\update_option( 'silver_assist_ip_blacklist_enabled', 0 );

		( new IPBlacklist() )->add_to_blacklist( $this->ip, 'Manual block', HOUR_IN_SECONDS );

		$this->assertTrue( ( new IPBlacklist() )->is_blacklisted( $this->ip ) );
	}

	/**
	 * The dashboard reports the real default, which is on
	 *
	 * @return void
	 */
	public function test_dashboard_reports_automatic_blacklisting_as_enabled_by_default(): void {
		$status = ( new SecurityDataProvider() )->get_security_status();

		$this->assertTrue( $status['general_security']['ip_blacklist_enabled'] );
	}

	/**
	 * The violation threshold saved by the settings handler is the one the blacklist uses
	 *
	 * @return void
	 */
	public function test_saved_threshold_is_the_one_the_blacklist_uses(): void {
		$this->submit( array( 'silver_assist_ip_blacklist_threshold' => '3' ) );

		$this->assertSame( 3, (int) \get_option( 'silver_assist_ip_blacklist_threshold' ) );

		$this->violate( 2 );
		$this->assertFalse( ( new IPBlacklist() )->is_blacklisted( $this->ip ) );

		$this->violate( 1 );
		$this->assertTrue( ( new IPBlacklist() )->is_blacklisted( $this->ip ), 'The 3rd violation should blacklist the IP when the threshold is 3.' );
	}

	/**
	 * A settings save must not change options its form does not render
	 *
	 * The honeypot, timing, obsolete browser and SQL injection options have no field in the
	 * settings screen, so a save that carries none of them must leave them alone.
	 *
	 * @return void
	 */
	public function test_saving_settings_does_not_touch_options_without_a_field(): void {
		\update_option( 'silver_assist_cf7_honeypot_enabled', 1 );

		$this->submit( array( 'silver_assist_login_attempts' => '5' ) );

		$this->assertSame( 1, (int) \get_option( 'silver_assist_cf7_honeypot_enabled' ), 'Saving the settings form must not turn the CF7 honeypot off.' );
		$this->assertFalse( \get_option( 'silver_assist_cf7_timing_protection' ), 'Options nothing reads are no longer written.' );
		$this->assertFalse( \get_option( 'silver_assist_cf7_obsolete_browser_blocking' ) );
		$this->assertFalse( \get_option( 'silver_assist_cf7_sql_injection_protection' ) );
	}

	/**
	 * A save from the login form does not switch the IP blacklist toggle off
	 *
	 * @return void
	 */
	public function test_saving_another_section_keeps_the_ip_toggle(): void {
		\update_option( 'silver_assist_ip_blacklist_enabled', 1 );

		$this->submit( array( 'silver_assist_login_attempts' => '5' ) );

		$this->assertSame( 1, (int) \get_option( 'silver_assist_ip_blacklist_enabled' ) );
	}
}
