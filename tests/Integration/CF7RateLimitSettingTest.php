<?php
/**
 * CF7 rate limit setting tests
 *
 * The Form Protection tab saves `silver_assist_cf7_rate_limit` and `silver_assist_cf7_rate_window`;
 * enforcement, the dashboard and the getters must read those same options.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use SilverAssist\Security\Admin\Settings\SettingsSaver;
use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\Security\ContactForm7Integration;
use SilverAssist\Security\Security\FormProtection;
use WP_UnitTestCase;

/**
 * Single option governing the CF7 submit rate limit
 */
class CF7RateLimitSettingTest extends WP_UnitTestCase {

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

		foreach ( array( 'cf7_rate_limit', 'cf7_rate_window', 'cf7_protection_enabled', 'form_rate_limit', 'form_rate_window', 'form_protection_enabled' ) as $name ) {
			\delete_option( 'silver_assist_' . $name );
		}
		$this->clean_counters();

		$this->server               = array(
			'REMOTE_ADDR'     => $_SERVER['REMOTE_ADDR'] ?? null,
			'HTTP_USER_AGENT' => $_SERVER['HTTP_USER_AGENT'] ?? null,
		);
		$_SERVER['REMOTE_ADDR']     = '203.0.113.50';
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
	 * Save the Form Protection tab through the real saver
	 *
	 * @param array<string, string> $values Extra posted values.
	 * @return void
	 */
	private function save_cf7_tab( array $values ): void {
		( new SettingsSaver() )->save(
			\array_merge( array( 'silver_assist_cf7_protection_enabled' => '1' ), $values ),
			'cf7'
		);
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
	 * The limit saved on the Form Protection tab is the one enforced
	 *
	 * @return void
	 */
	public function test_saved_cf7_rate_limit_is_enforced(): void {
		$this->save_cf7_tab( array( 'silver_assist_cf7_rate_limit' => '4' ) );
		$this->assertSame( 4, (int) \get_option( 'silver_assist_cf7_rate_limit' ) );

		\remove_all_filters( 'wpcf7_validate' );
		new ContactForm7Integration();

		for ( $i = 1; $i <= 4; $i++ ) {
			$this->assertTrue( $this->submit(), "Submission {$i} is within the saved limit of 4" );
		}
		$this->assertFalse( $this->submit(), 'Submission 5 exceeds the saved limit of 4' );
	}

	/**
	 * The window saved on the tab is the one the counter uses
	 *
	 * @return void
	 */
	public function test_saved_cf7_rate_window_is_read(): void {
		$this->save_cf7_tab( array( 'silver_assist_cf7_rate_window' => '120' ) );

		$this->assertSame( 120, ( new FormProtection() )->get_rate_window() );
	}

	/**
	 * The getters and the dashboard report the saved limit
	 *
	 * @return void
	 */
	public function test_getters_and_dashboard_follow_the_saved_limit(): void {
		$this->save_cf7_tab( array( 'silver_assist_cf7_rate_limit' => '7' ) );

		$this->assertSame( 7, ( new FormProtection() )->get_rate_limit() );

		$data = ( new SecurityDataProvider() )->get_security_status();
		$this->assertSame( 7, $data['form_protection']['rate_limit'] );
		$this->assertTrue( $data['form_protection']['enabled'] );

		$this->save_cf7_tab( array( 'silver_assist_cf7_protection_enabled' => '' ) );
		$data = ( new SecurityDataProvider() )->get_security_status();
		$this->assertFalse( $data['form_protection']['enabled'], 'The dashboard follows the CF7 protection toggle' );
	}

	/**
	 * A legacy value is adopted once when nothing was saved
	 *
	 * @return void
	 */
	public function test_legacy_value_is_migrated_once(): void {
		\add_option( 'silver_assist_form_rate_limit', 6 );
		\add_option( 'silver_assist_form_rate_window', 90 );

		DefaultConfig::migrate_legacy_options();

		$this->assertSame( 6, (int) \get_option( 'silver_assist_cf7_rate_limit' ) );
		$this->assertSame( 90, (int) \get_option( 'silver_assist_cf7_rate_window' ) );
		$this->assertFalse( \get_option( 'silver_assist_form_rate_limit' ) );
		$this->assertFalse( \get_option( 'silver_assist_form_rate_window' ) );

		// Idempotent, and a later value of the admin is never touched.
		\update_option( 'silver_assist_cf7_rate_limit', 3 );
		DefaultConfig::migrate_legacy_options();
		$this->assertSame( 3, (int) \get_option( 'silver_assist_cf7_rate_limit' ) );
	}

	/**
	 * A value the admin already saved wins over the legacy one
	 *
	 * @return void
	 */
	public function test_migration_never_clobbers_a_saved_value(): void {
		\update_option( 'silver_assist_cf7_rate_limit', 5 );
		\add_option( 'silver_assist_form_rate_limit', 9 );

		DefaultConfig::migrate_legacy_options();

		$this->assertSame( 5, (int) \get_option( 'silver_assist_cf7_rate_limit' ) );
		$this->assertFalse( \get_option( 'silver_assist_form_rate_limit' ) );
	}

	/**
	 * A migrated legacy value outside the saver range is clamped
	 *
	 * @return void
	 */
	public function test_migrated_value_is_clamped_to_the_saver_range(): void {
		\add_option( 'silver_assist_form_rate_limit', 500 );
		\add_option( 'silver_assist_form_rate_window', 5 );

		DefaultConfig::migrate_legacy_options();

		$this->assertSame( 10, (int) \get_option( 'silver_assist_cf7_rate_limit' ) );
		$this->assertSame( 30, (int) \get_option( 'silver_assist_cf7_rate_window' ) );
	}

	/**
	 * Accepted submissions never extend the window (fixed window, like the other limiters)
	 *
	 * @return void
	 */
	public function test_accepted_submissions_do_not_extend_the_window(): void {
		global $wpdb;

		$this->save_cf7_tab( array( 'silver_assist_cf7_rate_limit' => '5' ) );
		$form_protection = new FormProtection();

		$this->assertTrue( $form_protection->allow_form_submission( '203.0.113.60' ) );

		$timeout_name = '_transient_timeout_' . SecurityHelper::generate_ip_transient_key( 'form_rate', '203.0.113.60' );
		$expiry       = time() + 10;
		$wpdb->update( $wpdb->options, array( 'option_value' => (string) $expiry ), array( 'option_name' => $timeout_name ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		\wp_cache_flush();

		$this->assertTrue( $form_protection->allow_form_submission( '203.0.113.60' ) );

		$stored = (int) $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $timeout_name ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$this->assertSame( $expiry, $stored, 'An accepted submission must not push the window end' );
	}
}
