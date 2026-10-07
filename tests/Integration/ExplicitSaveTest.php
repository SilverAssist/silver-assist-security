<?php
/**
 * Explicit save per tab (#160)
 *
 * One form and one Save per settings tab, no generic auto-save, per-field messages after a save and a
 * safe Admin Hide flow (validated path, confirmation, rewrite flush), driven through the real renderer,
 * handler and saver.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use DOMDocument;
use DOMXPath;
use SilverAssist\Security\Admin\Ajax\SecurityAjaxHandler;
use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use SilverAssist\Security\Admin\Data\StatisticsProvider;
use SilverAssist\Security\Admin\Renderer\SettingsRenderer;
use SilverAssist\Security\Admin\Settings\SettingsHandler;
use SilverAssist\Security\Admin\Settings\SettingsRegistry;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use SilverAssist\Security\Tests\Helpers\RenderedSettingsForms;
use WP_UnitTestCase;

/**
 * Behavior of the explicit save model
 */
class ExplicitSaveTest extends WP_UnitTestCase {

	use RenderedSettingsForms;

	/**
	 * Times the rewrite rules were regenerated
	 *
	 * @var int
	 */
	private int $flushes = 0;

	/**
	 * Administrator, stub integrations, clean options and a flush counter
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->require_full_settings_screen();
		\wp_set_current_user( $this->factory()->user->create( array( 'role' => 'administrator' ) ) );
		foreach ( \array_keys( SettingsRegistry::all() ) as $option ) {
			\delete_option( $option );
		}
		SettingsHandler::clear_last_result();
		\remove_all_actions( 'admin_notices' );
		$_POST = array();

		// With plain permalinks core does not generate rules at all, so a flush would not be observable.
		$this->set_permalink_structure( '/%postname%/' );
		$this->flushes = 0;
		\add_action(
			'generate_rewrite_rules',
			function (): void {
				++$this->flushes;
			}
		);
	}

	/**
	 * Clean request state
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		$_POST = array();
		SettingsHandler::clear_last_result();
		parent::tearDown();
	}

	/**
	 * Post fields through the handler
	 *
	 * @param array<string, string> $fields Fields.
	 * @return void
	 */
	private function post( array $fields ): void {
		$_POST = $fields;
		( new SettingsHandler() )->save_security_settings();
	}

	/**
	 * A login-security tab POST, as the tab's form builds it, with overrides
	 *
	 * @param array<string, string> $overrides Field values to set.
	 * @param string[]              $remove    Fields to leave out (unchecked boxes).
	 * @return array<string, string>
	 */
	private function login_tab_post( array $overrides, array $remove = array() ): array {
		$fields = $this->form_fields( $this->form_for_tab( 'login-security' ) );
		$fields = \array_merge( $fields, $overrides );
		foreach ( $remove as $name ) {
			unset( $fields[ $name ] );
		}

		return $fields;
	}

	/**
	 * Admin notices as HTML
	 *
	 * @return string
	 */
	private function notices(): string {
		\ob_start();
		\do_action( 'admin_notices' );

		return (string) \ob_get_clean();
	}

	/**
	 * Every settings tab as an XPath
	 *
	 * @return DOMXPath
	 */
	private function rendered_screen(): DOMXPath {
		$renderer = new SettingsRenderer( GraphQLConfigManager::get_instance() );
		\ob_start();
		$renderer->render_all_tabs();
		$html = (string) \ob_get_clean();

		$previous = \libxml_use_internal_errors( true );
		$dom      = new DOMDocument();
		$dom->loadHTML( '<?xml encoding="utf-8" ?><body>' . $html . '</body>' );
		\libxml_clear_errors();
		\libxml_use_internal_errors( $previous );

		return new DOMXPath( $dom );
	}

	/**
	 * One form per tab, one Save button in it, a save bar and a status region
	 *
	 * @return void
	 */
	public function test_every_tab_has_one_form_and_one_save(): void {
		$xpath = $this->rendered_screen();

		foreach ( \array_keys( SettingsRegistry::tabs() ) as $tab ) {
			$panel = $xpath->query( "//div[@id='{$tab}-content']" )->item( 0 );
			$this->assertNotNull( $panel, "Tab {$tab} is not rendered." );

			$forms = $xpath->query( './/form', $panel );
			$this->assertSame( 1, $forms->length, "Tab {$tab} must have exactly one form." );
			$this->assertSame( 1, $xpath->query( './/input[@type="submit"]', $panel )->length, "Tab {$tab} must have exactly one Save button." );
			$this->assertSame( 1, $xpath->query( ".//form[@id='{$tab}-form']//*[contains(concat(' ', normalize-space(@class), ' '), ' silver-save-bar ')]", $panel )->length, "Tab {$tab} needs its save bar inside the form." );
			$this->assertSame( 1, $xpath->query( ".//*[@role='status'][contains(concat(' ', normalize-space(@class), ' '), ' silver-save-status ')]", $panel )->length, "Tab {$tab} needs one status region." );
		}
	}

	/**
	 * The tab form posts every field of the tab, and the save persists them all
	 *
	 * The Login Security tab holds three sections: login protection, Admin Hide and branding.
	 *
	 * @return void
	 */
	public function test_tab_form_persists_every_section_of_the_tab(): void {
		\update_option( 'silver_assist_password_strength_enforcement', 1 );
		\update_option( 'silver_assist_login_branding_enabled', 1 );

		$this->post(
			$this->login_tab_post(
				array(
					'silver_assist_login_attempts'          => '9',
					'silver_assist_admin_hide_path'         => 'my-private-door',
					'silver_assist_login_branding_bg_color' => '#123abc',
					'silver_assist_login_branding_logo_url' => 'https://example.com/logo.png',
				),
				array( 'silver_assist_password_strength_enforcement', 'silver_assist_login_branding_enabled' )
			)
		);

		$this->assertSame( 9, (int) \get_option( 'silver_assist_login_attempts' ) );
		$this->assertSame( 'my-private-door', \get_option( 'silver_assist_admin_hide_path' ) );
		$this->assertSame( '#123abc', \get_option( 'silver_assist_login_branding_bg_color' ) );
		$this->assertSame( 'https://example.com/logo.png', \get_option( 'silver_assist_login_branding_logo_url' ) );
		$this->assertSame( 0, (int) \get_option( 'silver_assist_password_strength_enforcement' ), 'An unchecked box in the tab is saved as off.' );
		$this->assertSame( 0, (int) \get_option( 'silver_assist_login_branding_enabled' ) );
		$this->assertStringContainsString( 'saved successfully', $this->notices() );
	}

	/**
	 * A tab POST does not write the options of another tab
	 *
	 * @return void
	 */
	public function test_tab_post_does_not_write_other_tabs(): void {
		\update_option( 'silver_assist_rest_rate_limit_requests', 50 );

		$this->post( $this->login_tab_post( array( 'silver_assist_rest_rate_limit_requests' => '999' ) ) );

		$this->assertSame( 50, (int) \get_option( 'silver_assist_rest_rate_limit_requests' ) );
	}

	/**
	 * An unknown tab writes nothing and says so
	 *
	 * @return void
	 */
	public function test_unknown_tab_writes_nothing(): void {
		\update_option( 'silver_assist_login_attempts', 5 );

		$this->post(
			$this->login_tab_post(
				array(
					'settings_tab'                 => 'nope',
					'silver_assist_login_attempts' => '15',
				)
			)
		);

		$this->assertSame( 5, (int) \get_option( 'silver_assist_login_attempts' ) );
		$this->assertStringContainsString( 'notice-error', $this->notices() );
	}

	/**
	 * Enabling Admin Hide without confirming the URL does not enable it
	 *
	 * @return void
	 */
	public function test_enabling_admin_hide_needs_confirmation(): void {
		$this->post(
			$this->login_tab_post(
				array(
					'silver_assist_admin_hide_enabled' => '1',
					'silver_assist_admin_hide_path'    => 'my-private-door',
				)
			)
		);

		$this->assertSame( 0, (int) \get_option( 'silver_assist_admin_hide_enabled', 0 ) );
		$this->assertNotSame( 'my-private-door', \get_option( 'silver_assist_admin_hide_path' ), 'An unconfirmed change is not written.' );
		$this->assertSame( 0, $this->flushes, 'Nothing changed, nothing is flushed.' );
		$this->assertStringContainsString( 'notice-error', $this->notices() );
	}

	/**
	 * Enabling with a confirmed, valid path enables it, flushes the rewrite rules and shows the admin URL
	 *
	 * @return void
	 */
	public function test_confirmed_enable_saves_flushes_and_shows_the_url(): void {
		$this->post(
			$this->login_tab_post(
				array(
					'silver_assist_admin_hide_enabled' => '1',
					'silver_assist_admin_hide_path'    => 'my-private-door',
					'silver_assist_admin_hide_confirm' => '1',
				)
			)
		);

		$this->assertSame( 1, (int) \get_option( 'silver_assist_admin_hide_enabled' ) );
		$this->assertSame( 'my-private-door', \get_option( 'silver_assist_admin_hide_path' ) );
		$this->assertGreaterThan( 0, $this->flushes, 'Turning Admin Hide on flushes the rewrite rules.' );
		$this->assertStringContainsString( \home_url( '/my-private-door' ), $this->notices(), 'The resulting admin URL is shown after the save.' );
	}

	/**
	 * An invalid path never enables Admin Hide, even with the confirmation
	 *
	 * @return void
	 */
	public function test_invalid_path_never_enables_admin_hide(): void {
		foreach ( array( 'wp-json', '', 'ab', 'login' ) as $bad ) {
			$this->post(
				$this->login_tab_post(
					array(
						'silver_assist_admin_hide_enabled' => '1',
						'silver_assist_admin_hide_path'    => $bad,
						'silver_assist_admin_hide_confirm' => '1',
					)
				)
			);

			$this->assertSame( 0, (int) \get_option( 'silver_assist_admin_hide_enabled', 0 ), "'{$bad}' must not enable Admin Hide." );
		}
		$this->assertSame( 0, $this->flushes );
	}

	/**
	 * Changing the path while Admin Hide is on needs the same confirmation, and flushes once confirmed
	 *
	 * @return void
	 */
	public function test_path_change_while_enabled_needs_confirmation_and_flushes(): void {
		\update_option( 'silver_assist_admin_hide_enabled', 1 );
		\update_option( 'silver_assist_admin_hide_path', 'first-door' );

		$this->post(
			$this->login_tab_post(
				array(
					'silver_assist_admin_hide_enabled' => '1',
					'silver_assist_admin_hide_path'    => 'second-door',
				)
			)
		);
		$this->assertSame( 'first-door', \get_option( 'silver_assist_admin_hide_path' ), 'The live path stays until the change is confirmed.' );
		$this->assertSame( 0, $this->flushes );

		$this->post(
			$this->login_tab_post(
				array(
					'silver_assist_admin_hide_enabled' => '1',
					'silver_assist_admin_hide_path'    => 'second-door',
					'silver_assist_admin_hide_confirm' => '1',
				)
			)
		);
		$this->assertSame( 'second-door', \get_option( 'silver_assist_admin_hide_path' ) );
		$this->assertGreaterThan( 0, $this->flushes );
	}

	/**
	 * Turning Admin Hide off needs no confirmation, and flushes
	 *
	 * @return void
	 */
	public function test_disabling_admin_hide_always_works(): void {
		\update_option( 'silver_assist_admin_hide_enabled', 1 );
		\update_option( 'silver_assist_admin_hide_path', 'first-door' );

		$this->post( $this->login_tab_post( array( 'silver_assist_admin_hide_path' => 'wp-json' ), array( 'silver_assist_admin_hide_enabled' ) ) );

		$this->assertSame( 0, (int) \get_option( 'silver_assist_admin_hide_enabled' ), 'Switching it off is never blocked, not even by a bad path in the box.' );
		$this->assertGreaterThan( 0, $this->flushes );
	}

	/**
	 * A save that does not touch Admin Hide does not flush the rewrite rules
	 *
	 * @return void
	 */
	public function test_unrelated_save_does_not_flush(): void {
		\update_option( 'silver_assist_admin_hide_enabled', 1 );
		\update_option( 'silver_assist_admin_hide_path', 'first-door' );

		$this->post(
			$this->login_tab_post(
				array(
					'silver_assist_login_attempts'     => '8',
					'silver_assist_admin_hide_enabled' => '1',
					'silver_assist_admin_hide_path'    => 'first-door',
				)
			)
		);

		$this->assertSame( 8, (int) \get_option( 'silver_assist_login_attempts' ) );
		$this->assertSame( 0, $this->flushes );
	}

	/**
	 * The Admin Hide card shows the URL the admin will be reachable at and a confirmation checkbox
	 *
	 * @return void
	 */
	public function test_admin_hide_card_shows_the_url_and_confirmation(): void {
		\update_option( 'silver_assist_admin_hide_path', 'my-private-door' );
		$xpath = $this->rendered_screen();

		$this->assertSame( 1, $xpath->query( "//*[@id='admin-hide-url-preview']" )->length );
		$this->assertStringContainsString( \home_url( '/my-private-door' ), $xpath->query( "//*[@id='admin-hide-url-preview']" )->item( 0 )->textContent );
		$confirm = $xpath->query( "//input[@type='checkbox'][@name='silver_assist_admin_hide_confirm']" );
		$this->assertSame( 1, $confirm->length );
		$this->assertFalse( $confirm->item( 0 )->hasAttribute( 'checked' ), 'The confirmation is never pre-checked.' );
	}

	/**
	 * A rejected value is reported next to its field, and the field keeps what was typed
	 *
	 * @return void
	 */
	public function test_rejected_value_is_shown_next_to_the_field(): void {
		$this->post( $this->login_tab_post( array( 'silver_assist_admin_hide_path' => 'wp-json' ) ) );
		$xpath = $this->rendered_screen();

		$message = $xpath->query( "//*[@id='silver_assist_admin_hide_path-message']" );
		$this->assertSame( 1, $message->length, 'The path field needs its own message.' );
		$this->assertSame( 'alert', $message->item( 0 )->getAttribute( 'role' ) );
		$this->assertStringContainsString( 'wp-json', $message->item( 0 )->textContent );

		$input = $xpath->query( "//input[@id='silver_assist_admin_hide_path']" )->item( 0 );
		$this->assertSame( 'wp-json', $input->getAttribute( 'value' ), 'The input keeps what the user typed.' );
		$this->assertSame( 'true', $input->getAttribute( 'aria-invalid' ) );
		$this->assertSame( 'silver_assist_admin_hide_path-message', $input->getAttribute( 'aria-describedby' ) );
	}

	/**
	 * An adjusted value is reported next to its field
	 *
	 * @return void
	 */
	public function test_adjusted_value_is_shown_next_to_the_field(): void {
		$this->post( $this->login_tab_post( array( 'silver_assist_login_attempts' => '99' ) ) );
		$xpath = $this->rendered_screen();

		$message = $xpath->query( "//*[@id='silver_assist_login_attempts-message']" );
		$this->assertSame( 1, $message->length );
		$this->assertStringContainsString( '99', $message->item( 0 )->textContent );
		$this->assertStringContainsString( '20', $message->item( 0 )->textContent );
	}

	/**
	 * Without a save there are no field messages
	 *
	 * @return void
	 */
	public function test_no_messages_without_a_save(): void {
		$this->assertSame( 0, $this->rendered_screen()->query( "//*[contains(concat(' ', normalize-space(@class), ' '), ' silver-field-message ')]" )->length );
	}

	/**
	 * The auto-save endpoint is gone and the live path validation is still there
	 *
	 * @return void
	 */
	public function test_autosave_endpoint_is_removed(): void {
		new SecurityAjaxHandler( new SecurityDataProvider(), new StatisticsProvider() );

		$this->assertFalse( \has_action( 'wp_ajax_silver_assist_auto_save' ) );
		$this->assertFalse( \method_exists( SecurityAjaxHandler::class, 'auto_save' ) );
		$this->assertNotFalse( \has_action( 'wp_ajax_silver_assist_validate_admin_path' ), 'Live path validation stays.' );
		$this->assertFalse( \method_exists( SettingsRegistry::class, 'autosave_options' ) );
		foreach ( SettingsRegistry::all() as $declaration ) {
			$this->assertArrayNotHasKey( 'autosave', $declaration );
		}
	}

	/**
	 * The admin script no longer posts settings in the background
	 *
	 * @return void
	 */
	public function test_admin_script_has_no_autosave(): void {
		$js = (string) \file_get_contents( \dirname( __DIR__, 2 ) . '/assets/js/admin.js' );

		$this->assertStringNotContainsString( 'silver_assist_auto_save', $js );
		$this->assertStringNotContainsString( 'initAutoSave', $js );
		$this->assertStringContainsString( 'beforeunload', $js, 'The leave warning replaces it.' );
	}
}
