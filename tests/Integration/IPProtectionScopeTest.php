<?php
/**
 * IP protection scope tests
 *
 * The plugin has two separate per-IP protections (#146, part of #124):
 *
 * - the login lockout (`LoginSecurity`), which locks an IP out of the login after failed attempts, and
 * - the form flood protection (`IPBlacklist` with `ContactForm7Integration` and `FormProtection`),
 *   which blocks an IP from submitting Contact Form 7 forms. It exists by design for CF7 only.
 *
 * These tests pin that the two do not leak into each other and that the admin screens say which
 * protection each number, list and toggle belongs to.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use DOMDocument;
use DOMXPath;
use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use SilverAssist\Security\Admin\Renderer\DashboardRenderer;
use SilverAssist\Security\Admin\Renderer\SettingsRenderer;
use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use SilverAssist\Security\Security\ContactForm7Integration;
use SilverAssist\Security\Security\IPBlacklist;
use SilverAssist\Security\Security\LoginSecurity;
use WP_Error;
use WP_UnitTestCase;

/**
 * Scope of the login lockout and the form flood protection
 */
class IPProtectionScopeTest extends WP_UnitTestCase {

	/**
	 * Original $_SERVER
	 *
	 * @var array<string, mixed>
	 */
	private array $server_backup = array();

	/**
	 * Prepare an administrator, the CF7 marker class and clean counters
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();
		if ( ! class_exists( 'WPCF7' ) ) {
			eval( 'class WPCF7 {}' ); // phpcs:ignore Squiz.PHP.Eval.Discouraged -- Test-only CF7 class stub.
		}
		$this->server_backup        = $_SERVER;
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15';
		wp_set_current_user( $this->factory()->user->create( array( 'role' => 'administrator' ) ) );
		wp_cache_delete( 'silver_assist_blocked_ips_count', 'silver-assist-security' );
	}

	/**
	 * Restore globals
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		$_SERVER = $this->server_backup;
		$_POST   = array();
		wp_cache_flush();
		parent::tearDown();
	}

	/**
	 * Lock an IP out of the login the way failed logins do
	 *
	 * @param string $ip Client IP.
	 * @return void
	 */
	private function lock_out_of_login( string $ip ): void {
		$_SERVER['REMOTE_ADDR'] = $ip;
		$login                  = LoginSecurity::instance();
		for ( $i = 0; $i < 5; $i++ ) {
			$login->handle_failed_login( 'someone' );
		}
		wp_cache_delete( 'silver_assist_blocked_ips_count', 'silver-assist-security' );
	}

	/**
	 * Render the dashboard and return it as a DOM
	 *
	 * @return DOMXPath
	 */
	private function dashboard(): DOMXPath {
		$renderer = new DashboardRenderer( GraphQLConfigManager::get_instance(), new SecurityDataProvider() );
		ob_start();
		$renderer->render();
		return $this->xpath( (string) ob_get_clean() );
	}

	/**
	 * Render every settings tab and return it as a DOM
	 *
	 * @return DOMXPath
	 */
	private function settings(): DOMXPath {
		$renderer = new SettingsRenderer( GraphQLConfigManager::get_instance() );
		ob_start();
		$renderer->render_all_tabs();
		return $this->xpath( (string) ob_get_clean() );
	}

	/**
	 * Parse markup
	 *
	 * @param string $html Markup.
	 * @return DOMXPath
	 */
	private function xpath( string $html ): DOMXPath {
		$dom = new DOMDocument();
		libxml_use_internal_errors( true );
		$dom->loadHTML( '<?xml encoding="utf-8"?>' . $html );
		libxml_clear_errors();
		return new DOMXPath( $dom );
	}

	/**
	 * The number shown for a stat label inside a dashboard card
	 *
	 * @param DOMXPath $xpath Dashboard DOM.
	 * @param string   $card  Card class (`login-security`, `cf7-security`).
	 * @param string   $label Stat label.
	 * @return string|null Value text, or null when the card has no such stat.
	 */
	private function stat( DOMXPath $xpath, string $card, string $label ): ?string {
		$nodes = $xpath->query( "//div[contains(@class,'{$card}')]//div[@class='stat'][span[@class='stat-label'][normalize-space()='{$label}']]/span[@class='stat-value']" );
		return ( $nodes && $nodes->length ) ? trim( (string) $nodes->item( 0 )->textContent ) : null;
	}

	/**
	 * An IP in the form flood blacklist can still use the login
	 *
	 * The blacklist is checked only by the Contact Form 7 validation, by design.
	 *
	 * @return void
	 */
	public function test_blacklisted_ip_is_not_locked_out_of_login(): void {
		$ip                     = '198.51.100.20';
		$_SERVER['REMOTE_ADDR'] = $ip;
		$user                   = get_userdata(
			$this->factory()->user->create(
				array(
					'user_login' => 'visitor',
					'user_pass'  => 'Correct-Horse-1!',
				)
			)
		);
		IPBlacklist::get_instance()->add_to_blacklist( $ip, 'test', HOUR_IN_SECONDS );
		$login = LoginSecurity::instance();

		$this->assertTrue( IPBlacklist::get_instance()->is_blacklisted( $ip ) );
		$this->assertNotInstanceOf( WP_Error::class, $login->check_login_lockout( $user, 'visitor', 'Correct-Horse-1!' ) );
	}

	/**
	 * An IP in the form flood blacklist can still reach the REST API
	 *
	 * @return void
	 */
	public function test_blacklisted_ip_can_still_reach_rest(): void {
		$ip                     = '198.51.100.21';
		$_SERVER['REMOTE_ADDR'] = $ip;
		IPBlacklist::get_instance()->add_to_blacklist( $ip, 'test', HOUR_IN_SECONDS );

		$response = rest_do_request( new \WP_REST_Request( 'GET', '/wp/v2/posts' ) );

		$this->assertSame( 200, $response->get_status() );
	}

	/**
	 * An IP locked out of the login can still submit a Contact Form 7 form
	 *
	 * The two protections keep separate state: a login lockout is not a form block.
	 *
	 * @return void
	 */
	public function test_login_lockout_does_not_block_form_submits(): void {
		$ip = '198.51.100.22';
		$this->lock_out_of_login( $ip );
		$this->assertNotFalse( get_transient( SecurityHelper::generate_ip_transient_key( 'lockout', $ip ) ), 'the IP is locked out of login' );
		$this->assertFalse( IPBlacklist::get_instance()->is_blacklisted( $ip ), 'a login lockout is not a blacklist entry' );

		$integration = new ContactForm7Integration();
		$result      = new FakeCf7Validation();
		$_POST       = array( 'your-message' => 'Hello there, a question about visiting hours.' );
		apply_filters( 'wpcf7_validate', $result, array() );

		$this->assertTrue( $result->is_valid(), 'a login lockout does not stop the contact form' );
		unset( $integration );
	}

	/**
	 * The login card counts login lockouts, not form flood blocks
	 *
	 * @return void
	 */
	public function test_dashboard_login_card_counts_login_lockouts_only(): void {
		IPBlacklist::get_instance()->add_to_blacklist( '198.51.100.30', 'flood', HOUR_IN_SECONDS );
		IPBlacklist::get_instance()->add_to_blacklist( '198.51.100.31', 'flood', HOUR_IN_SECONDS );
		$this->lock_out_of_login( '198.51.100.32' );

		$xpath = $this->dashboard();

		$this->assertSame( '1', $this->stat( $xpath, 'login-security', 'Locked-out IPs' ), 'the login card counts the one login lockout' );
	}

	/**
	 * The form protection card counts form flood blocks, not login lockouts
	 *
	 * @return void
	 */
	public function test_dashboard_form_card_counts_form_flood_blocks_only(): void {
		IPBlacklist::get_instance()->add_to_blacklist( '198.51.100.30', 'flood', HOUR_IN_SECONDS );
		IPBlacklist::get_instance()->add_to_blacklist( '198.51.100.31', 'flood', HOUR_IN_SECONDS );
		$this->lock_out_of_login( '198.51.100.32' );

		$xpath = $this->dashboard();

		$this->assertSame( '2', $this->stat( $xpath, 'cf7-security', 'Form Flood Blocked IPs' ), 'the form card counts the two flood blocks' );
	}

	/**
	 * The dashboard names the blacklist for what it is
	 *
	 * @return void
	 */
	public function test_dashboard_names_the_form_flood_blacklist(): void {
		$text = $this->dashboard()->document->textContent;

		$this->assertStringContainsString( 'Form Flood Blacklist', $text );
		$this->assertStringNotContainsString( 'IP Blacklisting', $text, 'the generic name suggested a site-wide block' );
	}

	/**
	 * The IP Management tab says which protection each control and list belongs to
	 *
	 * @return void
	 */
	public function test_ip_management_tab_states_the_scope(): void {
		$tab = $this->settings()->query( "//*[@id='ip-management-content']" )->item( 0 );
		$this->assertNotNull( $tab );
		$text = preg_replace( '/\s+/', ' ', $tab->textContent );

		$this->assertStringContainsString( 'Form Flood Blacklist', $text, 'the toggle names the protection' );
		$this->assertStringContainsString( 'Contact Form 7', $text );
		$this->assertStringContainsString( 'Login Security tab', $text, 'it points to where the login lockout lives' );
		$this->assertStringNotContainsString( 'Login Security - Blocked IPs', $text, 'the blacklist is not the login lockout list' );
		$this->assertStringNotContainsString( 'denied access to login', $text, 'a manual block does not stop login' );
	}

	/**
	 * Manual block copy tells the truth about what is blocked and for how long
	 *
	 * @return void
	 */
	public function test_manual_block_copy_states_what_it_blocks(): void {
		$text = preg_replace( '/\s+/', ' ', $this->settings()->document->textContent );

		$this->assertStringContainsString( 'from submitting Contact Form 7 forms for 30 days', $text );
		$this->assertStringContainsString( 'does not block login', $text );
	}
}
