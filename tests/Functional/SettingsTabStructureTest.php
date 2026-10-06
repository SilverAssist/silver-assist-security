<?php
/**
 * Settings tab structure tests
 *
 * The admin JavaScript shows and hides only elements with the silver-tab-content
 * class, so any card rendered outside a tab panel is visible on every tab (#156).
 *
 * @package SilverAssist\Security\Tests\Functional
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Functional;

use DOMDocument;
use DOMXPath;
use SilverAssist\Security\Admin\Renderer\SettingsRenderer;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use WP_UnitTestCase;

/**
 * Test that every settings card lives inside exactly one tab panel
 */
class SettingsTabStructureTest extends WP_UnitTestCase {

	/**
	 * Parsed settings markup
	 *
	 * @var DOMXPath
	 */
	private DOMXPath $xpath;

	/**
	 * Render all settings tabs once and parse them
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();

		\wp_set_current_user( $this->factory()->user->create( array( 'role' => 'administrator' ) ) );

		$renderer = new SettingsRenderer( GraphQLConfigManager::get_instance() );
		ob_start();
		$renderer->render_all_tabs();
		$html = (string) ob_get_clean();

		$dom = new DOMDocument();
		// Keep libxml's warnings about HTML5 markup quiet and restore the previous mode afterwards.
		$previous = libxml_use_internal_errors( true );
		$dom->loadHTML( '<?xml encoding="utf-8" ?><body>' . $html . '</body>' );
		libxml_clear_errors();
		libxml_use_internal_errors( $previous );
		$this->xpath = new DOMXPath( $dom );
	}

	/**
	 * Every settings card sits inside a tab panel
	 *
	 * A card outside a panel is shown on every tab.
	 *
	 * @return void
	 */
	public function test_no_card_is_rendered_outside_a_tab_panel(): void {
		$orphans = $this->xpath->query( "//div[contains(concat(' ', normalize-space(@class), ' '), ' status-card ')][not(ancestor::div[contains(concat(' ', normalize-space(@class), ' '), ' silver-tab-content ')])]" );

		$headings = array();
		foreach ( $orphans as $card ) {
			$heading    = $this->xpath->query( './/h3', $card )->item( 0 );
			$headings[] = $heading ? trim( $heading->textContent ) : '(no heading)';
		}

		$this->assertSame( array(), $headings, 'These cards are outside any tab panel and would show on every tab: ' . implode( ', ', $headings ) );
	}

	/**
	 * Login Page Branding belongs to the Login Protection tab only
	 *
	 * @return void
	 */
	public function test_login_branding_is_inside_the_login_protection_panel(): void {
		$inside = $this->xpath->query( "//div[@id='login-security-content']//h3[normalize-space(.)='Login Page Branding']" );
		$all    = $this->xpath->query( "//h3[normalize-space(.)='Login Page Branding']" );

		$this->assertSame( 1, $all->length, 'The branding card should be rendered once.' );
		$this->assertSame( 1, $inside->length, 'The branding card should be inside #login-security-content.' );
	}

	/**
	 * Tab panels are siblings, never nested
	 *
	 * A panel inside another panel would be hidden or shown with its parent.
	 *
	 * @return void
	 */
	public function test_tab_panels_are_not_nested(): void {
		$nested = $this->xpath->query( "//div[contains(concat(' ', normalize-space(@class), ' '), ' silver-tab-content ')]//div[contains(concat(' ', normalize-space(@class), ' '), ' silver-tab-content ')]" );

		$this->assertSame( 0, $nested->length );
	}
}
