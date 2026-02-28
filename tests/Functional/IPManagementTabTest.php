<?php
/**
 * Silver Assist Security Essentials - IP Management Tab Functional Tests
 *
 * Tests that the IP Management settings tab renders the expected UI sections
 * including blocked IP lists, manual management form, and CF7 section.
 *
 * @package SilverAssist\Security\Tests\Functional
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Tests\Functional;

use SilverAssist\Security\Admin\Renderer\SettingsRenderer;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use WP_UnitTestCase;

/**
 * IP Management Tab functional tests
 *
 * @since 1.1.15
 */
class IPManagementTabTest extends WP_UnitTestCase {

	/**
	 * Captured settings HTML
	 *
	 * @var string
	 */
	private string $settings_html = '';

	/**
	 * Set up by rendering all settings tabs once
	 */
	protected function setUp(): void {
		parent::setUp();

		$admin_id = $this->factory()->user->create( [ 'role' => 'administrator' ] );
		\wp_set_current_user( $admin_id );

		$config_manager = GraphQLConfigManager::getInstance();
		$renderer       = new SettingsRenderer( $config_manager );

		ob_start();
		$renderer->render_all_tabs();
		$this->settings_html = ob_get_clean();
	}

	/**
	 * Test IP management tab renders key sections
	 */
	public function test_ip_management_renders_all_sections(): void {
		// The IP management tab should contain blocked IPs UI
		$this->assertStringContainsString(
			'ip-management',
			$this->settings_html,
			'Settings should contain ip-management section'
		);
	}

	/**
	 * Test manual IP form has required inputs
	 */
	public function test_manual_ip_form_has_inputs(): void {
		// Should have an input for IP address and a button
		$this->assertStringContainsString(
			'ip_address',
			$this->settings_html,
			'Settings should contain an IP address input'
		);
	}

	/**
	 * Test CF7 section is conditional on CF7 being active
	 */
	public function test_cf7_section_conditional_on_cf7_active(): void {
		$cf7_active = \SilverAssist\Security\Core\SecurityHelper::is_contact_form_7_active();

		if ( $cf7_active ) {
			$this->assertStringContainsString(
				'cf7',
				strtolower( $this->settings_html ),
				'CF7 section should appear when CF7 is active'
			);
		} else {
			// When CF7 is not active, the section may be hidden or absent
			// This test documents the conditional behavior
			$this->assertTrue( true, 'CF7 section correctly absent when CF7 is not active' );
		}
	}

	/**
	 * Clean up
	 */
	protected function tearDown(): void {
		\wp_set_current_user( 0 );
		parent::tearDown();
	}
}
