<?php
/**
 * Silver Assist Security Essentials - Dashboard Display Functional Tests
 *
 * Tests that the dashboard renderer produces HTML output containing
 * the expected UI elements (status cards, statistics, activity tabs).
 *
 * @package SilverAssist\Security\Tests\Functional
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Tests\Functional;

use SilverAssist\Security\Admin\Renderer\DashboardRenderer;
use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use WP_UnitTestCase;

/**
 * Dashboard display functional tests
 *
 * @since 1.1.15
 */
class DashboardDisplayTest extends WP_UnitTestCase {

	/**
	 * Captured dashboard HTML
	 *
	 * @var string
	 */
	private string $dashboard_html = '';

	/**
	 * Set up by rendering the dashboard once
	 */
	protected function setUp(): void {
		parent::setUp();

		$admin_id = $this->factory()->user->create( [ 'role' => 'administrator' ] );
		\wp_set_current_user( $admin_id );

		$config_manager = GraphQLConfigManager::getInstance();
		$data_provider  = new SecurityDataProvider();

		$renderer = new DashboardRenderer( $config_manager, $data_provider );

		ob_start();
		$renderer->render();
		$this->dashboard_html = ob_get_clean();
	}

	/**
	 * Test dashboard renders status cards
	 */
	public function test_dashboard_renders_status_cards(): void {
		$this->assertStringContainsString(
			'status-card',
			$this->dashboard_html,
			'Dashboard should contain status-card elements'
		);
	}

	/**
	 * Test dashboard renders statistics section
	 */
	public function test_dashboard_renders_statistics_section(): void {
		$this->assertStringContainsString(
			'security-stats-container',
			$this->dashboard_html,
			'Dashboard should contain the security-stats-container'
		);
	}

	/**
	 * Test dashboard renders activity tabs
	 */
	public function test_dashboard_renders_activity_tabs(): void {
		$this->assertStringContainsString(
			'activity-tab',
			$this->dashboard_html,
			'Dashboard should contain activity-tab buttons'
		);
	}

	/**
	 * Clean up
	 */
	protected function tearDown(): void {
		\wp_set_current_user( 0 );
		parent::tearDown();
	}
}
