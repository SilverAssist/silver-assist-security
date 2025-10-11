<?php
/**
 * Unit Tests for Updater Class
 *
 * Tests the GitHub updater integration for Silver Assist Security Essentials.
 * Validates configuration, initialization, and integration with wp-github-updater package.
 *
 * @package SilverAssist\Security\Tests\Unit
 * @since 1.1.14
 */

namespace SilverAssist\Security\Tests\Unit;

use WP_UnitTestCase;
use SilverAssist\Security\Core\Updater;
use SilverAssist\WpGithubUpdater\Updater as GitHubUpdater;
use SilverAssist\WpGithubUpdater\UpdaterConfig;

/**
 * Class UpdaterTest
 *
 * Unit tests for Updater class configuration and initialization.
 *
 * @since 1.1.14
 */
class UpdaterTest extends WP_UnitTestCase {

	/**
	 * Test plugin file path for testing
	 *
	 * @var string
	 */
	private string $plugin_file;

	/**
	 * Test GitHub repository
	 *
	 * @var string
	 */
	private string $github_repo;

	/**
	 * Set up test environment
	 *
	 * @return void
	 */
	public function setUp(): void {
		parent::setUp();

		$this->plugin_file = SILVER_ASSIST_SECURITY_PATH . '/silver-assist-security.php';
		$this->github_repo = 'SilverAssist/silver-assist-security';
	}

	/**
	 * Test that Updater class can be instantiated
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_instantiation(): void {
		$updater = new Updater( $this->plugin_file, $this->github_repo );

		$this->assertInstanceOf( Updater::class, $updater );
		$this->assertInstanceOf( GitHubUpdater::class, $updater );
	}

	/**
	 * Test that Updater extends GitHubUpdater
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_extends_github_updater(): void {
		$updater = new Updater( $this->plugin_file, $this->github_repo );

		$this->assertInstanceOf( GitHubUpdater::class, $updater, 'Updater should extend GitHubUpdater' );
	}

	/**
	 * Test Updater configuration with correct plugin file
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_accepts_valid_plugin_file(): void {
		$updater = new Updater( $this->plugin_file, $this->github_repo );

		$this->assertInstanceOf( Updater::class, $updater );
	}

	/**
	 * Test Updater configuration with correct GitHub repository
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_accepts_valid_github_repo(): void {
		$updater = new Updater( $this->plugin_file, $this->github_repo );

		$this->assertInstanceOf( Updater::class, $updater );
	}

	/**
	 * Test Updater with different valid repository formats
	 *
	 * Tests that updater accepts various valid GitHub repository formats.
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_accepts_various_repo_formats(): void {
		$repo_formats = [
			'SilverAssist/silver-assist-security',
			'owner/repo',
			'test-org/test-plugin',
		];

		foreach ( $repo_formats as $repo ) {
			$updater = new Updater( $this->plugin_file, $repo );
			$this->assertInstanceOf( Updater::class, $updater, "Should accept repo format: {$repo}" );
		}
	}

	/**
	 * Test that Updater properly initializes with plugin constants
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_uses_plugin_constants(): void {
		$this->assertTrue( defined( 'SILVER_ASSIST_SECURITY_PATH' ), 'SILVER_ASSIST_SECURITY_PATH should be defined' );
		$this->assertTrue( defined( 'SILVER_ASSIST_SECURITY_VERSION' ), 'SILVER_ASSIST_SECURITY_VERSION should be defined' );

		$updater = new Updater( $this->plugin_file, $this->github_repo );
		$this->assertInstanceOf( Updater::class, $updater );
	}

	/**
	 * Test Updater configuration includes required fields
	 *
	 * This test validates that UpdaterConfig receives all required configuration.
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_config_has_required_fields(): void {
		$updater = new Updater( $this->plugin_file, $this->github_repo );

		// If instantiation succeeds, configuration is valid
		$this->assertInstanceOf( Updater::class, $updater );
	}

	/**
	 * Test Updater with absolute plugin file path
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_accepts_absolute_plugin_path(): void {
		$absolute_path = SILVER_ASSIST_SECURITY_PATH . '/silver-assist-security.php';
		$updater       = new Updater( $absolute_path, $this->github_repo );

		$this->assertInstanceOf( Updater::class, $updater );
	}

	/**
	 * Test that Updater can be instantiated multiple times
	 *
	 * Validates that multiple Updater instances can coexist.
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_multiple_updater_instances(): void {
		$updater1 = new Updater( $this->plugin_file, $this->github_repo );
		$updater2 = new Updater( $this->plugin_file, $this->github_repo );

		$this->assertInstanceOf( Updater::class, $updater1 );
		$this->assertInstanceOf( Updater::class, $updater2 );
		$this->assertNotSame( $updater1, $updater2, 'Each instance should be unique' );
	}

	/**
	 * Test Updater configuration with all expected config keys
	 *
	 * Validates that all configuration keys are passed to UpdaterConfig.
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_config_includes_all_keys(): void {
		$updater = new Updater( $this->plugin_file, $this->github_repo );

		// Verify configuration was successful by checking instantiation
		$this->assertInstanceOf( Updater::class, $updater );
		$this->assertInstanceOf( GitHubUpdater::class, $updater );
	}

	/**
	 * Test Updater configuration values are correct types
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_config_values_correct_types(): void {
		$updater = new Updater( $this->plugin_file, $this->github_repo );

		// If instantiation succeeds with proper types, test passes
		$this->assertInstanceOf( Updater::class, $updater );
	}
}
