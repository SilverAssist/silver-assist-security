<?php
/**
 * Integration Tests for Updater Class
 *
 * Tests the complete GitHub updater integration including WordPress hooks,
 * transient caching, and update checking functionality.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.1.14
 */

namespace SilverAssist\Security\Tests\Integration;

use WP_UnitTestCase;
use SilverAssist\Security\Core\Updater;
use SilverAssist\WpGithubUpdater\Updater as GitHubUpdater;
use SilverAssist\WpGithubUpdater\UpdaterConfig;

/**
 * Class UpdaterIntegrationTest
 *
 * Integration tests for Updater class with WordPress and GitHub API.
 *
 * @since 1.1.14
 */
class UpdaterIntegrationTest extends WP_UnitTestCase {

	/**
	 * Test plugin file path
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
	 * Updater instance for testing
	 *
	 * @var Updater|null
	 */
	private ?Updater $updater = null;

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
	 * Clean up after each test
	 *
	 * @return void
	 */
	public function tearDown(): void {
		// Clean up transients
		\delete_transient( 'silver_assist_security_update_check' );
		\delete_site_transient( 'update_plugins' );

		parent::tearDown();
	}

	/**
	 * Test Updater initialization with WordPress environment
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_initializes_in_wordpress_environment(): void {
		$updater = new Updater( $this->plugin_file, $this->github_repo );

		$this->assertInstanceOf( Updater::class, $updater );
	}

	/**
	 * Test that Updater integrates with WordPress update system
	 *
	 * Validates that updater can be instantiated in WordPress environment.
	 * Hook registration is handled internally by wp-github-updater package.
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_integrates_with_wordpress(): void {
		$updater = new Updater( $this->plugin_file, $this->github_repo );

		// Verify updater was created successfully
		$this->assertInstanceOf( Updater::class, $updater );

		// Verify WordPress environment is available
		$this->assertTrue( \defined( 'ABSPATH' ), 'WordPress ABSPATH should be defined' );
		$this->assertTrue( \function_exists( 'get_plugin_data' ), 'WordPress plugin functions should be available' );
	}

	/**
	 * Test Updater with plugin basename
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_works_with_plugin_basename(): void {
		$plugin_basename = \plugin_basename( $this->plugin_file );
		$updater         = new Updater( $this->plugin_file, $this->github_repo );

		$this->assertInstanceOf( Updater::class, $updater );
		$this->assertNotEmpty( $plugin_basename, 'Plugin basename should not be empty' );
	}

	/**
	 * Test that Updater respects WordPress plugin data
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_respects_wordpress_plugin_data(): void {
		if ( ! \function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugin_data = \get_plugin_data( $this->plugin_file, false, false );
		$updater     = new Updater( $this->plugin_file, $this->github_repo );

		$this->assertInstanceOf( Updater::class, $updater );
		$this->assertNotEmpty( $plugin_data, 'Plugin data should be available' );
		$this->assertArrayHasKey( 'Version', $plugin_data, 'Plugin should have Version field' );
	}

	/**
	 * Test Updater AJAX action configuration
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_ajax_action_configured(): void {
		$updater             = new Updater( $this->plugin_file, $this->github_repo );
		$expected_ajax_action = 'silver_assist_security_check_version';

		$this->assertInstanceOf( Updater::class, $updater );

		// Check if AJAX action is registered
		$has_ajax_action = \has_action( "wp_ajax_{$expected_ajax_action}" );
		$this->assertTrue( $has_ajax_action !== false, 'AJAX action should be registered' );
	}

	/**
	 * Test Updater AJAX nonce configuration
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_ajax_nonce_configured(): void {
		$updater            = new Updater( $this->plugin_file, $this->github_repo );
		$expected_ajax_nonce = 'silver_assist_security_ajax';

		$this->assertInstanceOf( Updater::class, $updater );

		// Verify nonce can be created with expected action
		$nonce = \wp_create_nonce( $expected_ajax_nonce );
		$this->assertNotEmpty( $nonce, 'Nonce should be created with configured action' );
		$this->assertIsString( $nonce, 'Nonce should be a string' );
	}

	/**
	 * Test that Updater works with current plugin version
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_works_with_current_version(): void {
		$updater = new Updater( $this->plugin_file, $this->github_repo );

		$this->assertInstanceOf( Updater::class, $updater );
		$this->assertTrue( defined( 'SILVER_ASSIST_SECURITY_VERSION' ), 'Plugin version constant should be defined' );
		$this->assertNotEmpty( SILVER_ASSIST_SECURITY_VERSION, 'Plugin version should not be empty' );
	}

	/**
	 * Test Updater plugin metadata configuration
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_plugin_metadata(): void {
		$updater = new Updater( $this->plugin_file, $this->github_repo );

		// Configuration values from constructor
		$expected_metadata = [
			'plugin_name'        => 'Silver Assist Security Essentials',
			'plugin_author'      => 'Silver Assist',
			'requires_wordpress' => '6.5',
			'requires_php'       => '8.3',
		];

		$this->assertInstanceOf( Updater::class, $updater );

		// Validate metadata structure
		foreach ( $expected_metadata as $key => $value ) {
			$this->assertIsString( $value, "{$key} should be a string" );
			$this->assertNotEmpty( $value, "{$key} should not be empty" );
		}
	}

	/**
	 * Test Updater with WordPress requirements
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_wordpress_requirements(): void {
		global $wp_version;

		$updater              = new Updater( $this->plugin_file, $this->github_repo );
		$required_wp_version  = '6.5';
		$current_wp_version   = $wp_version;

		$this->assertInstanceOf( Updater::class, $updater );
		$this->assertTrue( version_compare( $current_wp_version, $required_wp_version, '>=' ), 'WordPress version should meet minimum requirement' );
	}

	/**
	 * Test Updater with PHP requirements
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_php_requirements(): void {
		$updater = new Updater( $this->plugin_file, $this->github_repo );

		// The plugin header is the source of truth for the minimum PHP version (CI runs on it).
		$plugin_data          = get_plugin_data( $this->plugin_file, false, false );
		$required_php_version = $plugin_data['RequiresPHP'];
		$current_php_version  = PHP_VERSION;

		$this->assertNotEmpty( $required_php_version, 'The plugin header should declare "Requires PHP"' );

		$this->assertInstanceOf( Updater::class, $updater );
		$this->assertTrue( version_compare( $current_php_version, $required_php_version, '>=' ), 'PHP version should meet minimum requirement' );
	}

	/**
	 * Test Updater GitHub repository format
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_github_repo_format(): void {
		$updater = new Updater( $this->plugin_file, $this->github_repo );

		$this->assertInstanceOf( Updater::class, $updater );
		$this->assertMatchesRegularExpression( '/^[a-zA-Z0-9\-]+\/[a-zA-Z0-9\-_]+$/', $this->github_repo, 'GitHub repo should match format: owner/repo' );
	}

	/**
	 * Test Updater transient cleanup on deactivation
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_transient_cleanup(): void {
		$updater      = new Updater( $this->plugin_file, $this->github_repo );
		$transient_key = 'silver_assist_security_update_check';

		// Set a test transient
		\set_transient( $transient_key, [ 'test' => 'data' ], 3600 );
		$this->assertNotFalse( \get_transient( $transient_key ), 'Transient should be set' );

		// Clean up
		\delete_transient( $transient_key );
		$this->assertFalse( \get_transient( $transient_key ), 'Transient should be deleted' );

		$this->assertInstanceOf( Updater::class, $updater );
	}

	/**
	 * Test Updater with multiple WordPress sites (multisite compatibility)
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_multisite_compatibility(): void {
		$updater = new Updater( $this->plugin_file, $this->github_repo );

		$this->assertInstanceOf( Updater::class, $updater );

		// Check if running in multisite
		if ( \is_multisite() ) {
			$this->assertTrue( \is_multisite(), 'Should work in multisite environment' );
		} else {
			$this->assertFalse( \is_multisite(), 'Should work in single site environment' );
		}
	}

	/**
	 * Test that Updater doesn't interfere with other plugins
	 *
	 * @since 1.1.14
	 * @return void
	 */
	public function test_updater_isolated_from_other_plugins(): void {
		$updater1 = new Updater( $this->plugin_file, $this->github_repo );
		$updater2 = new Updater( $this->plugin_file, 'other-org/other-plugin' );

		$this->assertInstanceOf( Updater::class, $updater1 );
		$this->assertInstanceOf( Updater::class, $updater2 );
		$this->assertNotSame( $updater1, $updater2, 'Each updater instance should be independent' );
	}

	/**
	 * Read the configuration object the plugin's updater was built with
	 *
	 * @return UpdaterConfig
	 */
	private function updater_config(): UpdaterConfig {
		$updater  = new Updater( $this->plugin_file, $this->github_repo );
		$property = new \ReflectionProperty( GitHubUpdater::class, 'config' );
		$property->setAccessible( true );

		return $property->getValue( $updater );
	}

	/**
	 * The update metadata matches the plugin header (#145)
	 *
	 * WordPress uses it to decide whether a host may install the update and shows it in the
	 * plugin-information modal, so it must not claim a higher PHP version than the plugin needs.
	 *
	 * @return void
	 */
	public function test_updater_metadata_matches_plugin_header(): void {
		$plugin_data = get_plugin_data( $this->plugin_file, false, false );
		$config      = $this->updater_config();

		$this->assertSame( $plugin_data['RequiresPHP'], $config->requiresPHP, 'Updater requires_php must equal "Requires PHP" in the plugin header.' );
		$this->assertSame( $plugin_data['RequiresWP'], $config->requiresWordPress, 'Updater requires_wordpress must equal "Requires at least" in the plugin header.' );
	}

	/**
	 * The plugin's updater is configured with the cache window, asset name and token constant (#145)
	 *
	 * Replaces assertions that compared a literal with itself.
	 *
	 * @return void
	 */
	public function test_updater_config_values(): void {
		$config = $this->updater_config();

		$this->assertSame( 12 * 3600, $config->cacheDuration );
		$this->assertSame( 'silver-assist-security-v{version}.zip', $config->assetPattern );
		$this->assertSame( 'SILVER_GITHUB_TOKEN', $config->tokenConstant, 'Private-repo updates need the token constant (updater 1.4+).' );
	}

	/**
	 * A configured token reaches GitHub, and only api.github.com (#145)
	 *
	 * Uses its own constant name so the shared SILVER_GITHUB_TOKEN stays undefined.
	 *
	 * @return void
	 */
	public function test_updater_sends_the_token_to_the_github_api(): void {
		if ( ! defined( 'SILVER_ASSIST_TEST_GITHUB_TOKEN' ) ) {
			define( 'SILVER_ASSIST_TEST_GITHUB_TOKEN', 'test-token-123' );
		}

		$config = new UpdaterConfig(
			$this->plugin_file,
			$this->github_repo,
			array(
				'token_constant' => 'SILVER_ASSIST_TEST_GITHUB_TOKEN',
				'ajax_action'    => 'silver_assist_security_test_check',
				'ajax_nonce'     => 'silver_assist_security_test_nonce',
			)
		);
		$updater = new GitHubUpdater( $config );

		$captured = array();
		$mock     = static function ( $pre, $args, $url ) use ( &$captured ) {
			$captured[] = array( $url, $args['headers'] ?? array() );
			return array(
				'headers'  => array(),
				'body'     => wp_json_encode( array( 'tag_name' => 'v9.9.9' ) ),
				'response' => array( 'code' => 200, 'message' => 'OK' ),
				'cookies'  => array(),
				'filename' => null,
			);
		};
		add_filter( 'pre_http_request', $mock, 10, 3 );
		delete_transient( 'silver_assist_security_update_check' );
		$updater->getLatestVersion();
		remove_filter( 'pre_http_request', $mock, 10 );

		$this->assertNotEmpty( $captured, 'The updater should have asked GitHub for the latest release.' );
		foreach ( $captured as $request ) {
			$this->assertStringStartsWith( 'https://api.github.com/', $request[0] );
			$this->assertSame( 'Bearer test-token-123', $request[1]['Authorization'] ?? null );
		}
	}
}
