<?php
/**
 * Behavior of the wp-config constants the plugin reads
 *
 * A constant cannot be undefined or changed inside a PHP process, so the suite normally drives the
 * filters that sit beside them. These tests run in separate processes and exercise the constants
 * themselves: `SILVER_ASSIST_TRUSTED_PROXY_CIDRS`, `WP_ENVIRONMENT_TYPE` (GraphQL introspection),
 * `SCRIPT_DEBUG` (asset URLs) and `WP_DEBUG` (HSTS) (#154, G14).
 *
 * Constants that WordPress itself reads or defines during startup are handed to the child process
 * through `tests/bootstrap.php` (`SILVER_ASSIST_TEST_DEFINES`), see `run()`.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use GraphQL\Error\UserError;
use PHPUnit\Framework\TestResult;
use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\Security\GeneralSecurity;
use WP_UnitTestCase;

/**
 * Constants exercised as constants
 */
class ConstantsBehaviorTest extends WP_UnitTestCase {

	/**
	 * Constants a test needs before WordPress boots, by test method
	 *
	 * @var array<string, array<string, mixed>>
	 */
	private const BOOT_DEFINES = array(
		'test_environment_type_constant_decides_introspection' => array( 'WP_ENVIRONMENT_TYPE' => 'staging' ),
		'test_script_debug_constant_serves_unminified_assets'  => array( 'SCRIPT_DEBUG' => true ),
	);

	/**
	 * Hand the boot-time constants to the child process the test runs in
	 *
	 * @param TestResult|null $result Result collector.
	 * @return TestResult
	 */
	public function run( ?TestResult $result = null ): TestResult {
		$defines = self::BOOT_DEFINES[ $this->getName( false ) ] ?? null;
		if ( null !== $defines ) {
			putenv( 'SILVER_ASSIST_TEST_DEFINES=' . wp_json_encode( $defines ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.runtime_configuration_putenv -- Read by tests/bootstrap.php in the child process.
		}

		try {
			return parent::run( $result );
		} finally {
			putenv( 'SILVER_ASSIST_TEST_DEFINES' );
		}
	}

	/**
	 * Restore request globals
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		unset( $_SERVER['HTTP_X_FORWARDED_FOR'] );
		parent::tearDown();
	}

	/**
	 * Resolve the client IP for a peer and a forwarded chain
	 *
	 * @param string $peer      Connecting address.
	 * @param string $forwarded X-Forwarded-For value.
	 * @return string
	 */
	private function client_ip( string $peer, string $forwarded ): string {
		$_SERVER['REMOTE_ADDR']          = $peer;
		$_SERVER['HTTP_X_FORWARDED_FOR'] = $forwarded;

		return SecurityHelper::get_client_ip();
	}

	/**
	 * A comma-separated constant declares the trusted proxies
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 * @return void
	 */
	public function test_trusted_proxy_cidrs_constant_as_string(): void {
		// Control: with nothing declared, a public peer is not a proxy and its forwarded chain is ignored.
		$this->assertSame( '203.0.113.10', $this->client_ip( '203.0.113.10', '198.51.100.5, 52.84.1.1' ) );

		define( 'SILVER_ASSIST_TRUSTED_PROXY_CIDRS', '203.0.113.0/24, 52.84.0.0/15' );

		$this->assertSame( '198.51.100.5', $this->client_ip( '203.0.113.10', '198.51.100.5, 52.84.1.1' ), 'the declared hop is skipped and the first untrusted address is the client' );
		$this->assertSame( '198.51.100.99', $this->client_ip( '198.51.100.99', '10.9.9.9' ), 'a peer outside the declared CIDRs cannot choose its identity' );
	}

	/**
	 * An array constant works the same
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 * @return void
	 */
	public function test_trusted_proxy_cidrs_constant_as_array(): void {
		define( 'SILVER_ASSIST_TRUSTED_PROXY_CIDRS', array( '203.0.113.0/24' ) );

		$this->assertSame( '198.51.100.5', $this->client_ip( '203.0.113.10', '198.51.100.5' ) );
		$this->assertSame( '203.0.113.200', $this->client_ip( '203.0.113.200', '203.0.113.10' ), 'a chain made only of trusted hops falls back to the peer' );
	}

	/**
	 * WP_ENVIRONMENT_TYPE decides whether the plugin rejects GraphQL introspection
	 *
	 * This process starts with `WP_ENVIRONMENT_TYPE` defined as staging (see `run()`), no filter involved.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 * @return void
	 */
	public function test_environment_type_constant_decides_introspection(): void {
		if ( ! class_exists( 'WPGraphQL' ) ) {
			$this->markTestSkipped( 'WPGraphQL is not installed: run scripts/install-wpgraphql-for-tests.sh' );
		}

		$this->assertSame( 'staging', wp_get_environment_type(), 'the constant reached WordPress' );

		$data = array( 'query' => '{ __schema { queryType { name } } }' );
		$this->assertSame( $data, apply_filters( 'graphql_request_data', $data ), 'staging leaves introspection alone' );
	}

	/**
	 * With no WP_ENVIRONMENT_TYPE the site is production and introspection is rejected
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 * @return void
	 */
	public function test_unset_environment_type_rejects_introspection(): void {
		if ( ! class_exists( 'WPGraphQL' ) ) {
			$this->markTestSkipped( 'WPGraphQL is not installed: run scripts/install-wpgraphql-for-tests.sh' );
		}

		$this->assertFalse( defined( 'WP_ENVIRONMENT_TYPE' ) );

		$this->expectException( UserError::class );
		$this->expectExceptionMessage( 'Introspection is disabled in production' );
		apply_filters( 'graphql_request_data', array( 'query' => '{ __schema { queryType { name } } }' ) );
	}

	/**
	 * SCRIPT_DEBUG makes the plugin serve its source assets instead of the minified ones
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 * @return void
	 */
	public function test_script_debug_constant_serves_unminified_assets(): void {
		$this->assertTrue( defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG, 'the constant reached WordPress' );

		$url = SecurityHelper::get_asset_url( 'assets/css/admin.css' );

		$this->assertStringEndsWith( 'assets/css/admin.css', $url );
		$this->assertStringNotContainsString( '.min.', $url );
	}

	/**
	 * Without SCRIPT_DEBUG the minified assets are served
	 *
	 * @return void
	 */
	public function test_minified_assets_without_script_debug(): void {
		$this->assertFalse( defined( 'SCRIPT_DEBUG' ) && SCRIPT_DEBUG, 'the suite runs without SCRIPT_DEBUG' );

		$this->assertStringEndsWith( 'assets/css/admin.min.css', SecurityHelper::get_asset_url( 'assets/css/admin.css' ) );
	}

	/**
	 * WP_DEBUG alone keeps HSTS off, even over HTTPS on a production-looking host
	 *
	 * The test configuration defines `WP_DEBUG` as true and a constant cannot be unset, so the other
	 * half (HSTS sent when detection says "not development") is the filter test in
	 * `GeneralHardeningBehaviorTest::test_hsts_only_on_ssl_outside_development`; the control below
	 * shows the header is suppressed by the detection, not by something else.
	 *
	 * @return void
	 */
	public function test_wp_debug_constant_disables_hsts(): void {
		$this->assertTrue( defined( 'WP_DEBUG' ) && true === WP_DEBUG, 'precondition: WP_DEBUG is on in the test installation' );
		$this->assertSame( 'production', wp_get_environment_type() );

		$_SERVER['SERVER_NAME'] = 'www.example.com';
		$_SERVER['HTTPS']       = 'on';

		$sent = $this->headers_for_request();
		foreach ( $sent as $line ) {
			$this->assertStringStartsNotWith( 'Strict-Transport-Security', $line, 'WP_DEBUG on a production host: no HSTS' );
		}
		$this->assertNotEmpty( $sent, 'the other headers are still sent' );

		add_filter( 'silver_assist_security_is_development_environment', '__return_false' );
		$this->assertContains( 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload', $this->headers_for_request(), 'control: HSTS goes out once detection says not development' );
	}

	/**
	 * Headers GeneralSecurity would send for the current request
	 *
	 * @return array<int, string>
	 */
	private function headers_for_request(): array {
		$security = new class() extends GeneralSecurity {
			/**
			 * Headers recorded instead of sent
			 *
			 * @var array<int, string>
			 */
			public array $sent = array();

			/**
			 * Record the headers
			 *
			 * @param array<string, string> $headers Header name => value.
			 * @return void
			 */
			protected function send_headers_now( array $headers ): void {
				foreach ( $headers as $name => $value ) {
					$this->sent[] = $name . ': ' . $value;
				}
			}
		};

		$security->add_security_headers();

		return $security->sent;
	}
}
