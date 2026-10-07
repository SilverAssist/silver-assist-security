<?php
/**
 * GraphQL connection limits, query timeout and request logging
 *
 * Real `graphql()` requests through WPGraphQL, asserting what a client gets back: how many nodes a
 * connection returns when the complexity limit is tightened, the `QUERY_TIMEOUT` error for a request
 * that overran, and that the request-logging filter hands the response on untouched (#154, G5).
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

declare(strict_types=1);

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\GraphQL\GraphQLSecurity;
use SilverAssist\Security\Tests\Helpers\HeadlessTestSupport;
use WP_UnitTestCase;

/**
 * Behavior tests for the GraphQL limits that are not rate limiting or query validation
 */
class GraphQLLimitsBehaviorTest extends WP_UnitTestCase {

	use HeadlessTestSupport;

	/**
	 * Plugin component under test
	 *
	 * @var GraphQLSecurity
	 */
	private GraphQLSecurity $security;

	/**
	 * Set up
	 *
	 * @return void
	 */
	public function setUp(): void {
		parent::setUp();

		$this->require_wpgraphql();
		$this->snapshot_server();

		$this->security         = GraphQLSecurity::instance();
		$_SERVER['HTTP_HOST']   = 'example.org';
		$_SERVER['REQUEST_URI'] = '/graphql';
		$_SERVER['REMOTE_ADDR'] = '203.0.113.31';
		\wp_set_current_user( 0 );
	}

	/**
	 * Tear down
	 *
	 * @return void
	 */
	public function tearDown(): void {
		\set_time_limit( 0 );
		\delete_option( 'silver_assist_graphql_query_timeout' );
		$this->restore_headless_state();
		$this->security->refresh_configuration();
		\delete_transient( 'graphql_rate_limit_' . \md5( '203.0.113.31' ) );

		parent::tearDown();
	}

	/**
	 * Run a query through WPGraphQL
	 *
	 * @param string $query GraphQL document.
	 * @return array<string, mixed> Execution result.
	 */
	private function run_query( string $query ): array {
		$result = \graphql( array( 'query' => $query ) );

		return \is_array( $result ) ? $result : array();
	}

	/**
	 * Error codes of a result
	 *
	 * @param array<string, mixed> $result Execution result.
	 * @return array<int, string>
	 */
	private function error_codes( array $result ): array {
		$codes = array();
		foreach ( $result['errors'] ?? array() as $error ) {
			$codes[] = (string) ( $error['extensions']['code'] ?? '' );
		}

		return $codes;
	}

	/**
	 * The plugin caps how many nodes one connection returns: 100 normally, 50 in headless mode
	 *
	 * The cap is the 100 node ceiling WPGraphQL passes in, divided by the complexity limit over 100.
	 * Headless mode raises that limit to 200, so it halves the ceiling: a headless client asking for
	 * `first: 100` silently receives 50 nodes. That is how the code behaves today (suspected bug S6 in
	 * `.github/copilot-instructions.md`); the test records it so a change is deliberate.
	 *
	 * @return void
	 */
	public function test_connection_page_size_is_capped_by_the_complexity_limit(): void {
		self::factory()->post->create_many( 60 );
		$query = '{ posts(first: 100) { nodes { databaseId } } }';

		$standard = $this->run_query( $query );
		$this->assertSame( array(), $standard['errors'] ?? array(), (string) \wp_json_encode( $standard ) );
		$this->assertGreaterThanOrEqual( 60, \count( $standard['data']['posts']['nodes'] ), 'control: standard mode returns every post up to 100' );

		\update_option( 'silver_assist_graphql_headless_mode', true );
		$this->clear_graphql_config_caches();
		$this->security->refresh_configuration();

		$headless = $this->run_query( $query );
		$this->assertSame( array(), $headless['errors'] ?? array(), (string) \wp_json_encode( $headless ) );
		$this->assertCount( 50, $headless['data']['posts']['nodes'], 'the connection returns 50 nodes, not the 60 requested' );
	}

	/**
	 * Connection resolvers receive the plugin's complexity hint
	 *
	 * @return void
	 */
	public function test_connection_query_args_carry_the_complexity_hint(): void {
		self::factory()->post->create_many( 3 );

		$seen = null;
		\add_filter(
			'graphql_connection_query_args',
			static function ( $args ) use ( &$seen ) {
				$seen = $args;
				return $args;
			},
			99
		);

		$this->run_query( '{ posts(first: 30) { nodes { databaseId } } }' );

		$this->assertIsArray( $seen );
		$hint = $seen['_silver_assist_complexity_hint'] ?? null;
		$this->assertIsArray( $hint, 'the hint is added to the connection query args' );
		// WPGraphQL passes the resolver and the unfiltered args to this filter, not a source and the
		// field info, so `connection_type` is always "unknown" (suspected bug S6); nothing reads the hint.
		$this->assertSame( 5 + 3, $hint['estimated_cost'], 'base cost 5 plus one point per ten requested nodes' );
	}

	/**
	 * A request that ran past the timeout gets a QUERY_TIMEOUT error
	 *
	 * @return void
	 */
	public function test_slow_request_gets_a_query_timeout_error(): void {
		$_SERVER['REQUEST_TIME_FLOAT'] = \microtime( true );
		$fast                          = $this->run_query( '{ generalSettings { title } }' );
		$this->assertNotContains( 'QUERY_TIMEOUT', $this->error_codes( $fast ), 'control: a request that just started is fine' );

		// The request began 100 seconds ago, longer than the 30 second default limit.
		$_SERVER['REQUEST_TIME_FLOAT'] = \microtime( true ) - 100;
		$slow                          = $this->run_query( '{ generalSettings { title } }' );

		$this->assertContains( 'QUERY_TIMEOUT', $this->error_codes( $slow ) );
	}

	/**
	 * The configured timeout is applied to PHP's execution limit when the endpoint boots
	 *
	 * @return void
	 */
	public function test_execution_limit_is_set_to_the_configured_timeout(): void {
		\update_option( 'silver_assist_graphql_query_timeout', 12 );
		\set_time_limit( 0 );

		$this->security->set_execution_timeout();

		$this->assertSame( '12', \ini_get( 'max_execution_time' ) );
	}

	/**
	 * Request logging hands the response on untouched, for ordinary and suspicious queries
	 *
	 * The log line itself is not asserted: `SecurityHelper::log_security_event()` writes nothing but
	 * errors under PHPUnit.
	 *
	 * @return void
	 */
	public function test_request_logging_does_not_change_the_response(): void {
		$aliases = '';
		for ( $i = 0; $i < 12; $i++ ) {
			$aliases .= "a{$i}: generalSettings { title } ";
		}

		$ordinary   = $this->run_query( '{ generalSettings { title } }' );
		$suspicious = $this->run_query( '{ ' . $aliases . '}' );

		$this->assertSame( array(), $ordinary['errors'] ?? array() );
		$this->assertSame( array(), $suspicious['errors'] ?? array(), (string) \wp_json_encode( $suspicious ) );
		$this->assertArrayHasKey( 'a11', $suspicious['data'], 'every alias is answered' );

		$classify = new \ReflectionMethod( $this->security, 'is_suspicious_query' );
		$classify->setAccessible( true );
		// The very long query signature is 50 characters per complexity point (5000 by default).
		$this->assertTrue( $classify->invoke( $this->security, '{ generalSettings { title } }' . \str_repeat( ' ', 5000 ) ), 'a very long query is flagged for the log' );
		// The many-aliases signature is not asserted: its regular expression exhausts PCRE's backtrack limit
		// on a small query and so never matches (suspected bug S7 in `.github/copilot-instructions.md`).
		$this->assertFalse( $classify->invoke( $this->security, '{ generalSettings { title } }' ), 'an ordinary query is not' );
	}
}
