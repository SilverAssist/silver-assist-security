<?php
/**
 * GraphQL behavior tests for headless clients
 *
 * These tests send requests through WPGraphQL itself (`graphql()`), the same pipeline an HTTP request
 * to `/graphql` goes through (request data filters, `determine_current_user`, validation rules and
 * `do_graphql_request`), and assert what a client experiences: which requests succeed and which are
 * rejected. They do not assert that a hook is registered.
 *
 * The environment type is changed with `HeadlessTestSupport::set_environment_type()`, never by defining
 * `WP_ENVIRONMENT_TYPE`, because a constant leaks into every later test of the process.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

declare(strict_types=1);

namespace SilverAssist\Security\Tests\Integration;

use GraphQL\Error\UserError;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use SilverAssist\Security\GraphQL\GraphQLSecurity;
use SilverAssist\Security\Tests\Helpers\HeadlessTestSupport;
use WP_UnitTestCase;

/**
 * Behavior tests for GraphQL authentication, API key access, introspection, limits and rate limiting
 *
 * @since 1.5.4
 */
class GraphQLHeadlessBehaviorTest extends WP_UnitTestCase {

	use HeadlessTestSupport;

	/**
	 * Query a headless front end typically sends (Apollo adds `__typename` on its own)
	 */
	private const PAGE_QUERY = '
		query HomePage($first: Int!, $after: String) {
			posts(first: $first, after: $after, where: {orderby: {field: DATE, order: DESC}}) {
				pageInfo { hasNextPage endCursor }
				nodes {
					__typename id databaseId title slug uri date excerpt
				}
			}
			generalSettings { title description }
		}';

	/**
	 * Plugin component under test (the instance WPGraphQL hooks call)
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

		$this->security = GraphQLSecurity::instance();
		\wp_set_current_user( 0 );

		// A client request: a host and the GraphQL endpoint path, like the one a web server hands to PHP.
		$_SERVER['HTTP_HOST']   = 'example.org';
		$_SERVER['REQUEST_URI'] = '/graphql';
		$_SERVER['REMOTE_ADDR'] = '203.0.113.9';
	}

	/**
	 * Tear down
	 *
	 * @return void
	 */
	public function tearDown(): void {
		$this->restore_headless_state();
		\delete_transient( 'graphql_rate_limit_' . \md5( '203.0.113.9' ) );
		\delete_transient( 'graphql_rate_limit_{md5(203.0.113.9)}' );

		parent::tearDown();
	}

	/**
	 * Run a query through WPGraphQL
	 *
	 * @param string               $query     GraphQL document.
	 * @param array<string, mixed> $variables Variables.
	 * @return array<string, mixed> Execution result.
	 */
	private function run_query( string $query, array $variables = array() ): array {
		$result = \graphql(
			array(
				'query'     => $query,
				'variables' => $variables,
			)
		);

		return \is_array( $result ) ? $result : array();
	}

	/**
	 * Error messages of a result
	 *
	 * @param array<string, mixed> $result Execution result.
	 * @return string Messages joined with a space.
	 */
	private function error_messages( array $result ): string {
		$messages = array();
		foreach ( $result['errors'] ?? array() as $error ) {
			$messages[] = (string) ( $error['message'] ?? '' );
		}

		return \implode( ' ', $messages );
	}

	/**
	 * Resolve the user for a request that sends the API key in the given way
	 *
	 * @param string $key    API key to send.
	 * @param string $header Which header carries it: `x-api-key` or `bearer`.
	 * @return int Resolved user ID.
	 */
	private function authenticate_with_api_key( string $key, string $header ): int {
		if ( 'bearer' === $header ) {
			$_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . $key;
		} else {
			$_SERVER['HTTP_X_API_KEY'] = $key;
		}

		return $this->resolve_current_user();
	}

	// ---------------------------------------------------------------------
	// Authentication.
	// ---------------------------------------------------------------------

	/**
	 * By default the plugin does not close the endpoint: it follows WPGraphQL's own setting
	 *
	 * Documented behavior: `restrict_endpoint_to_logged_in_users` is off in WPGraphQL, so public
	 * content stays readable by anonymous visitors and the plugin does not change that.
	 *
	 * @return void
	 */
	public function test_anonymous_can_query_public_data_when_endpoint_is_not_restricted(): void {
		$this->set_environment_type( 'production' );
		$this->set_graphql_settings( array() );
		$this->security->enforce_authentication_requirement();

		$result = $this->run_query( '{ generalSettings { title } }' );

		$this->assertArrayNotHasKey( 'errors', $result, 'An anonymous query of public data should work by default' );
		$this->assertSame( 'Test Blog', $result['data']['generalSettings']['title'] );
	}

	/**
	 * When the endpoint is restricted, an anonymous request is rejected
	 *
	 * @return void
	 */
	public function test_anonymous_request_is_rejected_when_endpoint_requires_authentication(): void {
		$this->set_environment_type( 'production' );
		$this->set_graphql_settings( array( 'restrict_endpoint_to_logged_in_users' => 'on' ) );
		$this->security->enforce_authentication_requirement();

		$this->assertSame( 0, $this->resolve_current_user(), 'The request has no credentials' );

		$this->expectException( UserError::class );
		$this->expectExceptionMessage( 'Authentication required' );

		$this->run_query( '{ generalSettings { title } }' );
	}

	/**
	 * The plugin's local/development exemption does not open an endpoint WPGraphQL restricts
	 *
	 * In `local` and `development` the plugin skips its own authentication check for tooling, but
	 * WPGraphQL enforces `restrict_endpoint_to_logged_in_users` itself and the plugin must not
	 * downgrade that.
	 *
	 * @return void
	 */
	public function test_local_environment_does_not_downgrade_wpgraphql_authentication(): void {
		$this->set_environment_type( 'local' );
		$this->set_graphql_settings( array( 'restrict_endpoint_to_logged_in_users' => 'on' ) );
		$this->security->enforce_authentication_requirement();

		$result = $this->run_query( '{ generalSettings { title } }' );

		$this->assertNotEmpty( $result['errors'] ?? array(), 'WPGraphQL should still reject the anonymous request' );
		$this->assertEmpty( $result['data']['generalSettings'] ?? null, 'No data should be returned to an anonymous client' );
	}

	/**
	 * A legitimate headless request that carries the API key succeeds
	 *
	 * Covers both ways the key can be sent. This is the request a Next.js server makes.
	 *
	 * @dataProvider api_key_transports
	 *
	 * @param string $header Header carrying the key.
	 * @return void
	 */
	public function test_api_key_request_succeeds_when_endpoint_requires_authentication( string $header ): void {
		$this->set_environment_type( 'production' );
		$this->set_graphql_settings( array( 'restrict_endpoint_to_logged_in_users' => 'on' ) );
		$this->security->enforce_authentication_requirement();

		$service_user_id = $this->create_api_key_service_user( 'headless-key-123' );

		$this->assertSame( $service_user_id, $this->authenticate_with_api_key( 'headless-key-123', $header ), 'The API key should resolve to the service account' );

		$result = $this->run_query( '{ generalSettings { title } }' );

		$this->assertArrayNotHasKey( 'errors', $result, 'An API key request should not be rejected' );
		$this->assertSame( 'Test Blog', $result['data']['generalSettings']['title'] );
	}

	/**
	 * A wrong API key is treated as anonymous and rejected
	 *
	 * @dataProvider api_key_transports
	 *
	 * @param string $header Header carrying the key.
	 * @return void
	 */
	public function test_wrong_api_key_is_rejected_when_endpoint_requires_authentication( string $header ): void {
		$this->set_environment_type( 'production' );
		$this->set_graphql_settings( array( 'restrict_endpoint_to_logged_in_users' => 'on' ) );
		$this->security->enforce_authentication_requirement();

		$this->create_api_key_service_user( 'headless-key-123' );

		$this->assertSame( 0, $this->authenticate_with_api_key( 'not-the-key', $header ), 'A wrong key should not authenticate' );

		$this->expectException( UserError::class );
		$this->expectExceptionMessage( 'Authentication required' );

		$this->run_query( '{ generalSettings { title } }' );
	}

	/**
	 * Header transports accepted for the API key
	 *
	 * @return array<string, array{0: string}>
	 */
	public static function api_key_transports(): array {
		return array(
			'X-API-Key header'          => array( 'x-api-key' ),
			'Authorization Bearer'      => array( 'bearer' ),
		);
	}

	/**
	 * Application passwords keep working on the GraphQL endpoint
	 *
	 * WPGraphQL authenticates `Authorization: Basic` application passwords itself; the plugin must
	 * neither break that nor require the API key on top of it.
	 *
	 * @return void
	 */
	public function test_application_password_authenticates_graphql_request(): void {
		$this->set_environment_type( 'production' );
		$this->set_graphql_settings( array( 'restrict_endpoint_to_logged_in_users' => 'on' ) );
		$this->security->enforce_authentication_requirement();

		\add_filter( 'wp_is_application_passwords_available', '__return_true' );

		$user_id = self::factory()->user->create( array( 'role' => 'editor' ) );
		$user    = \get_userdata( $user_id );
		$created = \WP_Application_Passwords::create_new_application_password( $user_id, array( 'name' => 'Next.js' ) );
		$this->assertIsArray( $created );

		$_SERVER['PHP_AUTH_USER'] = $user->user_login;
		$_SERVER['PHP_AUTH_PW']   = $created[0];

		$this->assertSame( $user_id, $this->resolve_current_user(), 'An application password should authenticate a GraphQL request' );

		$result = $this->run_query( '{ generalSettings { title } }' );

		$this->assertArrayNotHasKey( 'errors', $result );
		$this->assertSame( 'Test Blog', $result['data']['generalSettings']['title'] );
	}

	/**
	 * The API key only authenticates requests to the GraphQL endpoint
	 *
	 * A valid key must not log a client in on REST or any other URL, even when the URL contains the
	 * text `/graphql`.
	 *
	 * @return void
	 */
	public function test_api_key_does_not_authenticate_other_endpoints(): void {
		$this->create_api_key_service_user( 'headless-key-123' );

		foreach ( array( '/wp-json/wp/v2/users/me', '/wp-json/wp/v2/users/me?redirect=/graphql', '/wp-json/wp/v2/posts/graphql-intro', '/graphql-docs/' ) as $uri ) {
			$_SERVER['REQUEST_URI']    = $uri;
			$_SERVER['HTTP_X_API_KEY'] = 'headless-key-123';

			$this->assertSame( 0, $this->resolve_current_user(), "The API key must not authenticate {$uri}" );
		}
	}

	/**
	 * The API key works on a custom GraphQL endpoint path
	 *
	 * Headless sites commonly change the endpoint in the WPGraphQL settings; the key must follow it.
	 *
	 * @return void
	 */
	public function test_api_key_works_on_custom_graphql_endpoint(): void {
		$original_route = \WPGraphQL\Router::$route;
		\WPGraphQL\Router::$route = 'headless-api';

		try {
			$service_user_id = $this->create_api_key_service_user( 'headless-key-123' );

			$_SERVER['REQUEST_URI']    = '/headless-api';
			$_SERVER['HTTP_X_API_KEY'] = 'headless-key-123';

			$this->assertSame( $service_user_id, $this->resolve_current_user(), 'The API key should work on the configured endpoint' );
		} finally {
			\WPGraphQL\Router::$route = $original_route;
		}
	}

	/**
	 * WPGraphQL's cookie CSRF protection is not weakened by an X-API-Key header
	 *
	 * WPGraphQL downgrades a cookie-authenticated request without a nonce to guest unless a plugin
	 * answers `graphql_authentication_errors` with `false`. The plugin must do that only for a request
	 * that was really authenticated by the API key.
	 *
	 * @return void
	 */
	public function test_graphql_authentication_errors_filter_only_bypasses_for_real_api_key_login(): void {
		$admin_id = self::factory()->user->create( array( 'role' => 'administrator' ) );
		\wp_set_current_user( $admin_id );
		$_SERVER['HTTP_X_API_KEY'] = 'some-header-value';

		$this->assertNull( \apply_filters( 'graphql_authentication_errors', null ), 'A cookie user sending an unrelated X-API-Key keeps WPGraphQL nonce check' );

		$this->create_api_key_service_user( 'headless-key-123' );
		$_SERVER['HTTP_X_API_KEY'] = 'headless-key-123';
		$this->assertGreaterThan( 0, $this->resolve_current_user() );

		$this->assertFalse( \apply_filters( 'graphql_authentication_errors', null ), 'A request authenticated by the API key must not be downgraded to guest' );
	}

	// ---------------------------------------------------------------------
	// Introspection per environment.
	// ---------------------------------------------------------------------

	/**
	 * In production introspection is rejected, for anonymous clients and authenticated ones
	 *
	 * The environment is the one WordPress reports (`wp_get_environment_type()`), which is
	 * `production` when nothing is configured.
	 *
	 * @return void
	 */
	public function test_introspection_is_rejected_in_production_even_for_administrators(): void {
		$this->set_environment_type( 'production' );
		$this->set_graphql_settings( array( 'public_introspection_enabled' => 'on' ) );

		\wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );

		$this->expectException( UserError::class );
		$this->expectExceptionMessage( 'Introspection is disabled in production' );

		$this->run_query( '{ __schema { queryType { name } } }' );
	}

	/**
	 * Outside production the plugin does not block introspection
	 *
	 * Tooling (GraphiQL, codegen) needs it on local, development and staging.
	 *
	 * @dataProvider non_production_environments
	 *
	 * @param string $environment Environment type.
	 * @return void
	 */
	public function test_introspection_is_not_blocked_by_the_plugin_outside_production( string $environment ): void {
		$this->set_environment_type( $environment );

		$data = array( 'query' => '{ __schema { queryType { name } } }' );

		$this->assertSame( $data, \apply_filters( 'graphql_request_data', $data ), "The plugin should let introspection through in {$environment}" );
	}

	/**
	 * Environments where the plugin leaves introspection alone
	 *
	 * @return array<string, array{0: string}>
	 */
	public static function non_production_environments(): array {
		return array(
			'local'       => array( 'local' ),
			'development' => array( 'development' ),
			'staging'     => array( 'staging' ),
		);
	}

	/**
	 * Only real `__schema` and `__type` selections are introspection
	 *
	 * The text `__schema` inside a string argument is ordinary data (a search term, for example).
	 *
	 * @return void
	 */
	public function test_introspection_words_inside_string_literals_are_allowed_in_production(): void {
		$this->set_environment_type( 'production' );

		$result = $this->run_query( '{ posts(where: {search: "__schema __type"}) { nodes { id } } } # __schema' );

		$this->assertArrayNotHasKey( 'errors', $result, 'A search term is not introspection: ' . $this->error_messages( $result ) );
	}

	/**
	 * Introspection is rejected however it is written
	 *
	 * @dataProvider introspection_queries
	 *
	 * @param string $query Query using an introspection entry point.
	 * @return void
	 */
	public function test_introspection_forms_are_rejected_in_production( string $query ): void {
		$this->set_environment_type( 'production' );

		$this->expectException( UserError::class );
		$this->expectExceptionMessage( 'Introspection is disabled in production' );

		$this->run_query( $query );
	}

	/**
	 * Ways to reach introspection
	 *
	 * @return array<string, array{0: string}>
	 */
	public static function introspection_queries(): array {
		return array(
			'__schema'           => array( '{ __schema { queryType { name } } }' ),
			'__type'             => array( '{ __type(name: "Post") { name } }' ),
			'aliased __schema'   => array( '{ s: __schema { queryType { name } } }' ),
			'inside a fragment'  => array( 'query { ...Intro } fragment Intro on RootQuery { __schema { queryType { name } } }' ),
			'named operation'    => array( 'query Intro { __type(name: "Post") { name } }' ),
		);
	}

	/**
	 * `__typename` is not introspection, and clients add it to every query
	 *
	 * Apollo Client and urql append `__typename` automatically. Blocking it in production breaks every
	 * headless page.
	 *
	 * @return void
	 */
	public function test_typename_is_allowed_in_production(): void {
		$this->set_environment_type( 'production' );

		$result = $this->run_query( self::PAGE_QUERY, array( 'first' => 5 ) );

		$this->assertArrayNotHasKey( 'errors', $result, 'A typical headless query (with __typename) should run in production: ' . $this->error_messages( $result ) );
		$this->assertArrayHasKey( 'posts', $result['data'] );
	}

	// ---------------------------------------------------------------------
	// Query limits.
	// ---------------------------------------------------------------------

	/**
	 * A realistic page query is within the limits in standard and headless mode
	 *
	 * @return void
	 */
	public function test_legitimate_page_query_is_accepted_in_standard_and_headless_mode(): void {
		foreach ( array( 0, 1 ) as $headless ) {
			\update_option( 'silver_assist_graphql_headless_mode', $headless );
			$this->clear_graphql_config_caches();

			$result = $this->run_query( self::PAGE_QUERY, array( 'first' => 5 ) );

			$this->assertArrayNotHasKey( 'errors', $result, "A normal page query should pass (headless={$headless}): " . $this->error_messages( $result ) );
		}
	}

	/**
	 * Listing queries that page through content stay within the standard complexity limit
	 *
	 * The complexity estimate counts each `first:` argument (one point per ten items), so three
	 * full pages of 100 items are fine; the limit exists to stop queries that ask for far more.
	 *
	 * @return void
	 */
	public function test_full_page_listings_are_within_the_standard_complexity_limit(): void {
		$result = $this->run_query(
			'{
				posts(first: 100) { nodes { __typename id title slug } }
				pages(first: 100) { nodes { __typename id title slug } }
				categories(first: 100) { nodes { __typename id name slug } }
			}'
		);

		$this->assertArrayNotHasKey( 'errors', $result, 'Three 100-item listings should pass: ' . $this->error_messages( $result ) );
	}

	/**
	 * Too many aliases are rejected
	 *
	 * @return void
	 */
	public function test_too_many_aliases_are_rejected(): void {
		$this->expectException( UserError::class );
		$this->expectExceptionMessage( 'too many aliases' );

		$this->run_query( $this->aliased_query( 25 ) );
	}

	/**
	 * Query limits also apply to every query of a batched request
	 *
	 * WPGraphQL accepts an array of queries in one HTTP request. Splitting an abusive query into a
	 * batch must not skip the limits.
	 *
	 * @return void
	 */
	public function test_limits_apply_to_batched_queries(): void {
		$this->expectException( UserError::class );
		$this->expectExceptionMessage( 'too many aliases' );

		\graphql(
			array(
				array( 'query' => '{ generalSettings { title } }' ),
				array( 'query' => $this->aliased_query( 25 ) ),
			)
		);
	}

	/**
	 * Excessive depth is rejected, in a single request and in a batch
	 *
	 * @return void
	 */
	public function test_excessive_depth_is_rejected_single_and_batched(): void {
		$deep = '{ posts { nodes { author { node { posts { nodes { author { node { posts { nodes { author { node { posts { nodes { author { node { name } } } } } } } } } } } } } } } } }';

		foreach ( array( array( 'query' => $deep ), array( array( 'query' => $deep ) ) ) as $request ) {
			try {
				\graphql( $request );
				$this->fail( 'A query deeper than the limit should be rejected' );
			} catch ( UserError $e ) {
				$this->assertStringContainsString( 'depth', $e->getMessage() );
			}
		}
	}

	/**
	 * A query over the complexity limit is rejected by validation
	 *
	 * @return void
	 */
	public function test_complex_query_is_rejected(): void {
		$parts = array();
		for ( $i = 1; $i <= 10; $i++ ) {
			$parts[] = "p{$i}: posts(first: 100) { nodes { id } }";
		}

		$result = $this->run_query( '{ ' . \implode( ' ', $parts ) . ' }' );

		$this->assertStringContainsString( 'complexity', $this->error_messages( $result ), 'A query above the complexity limit should fail validation' );
	}

	/**
	 * Build a query with a number of aliased connections
	 *
	 * @param int $count Number of aliases.
	 * @return string GraphQL document.
	 */
	private function aliased_query( int $count ): string {
		$parts = array();
		for ( $i = 1; $i <= $count; $i++ ) {
			$parts[] = "a{$i}: posts { nodes { id } }";
		}

		return '{ ' . \implode( ' ', $parts ) . ' }';
	}

	// ---------------------------------------------------------------------
	// Rate limiting.
	// ---------------------------------------------------------------------

	/**
	 * Anonymous requests are throttled per client IP
	 *
	 * @return void
	 */
	public function test_anonymous_requests_are_rate_limited(): void {
		$limit = GraphQLConfigManager::get_instance()->get_rate_limiting_config()['requests_per_minute'];

		for ( $i = 1; $i <= $limit; $i++ ) {
			$result = $this->run_query( '{ generalSettings { title } }' );
			$this->assertArrayNotHasKey( 'errors', $result, "Request {$i} of {$limit} should pass" );
		}

		$this->expectException( UserError::class );
		$this->expectExceptionMessage( 'Rate limit exceeded' );

		$this->run_query( '{ generalSettings { title } }' );
	}

	/**
	 * The rate limiter keeps raw client IPs out of the options table
	 *
	 * @return void
	 */
	public function test_rate_limit_counter_is_keyed_by_hashed_ip(): void {
		global $wpdb;

		$this->run_query( '{ generalSettings { title } }' );

		$raw = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s", '%graphql_rate_limit%203.0.113.9%' ) );
		$this->assertSame( 0, (int) $raw, 'The raw IP should not be part of the option name' );

		$this->assertNotFalse( \get_transient( 'graphql_rate_limit_' . \md5( '203.0.113.9' ) ), 'The counter should be keyed by the md5 of the IP' );
	}

	/**
	 * The rate limit is a fixed window: accepted requests do not extend it
	 *
	 * A counter whose lifetime is renewed by every request turns "N per minute" into "N until a
	 * full minute of silence", so sparse but steady traffic would be locked out for good.
	 *
	 * @return void
	 */
	public function test_rate_limit_window_is_fixed_and_resets_when_it_ends(): void {
		global $wpdb;

		if ( \wp_using_ext_object_cache() ) {
			$this->markTestSkipped( 'This test targets the options-table counter (no persistent object cache).' );
		}

		$key     = 'graphql_rate_limit_' . \md5( '203.0.113.9' );
		$timeout = "_transient_timeout_{$key}";

		$this->run_query( '{ generalSettings { title } }' );
		$wpdb->update( $wpdb->options, array( 'option_value' => (string) ( \time() + 10 ) ), array( 'option_name' => $timeout ) );

		$this->run_query( '{ generalSettings { title } }' );

		\wp_cache_flush(); // The rows were changed with direct queries.
		$this->assertEqualsWithDelta( \time() + 10, (int) \get_option( $timeout ), 2, 'A later request must not renew the window' );
		$this->assertSame( 2, (int) \get_transient( $key ), 'Both requests in the window are counted' );

		$wpdb->update( $wpdb->options, array( 'option_value' => (string) ( \time() - 1 ) ), array( 'option_name' => $timeout ) );
		\wp_cache_flush();
		$this->run_query( '{ generalSettings { title } }' );

		\wp_cache_flush();
		$this->assertSame( 1, (int) \get_transient( $key ), 'The first request after the window starts a new count' );
	}

	/**
	 * Requests authenticated with the API key are not throttled
	 *
	 * The headless server calls from one IP on behalf of every visitor, so a per-IP cap would turn
	 * into an outage of the site. The key is the credential; the limiter protects anonymous traffic.
	 *
	 * @return void
	 */
	public function test_api_key_requests_are_not_rate_limited(): void {
		$limit = GraphQLConfigManager::get_instance()->get_rate_limiting_config()['requests_per_minute'];

		$this->create_api_key_service_user( 'headless-key-123' );
		$_SERVER['HTTP_X_API_KEY'] = 'headless-key-123';
		$this->assertGreaterThan( 0, $this->resolve_current_user() );

		for ( $i = 1; $i <= $limit + 5; $i++ ) {
			$result = $this->run_query( '{ generalSettings { title } }' );
			$this->assertArrayNotHasKey( 'errors', $result, "Authenticated request {$i} should pass" );
		}
	}

	// ---------------------------------------------------------------------
	// Response headers.
	// ---------------------------------------------------------------------

	/**
	 * Headers WPGraphQL would send with its HTTP response, after every filter ran
	 *
	 * WPGraphQL answers on `parse_request` and exits before `send_headers`, so the filter
	 * `graphql_response_headers_to_send` is the only extension point that reaches that response.
	 *
	 * @return array<string, string>
	 */
	private function graphql_response_headers(): array {
		$method = new \ReflectionMethod( \WPGraphQL\Router::class, 'get_response_headers' );
		$method->setAccessible( true );

		return $method->invoke( null );
	}

	/**
	 * A GraphQL response carries the baseline security headers
	 *
	 * @return void
	 */
	public function test_graphql_response_carries_the_baseline_security_headers(): void {
		$headers = $this->graphql_response_headers();

		$this->assertSame( 'nosniff', $headers['X-Content-Type-Options'] ?? null );
		$this->assertSame( 'SAMEORIGIN', $headers['X-Frame-Options'] ?? null );
		$this->assertSame( 'strict-origin-when-cross-origin', $headers['Referrer-Policy'] ?? null );
		$this->assertArrayHasKey( 'Permissions-Policy', $headers );
		$this->assertArrayHasKey( 'Content-Type', $headers, 'WPGraphQL own headers are kept' );
		$this->assertArrayHasKey( 'Access-Control-Allow-Origin', $headers, 'WPGraphQL CORS headers are kept' );
	}

	/**
	 * The headers follow the site wide header filter and the headers other code already set
	 *
	 * @return void
	 */
	public function test_graphql_response_headers_follow_the_site_filter_and_keep_earlier_values(): void {
		\add_filter(
			'silver_assist_security_headers',
			static function ( array $headers ): array {
				$headers['Permissions-Policy'] = 'geolocation=(self)';
				unset( $headers['X-XSS-Protection'] );
				return $headers;
			}
		);
		\add_filter(
			'graphql_response_headers_to_send',
			static function ( array $headers ): array {
				$headers['Referrer-Policy'] = 'no-referrer';
				return $headers;
			},
			5
		);

		$headers = $this->graphql_response_headers();

		$this->assertSame( 'geolocation=(self)', $headers['Permissions-Policy'] );
		$this->assertArrayNotHasKey( 'X-XSS-Protection', $headers );
		$this->assertSame( 'no-referrer', $headers['Referrer-Policy'], 'A header another filter set first is not overwritten' );
	}

	/**
	 * A custom endpoint path gets the same headers
	 *
	 * @return void
	 */
	public function test_custom_endpoint_response_carries_the_baseline_security_headers(): void {
		$original_route           = \WPGraphQL\Router::$route;
		\WPGraphQL\Router::$route = 'headless-api';
		$_SERVER['REQUEST_URI']   = '/headless-api';

		try {
			$this->assertSame( 'nosniff', $this->graphql_response_headers()['X-Content-Type-Options'] ?? null );
		} finally {
			\WPGraphQL\Router::$route = $original_route;
		}
	}

	/**
	 * No front-end hook matches URLs by the text "/graphql"
	 *
	 * The old `send_headers` callback never ran for the GraphQL response and would have framed or
	 * uncached a page such as `/graphql-guide/`.
	 *
	 * @return void
	 */
	public function test_no_send_headers_hook_matches_graphql_by_substring(): void {
		$this->assertFalse( \has_action( 'send_headers', array( $this->security, 'add_graphql_security_headers' ) ) );
		$this->assertFalse( \method_exists( $this->security, 'add_graphql_security_headers' ) );
	}

	// ---------------------------------------------------------------------
	// Dead introspection hooks.
	// ---------------------------------------------------------------------

	/**
	 * The plugin does not register hooks WPGraphQL never fires
	 *
	 * `graphql_introspection_enabled`, `graphql_show_in_graphiql` and
	 * `WPGraphQL\Type\Introspection::register_introspection_fields` do not exist in WPGraphQL, so
	 * hooking them only suggests a protection that is not there. Introspection is rejected by
	 * `validate_query_before_execution` and WPGraphQL's own rule.
	 *
	 * @return void
	 */
	public function test_production_does_not_register_hooks_wpgraphql_never_fires(): void {
		$this->set_environment_type( 'production' );
		$this->set_graphql_settings( array( 'public_introspection_enabled' => 'on' ) );
		\remove_all_filters( 'graphql_introspection_enabled' );
		\remove_all_filters( 'graphql_show_in_graphiql' );

		\do_action( 'init' );
		\do_action( 'graphql_init' );

		$this->assertFalse( \has_filter( 'graphql_introspection_enabled' ) );
		$this->assertFalse( \has_filter( 'graphql_show_in_graphiql' ) );
		$this->assertFalse( \method_exists( $this->security, 'disable_introspection_in_production' ) );
	}

	/**
	 * Anonymous introspection is rejected in production, with WPGraphQL's public setting on or off
	 *
	 * @return void
	 */
	public function test_anonymous_introspection_is_rejected_in_production_with_the_public_setting_on(): void {
		$this->set_environment_type( 'production' );
		$this->set_graphql_settings( array( 'public_introspection_enabled' => 'on' ) );
		\wp_set_current_user( 0 );

		$this->expectException( UserError::class );
		$this->expectExceptionMessage( 'Introspection is disabled in production' );

		$this->run_query( '{ __schema { queryType { name } } }' );
	}

	// ---------------------------------------------------------------------
	// Failing validation helpers.
	// ---------------------------------------------------------------------

	/**
	 * Validation helpers refuse the query when they fail
	 *
	 * A query that is not a string makes the counting helpers throw a TypeError (an Error, not an Exception); an error while validating
	 * must not become "no errors found".
	 *
	 * @dataProvider validation_helpers
	 *
	 * @param string $helper Method name.
	 * @return void
	 */
	public function test_validation_helpers_fail_closed_when_they_error( string $helper ): void {
		$errors = $this->security->$helper( array( 'request_data' => array( 'query' => array( 'not', 'a', 'string' ) ) ) );

		$this->assertNotEmpty( $errors, "{$helper} must not allow a query it could not check" );
		$this->assertInstanceOf( UserError::class, $errors[0] );
	}

	/**
	 * Helpers that parse the query text
	 *
	 * @return array<string, array{0: string}>
	 */
	public static function validation_helpers(): array {
		return array(
			'depth'            => array( 'validate_query_depth' ),
			'aliases'          => array( 'validate_aliases' ),
			'directives'       => array( 'validate_directives' ),
			'field duplicates' => array( 'validate_field_duplicates' ),
		);
	}
}
