<?php
/**
 * REST API behavior tests for headless clients and forms
 *
 * Requests are dispatched through the real REST server (`rest_do_request()`), so the plugin's
 * `rest_pre_dispatch` callbacks run exactly as they do for `/wp-json/...` requests, and the tests
 * assert what a client receives (status codes and bodies), not that a hook is registered.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

declare(strict_types=1);

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\Security\RestAPISecurity;
use SilverAssist\Security\Tests\Helpers\HeadlessTestSupport;
use WP_REST_Request;
use WP_REST_Response;
use WP_REST_Server;
use WP_UnitTestCase;

/**
 * Behavior tests for REST rate limiting and the batch endpoint
 *
 * @since 1.5.4
 */
class RestAPIHeadlessBehaviorTest extends WP_UnitTestCase {
	use \SilverAssist\Security\Tests\Helpers\StoresRawOptions;


	use HeadlessTestSupport;

	/**
	 * Requests per window used by these tests (the production default is 100)
	 */
	private const LIMIT = 5;

	/**
	 * Client IP used by the tests
	 */
	private const CLIENT_IP = '203.0.113.20';

	/**
	 * Set up
	 *
	 * @return void
	 */
	public function setUp(): void {
		parent::setUp();

		$this->snapshot_server();

		\update_option( 'silver_assist_rest_batch_endpoint_protection', 1 );
		\update_option( 'silver_assist_rest_rate_limiting_enabled', 1 );
		$this->store_raw_option( 'silver_assist_rest_rate_limit_requests', self::LIMIT );
		\update_option( 'silver_assist_rest_rate_limit_window', 60 );

		// Only the instance under test: the one built at plugin load would count every request too.
		\remove_all_filters( 'rest_pre_dispatch' );
		new RestAPISecurity();

		\add_action( 'rest_api_init', array( $this, 'register_form_route' ) );

		global $wp_rest_server;
		$wp_rest_server = new WP_REST_Server(); // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Fresh server so the test route is registered.
		\do_action( 'rest_api_init', $wp_rest_server );

		$_SERVER['REMOTE_ADDR'] = self::CLIENT_IP;
		$this->clear_counters( self::CLIENT_IP );
		\wp_set_current_user( 0 );

		// The GraphQL limiter keeps its own window for this IP and reads configuration cached by
		// whichever test ran before: start from a known state instead of inheriting it.
		$this->clear_graphql_config_caches();
	}

	/**
	 * Tear down
	 *
	 * @return void
	 */
	public function tearDown(): void {
		global $wp_rest_server;
		$wp_rest_server = null; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Restore a clean server.

		$this->clear_counters( self::CLIENT_IP );
		$this->clear_counters( '198.51.100.77' );
		$this->restore_headless_state();

		parent::tearDown();
	}

	/**
	 * Register a public form-submission route shaped like Contact Form 7's
	 *
	 * @return void
	 */
	public function register_form_route(): void {
		\register_rest_route(
			'contact-form-7/v1',
			'/contact-forms/(?P<id>\d+)/feedback',
			array(
				'methods'             => 'POST',
				'callback'            => static fn (): WP_REST_Response => new WP_REST_Response( array( 'status' => 'mail_sent' ), 200 ),
				'permission_callback' => '__return_true',
			)
		);
	}

	/**
	 * Remove the rate-limit state of a client
	 *
	 * @param string $ip Client IP.
	 * @return void
	 */
	private function clear_counters( string $ip ): void {
		\delete_transient( SecurityHelper::generate_ip_transient_key( 'silver_assist_rest_window', $ip ) );
		\delete_transient( SecurityHelper::generate_ip_transient_key( 'silver_assist_rest_limit', $ip ) );
		\delete_transient( SecurityHelper::generate_ip_transient_key( 'graphql_rate_window', $ip ) );
		\delete_transient( SecurityHelper::generate_ip_transient_key( 'graphql_rate_limit', $ip ) );
	}

	/**
	 * Dispatch a request through the REST server
	 *
	 * @param string               $method HTTP method.
	 * @param string               $route  REST route.
	 * @param array<string, mixed> $params Body parameters.
	 * @return \WP_REST_Response Response.
	 */
	private function dispatch( string $method, string $route, array $params = array() ): \WP_REST_Response {
		$request = new WP_REST_Request( $method, $route );
		if ( array() !== $params ) {
			$request->set_header( 'content-type', 'application/json' );
			$request->set_body( (string) \wp_json_encode( $params ) );
		}

		return \rest_do_request( $request );
	}

	/**
	 * Status codes of consecutive anonymous requests
	 *
	 * @param int $count Number of requests.
	 * @return int[] HTTP status of each.
	 */
	private function anonymous_statuses( int $count ): array {
		$statuses = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$statuses[] = $this->dispatch( 'GET', '/wp/v2/posts' )->get_status();
		}

		return $statuses;
	}

	// ---------------------------------------------------------------------
	// Rate limit boundaries.
	// ---------------------------------------------------------------------

	/**
	 * The limit is a boundary: request N passes and request N + 1 gets a 429
	 *
	 * @return void
	 */
	public function test_anonymous_requests_pass_up_to_the_limit_and_the_next_one_gets_429(): void {
		$this->assertSame(
			array( 200, 200, 200, 200, 200, 429, 429 ),
			$this->anonymous_statuses( self::LIMIT + 2 ),
			'The first LIMIT requests succeed and every later one in the window is throttled'
		);
	}

	/**
	 * The 429 answer has the shape a REST client expects
	 *
	 * @return void
	 */
	public function test_throttled_response_is_a_429_rest_error(): void {
		$this->anonymous_statuses( self::LIMIT );

		$response = $this->dispatch( 'GET', '/wp/v2/posts' );
		$data     = $response->get_data();

		$this->assertSame( 429, $response->get_status() );
		$this->assertSame( 'rest_rate_limit_exceeded', $data['code'] );
		$this->assertSame( 'Too many requests. Please try again later.', $data['message'] );
		$this->assertSame( 429, $data['data']['status'] );
	}

	/**
	 * The limit and the window are the configured values
	 *
	 * @return void
	 */
	public function test_limit_and_window_follow_the_settings(): void {
		$this->store_raw_option( 'silver_assist_rest_rate_limit_requests', 3 );
		\update_option( 'silver_assist_rest_rate_limit_window', 120 );
		\remove_all_filters( 'rest_pre_dispatch' );
		new RestAPISecurity();

		$this->assertSame( array( 200, 200, 200, 429 ), $this->anonymous_statuses( 4 ) );

		$timeout = (int) \get_option( '_transient_timeout_' . SecurityHelper::generate_ip_transient_key( 'silver_assist_rest_limit', self::CLIENT_IP ) );
		if ( 0 === $timeout ) {
			$this->markTestSkipped( 'The counter lives in a persistent object cache, not in the options table.' );
		}

		$this->assertEqualsWithDelta( \time() + 120, $timeout, 5, 'The counter should expire after the configured window' );
	}

	/**
	 * Turning the limiter off removes the throttle
	 *
	 * @return void
	 */
	public function test_rate_limiting_can_be_disabled(): void {
		\update_option( 'silver_assist_rest_rate_limiting_enabled', 0 );
		\remove_all_filters( 'rest_pre_dispatch' );
		new RestAPISecurity();

		$this->assertSame( \array_fill( 0, self::LIMIT + 5, 200 ), $this->anonymous_statuses( self::LIMIT + 5 ) );
	}

	/**
	 * Once the window has passed the client can call again
	 *
	 * @return void
	 */
	public function test_client_is_served_again_after_the_window_expires(): void {
		global $wpdb;

		if ( \wp_using_ext_object_cache() ) {
			$this->markTestSkipped( 'This test targets the options-table counter (no persistent object cache).' );
		}

		$statuses = $this->anonymous_statuses( self::LIMIT + 1 );
		$this->assertSame( 429, \end( $statuses ), 'The client is throttled before the window expires' );

		$count_key = SecurityHelper::generate_ip_transient_key( 'silver_assist_rest_limit', self::CLIENT_IP );
		$wpdb->update( $wpdb->options, array( 'option_value' => (string) ( \time() - 1 ) ), array( 'option_name' => "_transient_timeout_{$count_key}" ) );

		$this->assertSame( 200, $this->dispatch( 'GET', '/wp/v2/posts' )->get_status(), 'The first request of a new window should pass' );
	}

	// ---------------------------------------------------------------------
	// Who is limited.
	// ---------------------------------------------------------------------

	/**
	 * Logged-in users (the block editor, wp-admin) are never throttled
	 *
	 * @return void
	 */
	public function test_logged_in_users_are_not_throttled(): void {
		\wp_set_current_user( self::factory()->user->create( array( 'role' => 'editor' ) ) );

		$this->assertSame( \array_fill( 0, self::LIMIT * 3, 200 ), $this->anonymous_statuses( self::LIMIT * 3 ) );
		$this->assertFalse(
			\get_transient( SecurityHelper::generate_ip_transient_key( 'silver_assist_rest_limit', self::CLIENT_IP ) ),
			'A logged-in request should not create a counter'
		);
	}

	/**
	 * A client that authenticates with an application password is not throttled
	 *
	 * @return void
	 */
	public function test_application_password_client_is_not_throttled(): void {
		\add_filter( 'wp_is_application_passwords_available', '__return_true' );
		\add_filter( 'application_password_is_api_request', '__return_true' );

		$user_id = self::factory()->user->create( array( 'role' => 'editor' ) );
		$created = \WP_Application_Passwords::create_new_application_password( $user_id, array( 'name' => 'Next.js' ) );
		$this->assertIsArray( $created );

		$_SERVER['PHP_AUTH_USER'] = \get_userdata( $user_id )->user_login;
		$_SERVER['PHP_AUTH_PW']   = $created[0];
		$GLOBALS['current_user']  = null; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Re-run determine_current_user.
		$this->assertSame( $user_id, \get_current_user_id(), 'The application password should authenticate the request' );

		$this->assertSame( \array_fill( 0, self::LIMIT * 3, 200 ), $this->anonymous_statuses( self::LIMIT * 3 ) );
	}

	/**
	 * Visitors behind one IP share a single budget
	 *
	 * Documented behavior: the limit is per client IP, so a school, an office or a headless server
	 * that proxies visitors shares one bucket. Public form routes (Contact Form 7) count like any
	 * other anonymous REST request. Raise `silver_assist_rest_rate_limit_requests` for such sites, or
	 * declare the proxy so each visitor is told apart (see the README).
	 *
	 * @return void
	 */
	public function test_visitors_behind_one_ip_share_the_budget_and_other_ips_are_unaffected(): void {
		// Five different visitors of the same office submit the form once each.
		for ( $visitor = 1; $visitor <= self::LIMIT; $visitor++ ) {
			$_SERVER['HTTP_USER_AGENT'] = "Visitor browser {$visitor}";
			$this->assertSame( 200, $this->dispatch( 'POST', '/contact-form-7/v1/contact-forms/1/feedback' )->get_status(), "Submission {$visitor} should pass" );
		}

		$_SERVER['HTTP_USER_AGENT'] = 'Visitor browser 6';
		$this->assertSame( 429, $this->dispatch( 'POST', '/contact-form-7/v1/contact-forms/1/feedback' )->get_status(), 'The sixth visitor on the same IP shares the exhausted budget' );

		$_SERVER['REMOTE_ADDR'] = '198.51.100.77';
		$this->assertSame( 200, $this->dispatch( 'POST', '/contact-form-7/v1/contact-forms/1/feedback' )->get_status(), 'A visitor on another IP has a budget of their own' );
	}

	/**
	 * GraphQL traffic does not consume the REST budget
	 *
	 * WPGraphQL is not served through the REST server, so GraphQL requests never reach
	 * `rest_pre_dispatch`. (This replaces the quarantined
	 * `RestAPISecurityIntegrationTest::test_graphql_endpoints_not_affected`, whose premise, a REST
	 * dispatch to `/graphql`, was wrong.)
	 *
	 * @return void
	 */
	public function test_graphql_requests_do_not_consume_the_rest_budget(): void {
		$this->require_wpgraphql();

		for ( $i = 0; $i < self::LIMIT * 2; $i++ ) {
			$result = \graphql( array( 'query' => '{ generalSettings { title } }' ) );
			$this->assertArrayNotHasKey( 'errors', $result, 'GraphQL call ' . ( $i + 1 ) . ' failed: ' . \wp_json_encode( $result['errors'] ?? null ) );
		}

		$this->assertNotFalse(
			\get_transient( SecurityHelper::generate_ip_transient_key( 'graphql_rate_limit', self::CLIENT_IP ) ),
			'The calls should have gone through the GraphQL limiter, with its own counter'
		);

		$this->assertFalse(
			\get_transient( SecurityHelper::generate_ip_transient_key( 'silver_assist_rest_limit', self::CLIENT_IP ) ),
			'GraphQL requests should not create a REST counter'
		);
		$this->assertSame( \array_fill( 0, self::LIMIT, 200 ), $this->anonymous_statuses( self::LIMIT ), 'The REST budget should be intact' );
	}

	// ---------------------------------------------------------------------
	// Batch endpoint.
	// ---------------------------------------------------------------------

	/**
	 * Anonymous clients cannot use the batch endpoint
	 *
	 * @return void
	 */
	public function test_batch_endpoint_is_forbidden_for_anonymous_clients(): void {
		$response = $this->dispatch(
			'POST',
			'/batch/v1',
			array( 'requests' => array( array( 'path' => '/wp/v2/posts', 'body' => array( 'title' => 'x' ) ) ) )
		);

		$this->assertSame( 403, $response->get_status() );
		$this->assertSame( 'rest_batch_disabled', $response->get_data()['code'] );
	}

	/**
	 * Routes that are not the batch endpoint are unaffected by the restriction
	 *
	 * @return void
	 */
	public function test_other_routes_are_not_caught_by_the_batch_restriction(): void {
		$this->assertSame( 200, $this->dispatch( 'GET', '/wp/v2/posts' )->get_status() );
		$this->assertNotSame( 'rest_batch_disabled', $this->dispatch( 'GET', '/wp/v2/types' )->get_data()['code'] ?? '' );
	}

	/**
	 * The block editor can still batch requests when the user is logged in
	 *
	 * @return void
	 */
	public function test_batch_endpoint_works_for_an_editor(): void {
		\wp_set_current_user( self::factory()->user->create( array( 'role' => 'editor' ) ) );

		$response = $this->dispatch(
			'POST',
			'/batch/v1',
			array(
				'requests' => array(
					array( 'path' => '/wp/v2/posts', 'body' => array( 'title' => 'Batched one', 'status' => 'draft' ) ),
					array( 'path' => '/wp/v2/posts', 'body' => array( 'title' => 'Batched two', 'status' => 'draft' ) ),
				),
			)
		);

		$this->assertSame( 207, $response->get_status(), 'A batch from a logged-in editor should be processed' );

		$statuses = \array_column( $response->get_data()['responses'], 'status' );
		$this->assertSame( array( 201, 201 ), $statuses, 'Both batched requests should have created a post' );
	}
}
