<?php
/**
 * GraphQL connection limits, query timeout and request logging
 *
 * Real `graphql()` requests through WPGraphQL, asserting what a client gets back: how many nodes a
 * connection returns, the `QUERY_TIMEOUT` error for a request that overran, and that request
 * logging flags many-alias queries (#154 G5, #175).
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
	 * A client gets every node it asked for, up to WPGraphQL's own 100 node ceiling, in both modes
	 *
	 * Headless mode raises the complexity limit to 200. The plugin used to divide the connection ceiling
	 * by that limit over 100, so a headless client asking for `first: 100` silently received 50 nodes
	 * (S6, #175). Page size is not the plugin's to cap: the complexity rule already counts `first` and
	 * rejects an over-budget query with an error.
	 *
	 * @return void
	 */
	public function test_connection_returns_the_requested_nodes_in_standard_and_headless_mode(): void {
		self::factory()->post->create_many( 60 );
		$query = '{ posts(first: 100) { nodes { databaseId } } }';

		$standard = $this->run_query( $query );
		$this->assertSame( array(), $standard['errors'] ?? array(), (string) \wp_json_encode( $standard ) );
		$this->assertGreaterThanOrEqual( 60, \count( $standard['data']['posts']['nodes'] ), 'standard mode returns every post up to 100' );

		\update_option( 'silver_assist_graphql_headless_mode', true );
		$this->clear_graphql_config_caches();
		$this->security->refresh_configuration();

		$headless = $this->run_query( $query );
		$this->assertSame( array(), $headless['errors'] ?? array(), (string) \wp_json_encode( $headless ) );
		$this->assertGreaterThanOrEqual( 60, \count( $headless['data']['posts']['nodes'] ), 'headless mode returns every post up to 100 too' );
		$this->assertSame( \count( $standard['data']['posts']['nodes'] ), \count( $headless['data']['posts']['nodes'] ) );
	}

	/**
	 * Messages of every error of a result, joined
	 *
	 * @param array<string, mixed> $result Execution result.
	 * @return string
	 */
	private function error_messages( array $result ): string {
		$messages = array();
		foreach ( $result['errors'] ?? array() as $error ) {
			$messages[] = (string) ( $error['message'] ?? '' );
		}

		return \implode( ' ', $messages );
	}

	/**
	 * `last:` is counted by the complexity budget exactly like `first:`
	 *
	 * The estimate counted only `first:`, so `posts(last: 1000)` cost nothing (#185). The two forms of
	 * one page size must be rejected alike, in the same position of the argument list or not.
	 *
	 * @return void
	 */
	public function test_last_is_rejected_over_the_complexity_budget_like_first(): void {
		foreach ( array( 'first', 'last' ) as $argument ) {
			$result = $this->run_query( "{ posts({$argument}: 1000) { nodes { id } } }" );
			$this->assertStringContainsString( 'complexity', $this->error_messages( $result ), "{$argument}: 1000 is over the budget" );
		}

		$late = $this->run_query( '{ posts(where: {search: "x"}, last: 1000) { nodes { id } } }' );
		$this->assertStringContainsString( 'complexity', $this->error_messages( $late ), 'last: after another argument is counted too' );

		$ok = $this->run_query( '{ posts(last: 100) { nodes { id } } }' );
		$this->assertSame( array(), $ok['errors'] ?? array(), (string) \wp_json_encode( $ok ) );
	}

	/**
	 * `last: 100` returns up to 100 nodes in standard and headless mode
	 *
	 * @return void
	 */
	public function test_last_100_returns_every_node_up_to_the_ceiling(): void {
		self::factory()->post->create_many( 105 );
		$query = '{ posts(last: 100) { nodes { databaseId } } }';

		$standard = $this->run_query( $query );
		$this->assertSame( array(), $standard['errors'] ?? array(), (string) \wp_json_encode( $standard ) );
		$this->assertCount( 100, $standard['data']['posts']['nodes'] );

		\update_option( 'silver_assist_graphql_headless_mode', true );
		$this->clear_graphql_config_caches();
		$this->security->refresh_configuration();

		$headless = $this->run_query( $query );
		$this->assertSame( array(), $headless['errors'] ?? array(), (string) \wp_json_encode( $headless ) );
		$this->assertCount( 100, $headless['data']['posts']['nodes'] );
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
	 * Raised security events
	 *
	 * @var array<int, array{0: string, 1: string, 2: array<string, mixed>}>
	 */
	private array $events = array();

	/**
	 * Record every security event raised from now on
	 *
	 * @return void
	 */
	private function spy_on_security_events(): void {
		$this->events = array();
		\add_action(
			'silver_assist_security_event',
			function ( string $type, string $message, array $context ): void {
				$this->events[] = array( $type, $message, $context );
			},
			10,
			3
		);
	}

	/**
	 * Types of the security events raised so far
	 *
	 * @return array<int, string>
	 */
	private function event_types(): array {
		return \array_column( $this->events, 0 );
	}

	/**
	 * Build a query with a number of aliased fields
	 *
	 * @param int $count Number of aliases.
	 * @return string GraphQL document.
	 */
	private function aliased_query( int $count ): string {
		$aliases = '';
		for ( $i = 0; $i < $count; $i++ ) {
			$aliases .= "a{$i}: generalSettings { title } ";
		}

		return '{ ' . $aliases . '}';
	}

	/**
	 * A many-alias query is answered and flagged in the security log
	 *
	 * The standard alias limit is 20, so 12 aliases pass validation; the log flags from half the limit
	 * (10). The log signature used to be a regular expression that exhausted PCRE's backtrack limit and
	 * never matched (S7, #175).
	 *
	 * @return void
	 */
	public function test_many_alias_query_is_flagged_in_the_security_log(): void {
		$this->spy_on_security_events();

		$result = $this->run_query( $this->aliased_query( 12 ) );

		$this->assertSame( array(), $result['errors'] ?? array(), (string) \wp_json_encode( $result ) );
		$this->assertArrayHasKey( 'a11', $result['data'], 'every alias is answered' );
		$this->assertContains( 'GRAPHQL_SUSPICIOUS_QUERY', $this->event_types() );
	}

	/**
	 * Few aliases and ordinary queries are not flagged
	 *
	 * @return void
	 */
	public function test_ordinary_and_few_alias_queries_are_not_flagged(): void {
		$this->spy_on_security_events();

		$this->run_query( '{ generalSettings { title } }' );
		$this->run_query( $this->aliased_query( 4 ) );

		$this->assertNotContains( 'GRAPHQL_SUSPICIOUS_QUERY', $this->event_types() );
	}

	/**
	 * The alias signature in headless mode starts at half of the headless limit (25 of 50)
	 *
	 * @return void
	 */
	public function test_alias_flag_threshold_follows_the_headless_limit(): void {
		\update_option( 'silver_assist_graphql_headless_mode', true );
		$this->clear_graphql_config_caches();
		$this->security->refresh_configuration();
		$this->spy_on_security_events();

		$this->run_query( $this->aliased_query( 12 ) );
		$this->assertNotContains( 'GRAPHQL_SUSPICIOUS_QUERY', $this->event_types(), '12 aliases are below the headless threshold' );

		$this->run_query( $this->aliased_query( 30 ) );
		$this->assertContains( 'GRAPHQL_SUSPICIOUS_QUERY', $this->event_types() );
	}

	/**
	 * A very long query is flagged for the log and an ordinary request is answered untouched
	 *
	 * @return void
	 */
	public function test_request_logging_does_not_change_the_response(): void {
		$ordinary = $this->run_query( '{ generalSettings { title } }' );
		$this->assertSame( array(), $ordinary['errors'] ?? array() );

		$classify = new \ReflectionMethod( $this->security, 'is_suspicious_query' );
		$classify->setAccessible( true );
		// The very long query signature is 50 characters per complexity point (5000 by default).
		$this->assertTrue( $classify->invoke( $this->security, '{ generalSettings { title } }' . \str_repeat( ' ', 5000 ) ), 'a very long query is flagged for the log' );
		$this->assertFalse( $classify->invoke( $this->security, '{ generalSettings { title } }' ), 'an ordinary query is not' );
	}

	/**
	 * Build a query with a number of directives, one field per line
	 *
	 * The field repeats on purpose (graphql-php merges it) so that no alias is involved.
	 *
	 * @param int $count Number of directives.
	 * @return string GraphQL document.
	 */
	private function directive_query( int $count ): string {
		$fields = '';
		for ( $i = 0; $i < $count; $i++ ) {
			$fields .= "  generalSettings @include(if: true) { title }\n";
		}

		return "{\n" . $fields . '}';
	}

	/**
	 * The alias flag starts exactly at half of the limit: 10 in standard mode, 25 in headless mode
	 *
	 * @return void
	 */
	public function test_alias_flag_boundary_in_standard_and_headless_mode(): void {
		$this->spy_on_security_events();

		$this->run_query( $this->aliased_query( 9 ) );
		$this->assertNotContains( 'GRAPHQL_SUSPICIOUS_QUERY', $this->event_types(), '9 aliases are not flagged in standard mode' );

		$this->run_query( $this->aliased_query( 10 ) );
		$this->assertContains( 'GRAPHQL_SUSPICIOUS_QUERY', $this->event_types(), '10 aliases are flagged in standard mode' );

		\update_option( 'silver_assist_graphql_headless_mode', true );
		$this->clear_graphql_config_caches();
		$this->security->refresh_configuration();
		$this->spy_on_security_events();

		$this->run_query( $this->aliased_query( 24 ) );
		$this->assertNotContains( 'GRAPHQL_SUSPICIOUS_QUERY', $this->event_types(), '24 aliases are not flagged in headless mode' );

		$this->run_query( $this->aliased_query( 25 ) );
		$this->assertContains( 'GRAPHQL_SUSPICIOUS_QUERY', $this->event_types(), '25 aliases are flagged in headless mode' );
	}

	/**
	 * Directives are flagged from half of the limit, however the query is laid out
	 *
	 * The signature was a greedy pattern whose `.` does not cross a line break, so a query written one
	 * field per line (what a formatter produces) was never flagged (#185). The limit is 15, the flag
	 * starts at 7.
	 *
	 * @return void
	 */
	public function test_many_directives_are_flagged_on_a_multiline_query(): void {
		$this->spy_on_security_events();

		$few = $this->run_query( $this->directive_query( 6 ) );
		$this->assertSame( array(), $few['errors'] ?? array(), (string) \wp_json_encode( $few ) );
		$this->assertNotContains( 'GRAPHQL_SUSPICIOUS_QUERY', $this->event_types(), '6 directives are not flagged' );

		$many = $this->run_query( $this->directive_query( 7 ) );
		$this->assertSame( array(), $many['errors'] ?? array(), (string) \wp_json_encode( $many ) );
		$this->assertContains( 'GRAPHQL_SUSPICIOUS_QUERY', $this->event_types(), '7 directives are flagged' );
	}

	/**
	 * Nested introspection is flagged on a multiline query, and `__typename` is not introspection
	 *
	 * @return void
	 */
	public function test_deep_introspection_is_flagged_on_a_multiline_query(): void {
		$this->set_environment_type( 'staging' );
		\wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$this->spy_on_security_events();

		$typename = $this->run_query( "{\n generalSettings {\n title\n __typename\n }\n}" );
		$this->assertSame( array(), $typename['errors'] ?? array(), (string) \wp_json_encode( $typename ) );
		$this->assertNotContains( 'GRAPHQL_SUSPICIOUS_QUERY', $this->event_types(), '__typename is not introspection' );

		$result = $this->run_query( "{\n __schema {\n types {\n fields {\n name\n }\n }\n }\n}" );
		$this->assertSame( array(), $result['errors'] ?? array(), (string) \wp_json_encode( $result ) );
		$this->assertContains( 'GRAPHQL_SUSPICIOUS_QUERY', $this->event_types() );
	}

	/**
	 * Fields repeated many times are flagged for the log, a wide selection of different fields is not
	 *
	 * The signature was a pattern that matched any long flat selection set, not repetition (#185). The
	 * flag starts at 50 duplicates. Validation rejects 11 repeats of a field in one selection set, so
	 * a request this repetitive never reaches the log; the classifier is exercised directly.
	 *
	 * @return void
	 */
	public function test_repeated_fields_are_flagged_and_wide_selections_are_not(): void {
		$classify = new \ReflectionMethod( $this->security, 'is_suspicious_query' );
		$classify->setAccessible( true );

		$this->assertFalse( $classify->invoke( $this->security, '{ generalSettings { title description url dateFormat timeFormat timezone language startOfWeek email defaultCategory defaultPostFormat postsPerPage } }' ), 'a wide selection of different fields is not repetition' );
		$this->assertTrue( $classify->invoke( $this->security, '{ ' . \str_repeat( 'generalSettings { title } ', 55 ) . '}' ), '54 repeats of one field are flagged' );
	}

	/**
	 * Repeating one field in a selection set is rejected, the same name elsewhere is not
	 *
	 * The limit (10, headless 20) is enforced by a linear pass. `nodes` under every connection, or
	 * aliased copies of a field, are ordinary (the alias limit governs those).
	 *
	 * @return void
	 */
	public function test_field_duplication_limit_is_enforced_per_selection_set(): void {
		$repeated = $this->run_query_or_error( '{ ' . \str_repeat( 'generalSettings { title } ', 12 ) . '}' );
		$this->assertStringContainsString( 'field duplication', $repeated, '11 repeats in one selection set are over the limit' );

		$connections = '';
		for ( $i = 0; $i < 12; $i++ ) {
			$connections .= "p{$i}: posts(first: 1) { nodes { id } } ";
		}
		$many = $this->run_query( '{ ' . $connections . '}' );
		$this->assertSame( array(), $many['errors'] ?? array(), (string) \wp_json_encode( $many ) );
	}

	/**
	 * Run a query and return the message of the error, whether graphql() returns or throws it
	 *
	 * @param string $query GraphQL document.
	 * @return string
	 */
	private function run_query_or_error( string $query ): string {
		try {
			return $this->error_messages( $this->run_query( $query ) );
		} catch ( \Throwable $e ) {
			return $e->getMessage();
		}
	}

	/**
	 * Classifying a hostile query is linear: it neither fails nor stalls
	 *
	 * The old patterns could exhaust PCRE's backtrack limit, where `preg_match` returns false and the
	 * query silently went unflagged.
	 *
	 * @return void
	 */
	public function test_classifying_a_crafted_query_is_fast_and_correct(): void {
		$classify = new \ReflectionMethod( $this->security, 'is_suspicious_query' );
		$classify->setAccessible( true );

		$started = \microtime( true );
		$this->assertTrue( $classify->invoke( $this->security, '{ ' . \str_repeat( '@a ', 20000 ) . '}' ), 'thousands of directives are flagged' );
		$this->assertTrue( $classify->invoke( $this->security, '{ __schema ' . \str_repeat( '{ a ', 20000 ) . '}' ), 'deep introspection is flagged' );
		$this->assertLessThan( 2.0, \microtime( true ) - $started, 'classification does not backtrack' );
	}

	/**
	 * The event action never carries the query text
	 *
	 * `silver_assist_security_event` is observable by any plugin or theme, and a query can hold personal
	 * data in its literals. The preview is written to the security log only (#185).
	 *
	 * @return void
	 */
	public function test_event_action_does_not_receive_the_query_preview(): void {
		$this->spy_on_security_events();

		$this->run_query( $this->aliased_query( 12 ) );

		$this->assertContains( 'GRAPHQL_SUSPICIOUS_QUERY', $this->event_types() );
		foreach ( $this->events as $event ) {
			$this->assertArrayNotHasKey( 'query_preview', $event[2], $event[0] . ' passes no query text to the action' );
		}
		$index = \array_search( 'GRAPHQL_SUSPICIOUS_QUERY', $this->event_types(), true );
		$this->assertArrayHasKey( 'query_length', $this->events[ $index ][2], 'the rest of the context is still there' );
	}

	/**
	 * Directives inside a comment or a string are not directives
	 *
	 * The validation counted every `@word` of the raw text, so a harmless query with a long email list in
	 * a string or a comment was rejected as directive abuse (#185).
	 *
	 * @return void
	 */
	public function test_directives_inside_strings_and_comments_are_not_counted(): void {
		$mentions = \str_repeat( '@a ', 40 );

		$commented = $this->run_query( "{ generalSettings { title } } # {$mentions}" );
		$this->assertSame( array(), $commented['errors'] ?? array(), (string) \wp_json_encode( $commented ) );

		$in_string = $this->run_query( "{ posts(first: 1, where: {search: \"{$mentions}\"}) { nodes { id } } }" );
		$this->assertSame( array(), $in_string['errors'] ?? array(), (string) \wp_json_encode( $in_string ) );

		$validate = new \ReflectionMethod( $this->security, 'validate_query_patterns' );
		$validate->setAccessible( true );
		$this->expectException( \GraphQL\Error\UserError::class );
		$this->expectExceptionMessage( 'too many directives' );
		$validate->invoke( $this->security, '{ generalSettings ' . \str_repeat( '@a ', 31 ) . '{ title } }' );
	}

	/**
	 * Comment and string stripping honours escaped quotes and block strings
	 *
	 * @return void
	 */
	public function test_stripping_is_escape_aware(): void {
		$strip = new \ReflectionMethod( $this->security, 'strip_comments_and_strings' );
		$strip->setAccessible( true );

		$this->assertSame( 'a "" b', $strip->invoke( $this->security, 'a "x \" @y # z" b' ), 'an escaped quote does not end the string' );
		$this->assertSame( 'a "" b', $strip->invoke( $this->security, 'a """ x " \""" @y { """ b' ), 'a block string ends at an unescaped triple quote' );
		$this->assertSame( "a \nb", $strip->invoke( $this->security, "a # \" @c {\nb" ), 'a comment ends at the line break and hides quotes in it' );
		$this->assertSame( 'a ""', $strip->invoke( $this->security, 'a "unterminated @x { {' ), 'an unterminated string is dropped to the end of the text' );
	}

	/**
	 * Crafted documents get an answer in well under a second, through a real request
	 *
	 * Long runs of tokens and a thousands-deep brace stack. The parser or the plugin rejects them; what
	 * matters is that nothing in the plugin's checks stalls on them (#185).
	 *
	 * @return void
	 */
	public function test_crafted_documents_are_answered_quickly(): void {
		$documents = array(
			'token run'   => '{ ' . \str_repeat( 'a ', 4000 ) . '{ a }',
			'word run'    => '{ ' . \str_repeat( 'a', 8000 ) . '{ a a }',
			'brace stack' => \str_repeat( '{', 2000 ),
			'deep nest'   => \str_repeat( 'a{', 2000 ) . 'b' . \str_repeat( '}', 2000 ),
		);

		foreach ( $documents as $name => $document ) {
			$started = \microtime( true );
			try {
				$result = $this->run_query( $document );
			} catch ( \Throwable $e ) {
				// graphql() lets a syntax error escape; it is a rejection as far as this test goes.
				$result = array( 'errors' => array( array( 'message' => $e->getMessage() ) ) );
			}
			$elapsed = \microtime( true ) - $started;

			$this->assertNotEmpty( $result['errors'] ?? array(), "{$name} is rejected" );
			$this->assertLessThan( 1.0, $elapsed, "{$name} is answered in under a second" );
		}
	}

	/**
	 * A check that cannot run rejects the query, it does not let it through
	 *
	 * Forcing PCRE to give up (a 1 backtrack limit) makes `preg_match_all` return false. The checks used
	 * to read that as zero matches.
	 *
	 * @return void
	 */
	public function test_validation_fails_closed_when_pcre_gives_up(): void {
		$validate = new \ReflectionMethod( $this->security, 'validate_query_patterns' );
		$validate->setAccessible( true );

		$limit = \ini_get( 'pcre.backtrack_limit' );
		\ini_set( 'pcre.backtrack_limit', '1' );
		\ini_set( 'pcre.jit', '0' );
		try {
			$validate->invoke( $this->security, '{ a: generalSettings { title } b: generalSettings { title } }' );
			$this->fail( 'a query that could not be checked was accepted' );
		} catch ( \GraphQL\Error\UserError $e ) {
			$this->assertStringContainsString( 'could not be validated', $e->getMessage() );
		} finally {
			\ini_set( 'pcre.backtrack_limit', (string) $limit );
			\ini_set( 'pcre.jit', '1' );
		}
	}
}
