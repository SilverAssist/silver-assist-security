<?php
/**
 * Silver Assist Security Essentials - GraphQL Security Protection
 *
 * Implements comprehensive GraphQL security including query depth/complexity limits,
 * rate limiting, introspection control, and request validation. Provides protection
 * against GraphQL-specific attacks and resource exhaustion.
 *
 * @package SilverAssist\Security\GraphQL
 * @since 1.1.1
 * @author Silver Assist
 * @version 1.5.3
 */

namespace SilverAssist\Security\GraphQL;

use GraphQL\Error\Error;
use GraphQL\Error\UserError;
use GraphQL\Executor\ExecutionResult;
use GraphQL\Language\Parser;
use GraphQL\Language\Printer;
use GraphQL\Language\Visitor;
use SilverAssist\PluginKernel\Interfaces\LoadableInterface;
use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\Security\GeneralSecurity;

/**
 * GraphQL Security class
 *
 * Handles GraphQL security features including query depth/complexity limits,
 * rate limiting, introspection control, and security validations
 *
 * @since 1.1.1
 */
class GraphQLSecurity implements LoadableInterface {

	/**
	 * Singleton instance
	 *
	 * @var self|null
	 */
	private static ?self $instance = null;

	/**
	 * Configuration manager instance
	 *
	 * @var GraphQLConfigManager
	 */
	private GraphQLConfigManager $config_manager;

	/**
	 * Maximum allowed query depth
	 *
	 * @var int
	 */
	private int $max_query_depth;

	/**
	 * Maximum allowed query complexity score
	 *
	 * @var int
	 */
	private int $max_query_complexity;

	/**
	 * Maximum allowed aliases per query
	 *
	 * @var int
	 */
	private int $max_aliases;

	/**
	 * Maximum allowed duplicate directives per query
	 *
	 * @var int
	 */
	private int $max_directives;

	/**
	 * Maximum allowed field duplicates
	 *
	 * @var int
	 */
	private int $max_field_duplicates;

	/**
	 * Query execution timeout in seconds
	 *
	 * @var int
	 */
	private int $query_timeout;

	/**
	 * Whether the current request was authenticated via API key
	 *
	 * Set to true in authenticate_api_key() on successful validation.
	 * Used by preserve_api_key_authentication() to safely bypass
	 * WPGraphQL's CSRF nonce check only for verified API key requests.
	 *
	 * @since 1.3.1
	 * @var bool
	 */
	private bool $api_key_authenticated = false;

	/**
	 * Constructor
	 *
	 * @since 1.1.1
	 */
	public function __construct() {
		$this->config_manager = GraphQLConfigManager::get_instance();
		$this->init_configuration();
		$this->register_hooks();
	}

	/**
	 * Get singleton instance
	 *
	 * @since 1.5.1
	 * @return self
	 */
	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * LoadableInterface entry point
	 *
	 * A no-op: hook registration already happens unconditionally in the
	 * constructor (see register_hooks(), which self-gates on
	 * class_exists('WPGraphQL')), triggered the first time instance()
	 * constructs this singleton.
	 *
	 * @since 1.5.1
	 * @return void
	 */
	public function init(): void {
	}

	/**
	 * Get loading priority
	 *
	 * @since 1.5.1
	 * @return int
	 */
	public function get_priority(): int {
		return 10;
	}

	/**
	 * Whether this component should load
	 *
	 * Matches pre-kernel behavior, where Plugin::init_graphql_security()
	 * only constructed GraphQLSecurity if WPGraphQL was active.
	 *
	 * @since 1.5.1
	 * @return bool
	 */
	public function should_load(): bool {
		return \class_exists( 'WPGraphQL' );
	}

	/**
	 * Initialize configuration values using GraphQLConfigManager
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function init_configuration(): void {
		// Get configuration from centralized manager.
		$config = $this->config_manager->get_configuration();

		// Set properties from configuration.
		$this->max_query_depth      = $config['query_depth_limit'];
		$this->max_query_complexity = $config['query_complexity_limit'];
		$this->query_timeout        = $config['query_timeout'];

		// Set adaptive limits based on headless mode.
		$this->max_aliases          = $this->config_manager->get_safe_limit( 'aliases' );
		$this->max_directives       = $this->config_manager->get_safe_limit( 'directives' );
		$this->max_field_duplicates = $this->config_manager->get_safe_limit( 'field_duplicates' );
	}

	/**
	 * Register GraphQL security hooks
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function register_hooks(): void {
		// Only initialize if WPGraphQL is active.
		if ( ! \class_exists( 'WPGraphQL' ) ) {
			return;
		}

		\add_action( 'init', array( $this, 'init_graphql_security' ) );
		\add_filter( 'graphql_request_results', array( $this, 'log_graphql_requests' ), 10, 5 );
		\add_action( 'graphql_init', array( $this, 'add_security_validations' ) );
		\add_filter( 'graphql_request_data', array( $this, 'validate_query_before_execution' ), 1, 5 );
		\add_action( 'graphql_init', array( $this, 'set_execution_timeout' ) );
		// WPGraphQL answers on parse_request and exits before send_headers, so its response headers
		// can only be changed through this filter.
		\add_filter( 'graphql_response_headers_to_send', array( $this, 'add_response_security_headers' ) );
		\add_action( 'graphql_init', array( $this, 'enforce_authentication_requirement' ) );

		// Hook into determine_current_user AFTER WordPress core callbacks
		// (wp_validate_auth_cookie at 10, wp_validate_logged_in_cookie at 20)
		// so that our returned user ID is not overwritten by cookie validation.
		\add_filter( 'determine_current_user', array( $this, 'authenticate_api_key' ), 30 );

		// Prevent WPGraphQL from downgrading API key-authenticated users to guest.
		// WPGraphQL's Router checks for Authorization header to skip nonce validation,
		// but X-API-Key is not recognized as an auth header. This filter tells WPGraphQL
		// to preserve the authenticated user when our API key auth succeeded.
		\add_filter( 'graphql_authentication_errors', array( $this, 'preserve_api_key_authentication' ) );
	}

	/**
	 * Initialize GraphQL security features
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function init_graphql_security(): void {
		// Add rate limiting for GraphQL endpoint.
		$this->setup_graphql_rate_limiting();
	}

	/**
	 * Add security validations integrating with WPGraphQL native features
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function add_security_validations(): void {
		// Add our custom validation rules.
		\add_filter( 'graphql_validation_rules', array( $this, 'add_custom_validation_rules' ) );

		// Integrate with WPGraphQL's native depth validation.
		$this->integrate_with_wpgraphql_depth_validation();
	}

	/**
	 * Integrate with WPGraphQL's native query depth validation
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function integrate_with_wpgraphql_depth_validation(): void {
		// Check if WPGraphQL depth validation is enabled.
		if ( function_exists( 'get_graphql_setting' ) ) {
			$wpgraphql_depth_enabled = \get_graphql_setting( 'query_depth_enabled', 'off' );
			$wpgraphql_max_depth     = \get_graphql_setting( 'query_depth_max', 10 );

			// If WPGraphQL depth validation is enabled, coordinate with it.
			if ( 'on' === $wpgraphql_depth_enabled ) {
				// Log coordination for debugging.
				if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
					SecurityHelper::log_security_event(
						'GRAPHQL_DEPTH_COORDINATION',
						sprintf(
							'Coordinating with WPGraphQL depth validation (max: %d)',
							$wpgraphql_max_depth
						),
						array( 'wpgraphql_max_depth' => $wpgraphql_max_depth )
					);
				}

				// Use WPGraphQL's limit if it's more restrictive.
				if ( $wpgraphql_max_depth < $this->max_query_depth ) {
					$this->max_query_depth = $wpgraphql_max_depth;
				}
			}
		}
	}

	/**
	 * Add custom validation rules with WPGraphQL integration
	 *
	 * @since 1.1.1
	 * @param array $validation_rules Existing validation rules.
	 * @return array Modified validation rules
	 */
	public function add_custom_validation_rules( array $validation_rules ): array {
		// Add our enhanced complexity validation.
		$validation_rules[] = new class($this->config_manager) {
			/**
			 * GraphQL configuration manager.
			 *
			 * @var GraphQLConfigManager
			 */
			private GraphQLConfigManager $config_manager;

			/**
			 * Constructor.
			 *
			 * @param GraphQLConfigManager $config_manager GraphQL configuration manager.
			 */
			public function __construct( GraphQLConfigManager $config_manager ) {
				$this->config_manager = $config_manager;
			}

			// phpcs:disable WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid -- Method names below are mandated by graphql-php's ValidationRule contract this anonymous class implements; cannot be snake_case.
			/**
			 * Get the validation rule name
			 *
			 * @return string
			 */
			public function getName(): string {
				return 'SilverAssistComplexityValidation';
			}

			/**
			 * Get visitor function for GraphQL validation
			 *
			 * @param mixed $context Validation context.
			 * @return array
			 */
			public function getVisitor( $context ): array {
				return array(
					// Visitors are keyed by node kind (`Document`), not by class name: a `DocumentNode` key
					// is never matched, which left this rule silent.
					'Document' => function ( $node ) use ( $context ) {
						// Use our enhanced complexity validation with WPGraphQL integration.
						$estimated_complexity = $this->estimate_query_complexity( $node );

						// Get dynamic complexity limit based on configuration.
						$complexity_limit = $this->config_manager->get_safe_limit( 'complexity' );

						if ( $estimated_complexity > $complexity_limit ) {
							$context->reportError(
								new Error(
									sprintf(
									/* translators: 1: estimated complexity, 2: maximum allowed complexity */
										\__( 'Query complexity %1$d exceeds maximum allowed complexity %2$d', 'silver-assist-security' ),
										$estimated_complexity,
										$complexity_limit
									)
								)
							);
						}
					},
				);
			}

			// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter.Found -- SDL visiting is unused here but $context must remain in the signature to satisfy the ValidationRule contract.
			/**
			 * Get SDL visitor (not used in this context)
			 *
			 * @param mixed $context SDL validation context.
			 * @return array
			 */
			public function getSDLVisitor( $context ): array {
				return array();
			}
			// phpcs:enable Generic.CodeAnalysis.UnusedFunctionParameter.Found, WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid

			/**
			 * Estimate query complexity using enhanced proxy method
			 *
			 * @param mixed $node DocumentNode.
			 * @return int Estimated complexity
			 */
			private function estimate_query_complexity( $node ): int {
				// Print the document back to GraphQL text for analysis. `Node::__toString()` returns the
				// AST as JSON, where none of the patterns below (fields, `first:` arguments, `where:`)
				// appear, so the estimate would only measure how deep the JSON nests.
				$query_string = Printer::doPrint( $node );

				// Enhanced complexity estimation.
				$base_complexity = 1;

				// Field count estimation (each field adds complexity).
				$field_matches = array();
				preg_match_all( '/\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*[{\(]/', $query_string, $field_matches );
				$field_complexity = ! empty( $field_matches[1] ) ? count( $field_matches[1] ) : 0;

				// Connection complexity (connections with arguments).
				$connection_matches = array();
				// Both page size arguments count, `first:` and `last:`, wherever they sit in the argument list.
				preg_match_all( '/\b(?:first|last)\s*:\s*(\d+)/', $query_string, $connection_matches );
				$connection_complexity = 0;
				if ( ! empty( $connection_matches[1] ) ) {
					foreach ( $connection_matches[1] as $page_size ) {
						$connection_complexity += (int) ceil( (int) $page_size / 10 );
					}
				}

				// Where clause complexity (filtering increases complexity).
				$where_complexity = substr_count( strtolower( $query_string ), 'where:' );

				// Fragment complexity (fragments can multiply complexity).
				$fragment_complexity = substr_count( $query_string, 'fragment' ) * 2;

				// Nested query complexity (deeper nesting = higher complexity).
				$nesting_level = 0;
				$max_nesting   = 0;
				$query_length  = strlen( $query_string );
				for ( $i = 0; $i < $query_length; $i++ ) {
					if ( '{' === $query_string[ $i ] ) {
						++$nesting_level;
						$max_nesting = max( $max_nesting, $nesting_level );
					} elseif ( '}' === $query_string[ $i ] ) {
						--$nesting_level;
					}
				}
				$nesting_complexity = $max_nesting * 2;

				return (int) ( $base_complexity + $field_complexity + $connection_complexity +
					$where_complexity + $fragment_complexity + $nesting_complexity );
			}
		};

		return $validation_rules;
	}

	/**
	 * Add custom validation rules
	 *
	 * @since 1.1.1
	 * @param array $rules Existing validation rules
	 * @return array
	 */
	// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required by the graphql_request_data filter signature.
	/**
	 * Validate query before execution
	 *
	 * WPGraphQL accepts either one operation (`array( 'query' => ... )`) or a batch (a list of
	 * operations). Every operation of a batch is validated, otherwise wrapping an abusive query in a
	 * batch would skip these checks.
	 *
	 * @since 1.1.1
	 * @since 1.5.4 Validates every operation of a batched request.
	 * @param array       $request_data Request data including query, or a list of operations for a batch.
	 * @param mixed       $request HTTP request object (optional).
	 * @param string|null $operation_name GraphQL operation name (optional).
	 * @param array|null  $variables Query variables (optional).
	 * @param mixed       $context Request context (optional).
	 * @return array
	 * @throws UserError When introspection is attempted in production or query patterns fail validation.
	 */
	public function validate_query_before_execution( array $request_data, $request = null, ?string $operation_name = null, ?array $variables = null, $context = null ): array {
		// phpcs:enable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		if ( \array_is_list( $request_data ) ) {
			foreach ( $request_data as $operation ) {
				if ( \is_array( $operation ) ) {
					$this->validate_single_operation( $operation );
				}
			}

			return $request_data;
		}

		$this->validate_single_operation( $request_data );

		return $request_data;
	}

	/**
	 * Validate the query of one GraphQL operation
	 *
	 * @since 1.5.4
	 * @param array $operation Operation data, with the document under `query`.
	 * @return void
	 * @throws UserError When introspection is attempted in production or query patterns fail validation.
	 */
	private function validate_single_operation( array $operation ): void {
		if ( empty( $operation['query'] ) || ! \is_string( $operation['query'] ) ) {
			return;
		}

		$query = $operation['query'];

		// Check for introspection in production.
		if ( $this->is_production_environment() && $this->is_introspection_query( $query ) ) {
			throw new UserError( esc_html( \__( 'Introspection is disabled in production.', 'silver-assist-security' ) ) );
		}

		// Validate query patterns.
		$this->validate_query_patterns( $query );
	}

	/**
	 * Check if query is introspection
	 *
	 * Only `__schema` and `__type` field selections are introspection, found by parsing the query so
	 * the same text inside a string argument or a comment does not count. `__typename` is a meta field
	 * that Apollo Client, urql and Relay add to ordinary queries, so it must stay allowed.
	 *
	 * @since 1.1.1
	 * @since 1.5.4 `__typename` is no longer treated as introspection.
	 * @param string $query GraphQL query string.
	 * @return bool
	 */
	private function is_introspection_query( string $query ): bool {
		try {
			$document = Parser::parse( $query, array( 'noLocation' => true ) );
		} catch ( \Throwable $e ) {
			// Not a valid document, so it will not execute; stay conservative with a text match.
			return (bool) \preg_match( '/\b__(?:schema|type)\b/', $query );
		}

		$found = false;
		Visitor::visit(
			$document,
			array(
				'Field' => static function ( $node ) use ( &$found ) {
					if ( \in_array( $node->name->value, array( '__schema', '__type' ), true ) ) {
						$found = true;
						return Visitor::stop();
					}

					return null;
				},
			)
		);

		return $found;
	}

	/**
	 * Validate query patterns for security issues
	 *
	 * @since 1.1.1
	 * @param string $query GraphQL query string.
	 * @return void
	 * @throws UserError When query exceeds security limits (aliases, directives, depth, size, duplicates).
	 */
	private function validate_query_patterns( string $query ): void {
		// Check for excessive aliases.
		$alias_count = preg_match_all( '/\w+\s*:\s*\w+/', $query );
		if ( $alias_count > $this->max_aliases ) {
			throw new UserError(
				\esc_html(
					sprintf(
						/* translators: 1: number of aliases found, 2: maximum allowed */
						\__( 'Query contains too many aliases (%1$d). Maximum allowed: %2$d', 'silver-assist-security' ),
						$alias_count,
						$this->max_aliases
					)
				)
			);
		}

		// Check for excessive directive usage.
		$directive_count = preg_match_all( '/@\w+/', $query );
		if ( $directive_count > $this->max_directives * 2 ) {
			throw new UserError(
				\esc_html(
					sprintf(
						/* translators: 1: number of directives found, 2: maximum allowed */
						\__( 'Query contains too many directives (%1$d). Maximum allowed: %2$d', 'silver-assist-security' ),
						$directive_count,
						$this->max_directives * 2
					)
				)
			);
		}

		// Check for field duplication patterns.
		if ( preg_match( "/(\w+)(\s*\w+\s*)*\{[^}]*\1[^}]*\1/", $query ) ) {
			throw new UserError(
				\esc_html(
					sprintf(
						/* translators: %d: maximum allowed field duplicates */
						\__( 'Query contains excessive field duplication. Maximum allowed: %d', 'silver-assist-security' ),
						$this->max_field_duplicates
					)
				)
			);
		}

		// Check for potential circular queries using configured depth limit.
		$depth_pattern = str_repeat( '\{[^}]*', $this->max_query_depth + 1 );
		if ( preg_match( "/$depth_pattern/", $query ) ) {
			throw new UserError(
				\esc_html(
					sprintf(
						/* translators: %d: maximum query depth limit in levels */
						\__( 'Query depth exceeds maximum limit of %d levels.', 'silver-assist-security' ),
						$this->max_query_depth
					)
				)
			);
		}

		// Check for excessively long queries (potential DoS).
		$max_query_length = $this->max_query_complexity * 100;
		if ( strlen( $query ) > $max_query_length ) {
			throw new UserError(
				\esc_html(
					sprintf(
						/* translators: 1: current query length in characters, 2: maximum allowed characters */
						\__( 'Query is too large (%1$d characters). Maximum allowed: %2$d characters.', 'silver-assist-security' ),
						strlen( $query ),
						$max_query_length
					)
				)
			);
		}
	}

	/**
	 * Set execution timeout
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function set_execution_timeout(): void {
		// Add GraphQL-specific timeout filter.
		\add_filter( 'graphql_request_results', array( $this, 'enforce_query_timeout' ), 1, 5 );

		// Get timeout configuration with PHP awareness.
		$timeout_config = $this->config_manager->get_timeout_config();

		// Only set PHP limit if current GraphQL timeout is lower than PHP limit.
		if ( 0 === $timeout_config['php_timeout'] || $timeout_config['current_timeout'] < $timeout_config['php_timeout'] ) {
			set_time_limit( $timeout_config['current_timeout'] );
		}

		// Log timeout configuration for debugging.
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			SecurityHelper::log_security_event(
				'GRAPHQL_TIMEOUT_CONFIG',
				sprintf(
					'GraphQL Security timeout configuration: PHP timeout %d seconds, current timeout %d seconds',
					$timeout_config['php_timeout'],
					$timeout_config['current_timeout']
				),
				array(
					'php_timeout'     => $timeout_config['php_timeout'],
					'graphql_timeout' => $timeout_config['current_timeout'],
					'applied_timeout' => 0 === $timeout_config['php_timeout'] ? $timeout_config['current_timeout'] :
						min( $timeout_config['php_timeout'], $timeout_config['current_timeout'] ),
				)
			);
		}
	}

	// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required by the graphql_request_results filter signature.
	/**
	 * Enforce query timeout using GraphQL execution tracking
	 *
	 * @since 1.1.1
	 * @param mixed       $response GraphQL response (ExecutionResult object or array).
	 * @param mixed       $schema GraphQL schema.
	 * @param string|null $operation Operation name.
	 * @param string|null $query Query string (can be null in some GraphQL contexts).
	 * @param array|null  $variables Query variables.
	 * @return mixed
	 */
	public function enforce_query_timeout( $response, $schema, ?string $operation, ?string $query, ?array $variables ) {
		// phpcs:enable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$request_time   = isset( $_SERVER['REQUEST_TIME_FLOAT'] ) ? floatval( \wp_unslash( $_SERVER['REQUEST_TIME_FLOAT'] ) ) : microtime( true );
		$execution_time = microtime( true ) - $request_time;

		// Check if query execution exceeded our timeout.
		if ( $execution_time > $this->query_timeout ) {
			$query_preview = $query ? substr( $query, 0, 100 ) . '...' : 'Unknown query';
			SecurityHelper::log_security_event(
				'GRAPHQL_QUERY_TIMEOUT',
				sprintf(
					'GraphQL query timeout exceeded: %.2fs (limit: %ds) - Query: %s',
					$execution_time,
					$this->query_timeout,
					$query_preview
				),
				array(
					'execution_time' => $execution_time,
					'timeout_limit'  => $this->query_timeout,
					'query_preview'  => $query_preview,
				)
			);

			// Handle both ExecutionResult object and array response formats.
			if ( is_object( $response ) && method_exists( $response, 'toArray' ) ) {
				// Convert ExecutionResult to array for manipulation.
				$response_array = $response->toArray();

				// Add timeout error to response.
				if ( ! isset( $response_array['errors'] ) ) {
					$response_array['errors'] = array();
				}

				$response_array['errors'][] = array(
					'message'    => sprintf(
						/* translators: %d: timeout limit in seconds */
						\__( 'Query execution timeout exceeded (%ds limit)', 'silver-assist-security' ),
						$this->query_timeout
					),
					'extensions' => array(
						'code'           => 'QUERY_TIMEOUT',
						'execution_time' => $execution_time,
					),
				);

				// Create new ExecutionResult with timeout error.
				return new ExecutionResult(
					$response_array['data'] ?? null,
					$response_array['errors'] ?? array(),
					$response_array['extensions'] ?? array()
				);
			} elseif ( is_array( $response ) ) {
				// Handle array response format.
				if ( ! isset( $response['errors'] ) ) {
					$response['errors'] = array();
				}

				$response['errors'][] = array(
					'message'    => sprintf(
						/* translators: %d: timeout limit in seconds */
						\__( 'Query execution timeout exceeded (%ds limit)', 'silver-assist-security' ),
						$this->query_timeout
					),
					'extensions' => array(
						'code'           => 'QUERY_TIMEOUT',
						'execution_time' => $execution_time,
					),
				);
			}
		}

		return $response;
	}

	/**
	 * Setup GraphQL rate limiting
	 *
	 * @since 1.1.1
	 * @return void
	 */
	private function setup_graphql_rate_limiting(): void {
		// `do_graphql_request` is the action WPGraphQL fires before it executes each operation. The
		// `graphql_request` action this used to hook is never fired by WPGraphQL, so the limiter
		// never ran.
		\add_action( 'do_graphql_request', array( $this, 'check_rate_limit' ) );
	}

	/**
	 * Check rate limit for GraphQL requests using ConfigManager
	 *
	 * Throttles anonymous operations per client IP. Authenticated requests (API key, application
	 * password, session) are not counted, like the REST limiter: a headless server calls from one IP
	 * on behalf of every visitor, so a per-IP cap on its authenticated traffic would take the site
	 * down. Each operation of a batched request counts once.
	 *
	 * @since 1.1.1
	 * @since 1.5.4 Runs on `do_graphql_request`, skips authenticated requests and hashes the IP in the key.
	 * @return void
	 * @throws UserError When GraphQL request rate limit is exceeded for the current IP address.
	 */
	public function check_rate_limit(): void {
		if ( \is_user_logged_in() ) {
			return;
		}

		$ip = $this->get_client_ip();
		if ( '' === $ip || '0.0.0.0' === $ip ) {
			// No peer address (internal or CLI call): nothing to key the limit on.
			return;
		}

		// Get rate limiting configuration from manager.
		$rate_config = $this->config_manager->get_rate_limiting_config();

		$time_window = 60; // seconds.

		// Check if this is likely a build/development request.
		$is_likely_build = $this->is_likely_build_process();

		// Use appropriate limits based on context.
		if ( $this->config_manager->is_headless_mode() || $is_likely_build ) {
			$max_requests = $rate_config['burst_limit'];
		} else {
			$max_requests = $rate_config['requests_per_minute'];
		}

		// Fixed-window counter shared with the REST limiter: atomic under concurrent requests and
		// never extended by accepted requests.
		$current_requests = SecurityHelper::increment_rate_window(
			SecurityHelper::generate_ip_transient_key( 'graphql_rate_window', $ip ),
			SecurityHelper::generate_ip_transient_key( 'graphql_rate_limit', $ip ),
			\time(),
			$time_window
		);

		if ( $current_requests > $max_requests ) {
			throw new UserError( \esc_html( \__( 'Rate limit exceeded. Please try again later.', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * Check if request is likely from a build process
	 *
	 * @since 1.1.1
	 * @return bool
	 */
	private function is_likely_build_process(): bool {
		$user_agent = isset( $_SERVER['HTTP_USER_AGENT'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';
		return (bool) preg_match( '/(next|gatsby|nuxt|build|node|fetch)/i', $user_agent );
	}

	/**
	 * Get client IP address
	 *
	 * @since 1.1.1
	 * @return string
	 */
	private function get_client_ip(): string {
		return SecurityHelper::get_client_ip();
	}

	// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required by the graphql_request_results filter signature.
	/**
	 * Log GraphQL requests for monitoring
	 *
	 * @since 1.1.1
	 * @param mixed       $response GraphQL response (ExecutionResult object or array).
	 * @param mixed       $schema GraphQL schema.
	 * @param string|null $operation Operation name.
	 * @param string|null $query Query string (can be null in some GraphQL contexts).
	 * @param array|null  $variables Query variables.
	 * @return mixed
	 */
	public function log_graphql_requests( $response, $schema, ?string $operation, ?string $query, ?array $variables ) {
		// phpcs:enable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		// Convert ExecutionResult to array for analysis if needed.
		$response_array = is_object( $response ) && method_exists( $response, 'toArray' ) ?
			$response->toArray() :
			( is_array( $response ) ? $response : array() );

		$request_time = isset( $_SERVER['REQUEST_TIME_FLOAT'] ) ? floatval( \wp_unslash( $_SERVER['REQUEST_TIME_FLOAT'] ) ) : microtime( true );
		$user_agent   = isset( $_SERVER['HTTP_USER_AGENT'] ) ? \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '';

		$log_data = array(
			'timestamp'      => \current_time( 'mysql' ),
			'ip'             => $this->get_client_ip(),
			'operation'      => $operation,
			'query_length'   => $query ? strlen( $query ) : 0,
			'has_errors'     => ! empty( $response_array['errors'] ),
			'execution_time' => microtime( true ) - $request_time,
			'user_agent'     => $user_agent,
		);

		// Log suspicious patterns (only if query is not null).
		if ( $query && $this->is_suspicious_query( $query ) ) {
			$log_data['suspicious']    = true;
			$log_data['query_preview'] = substr( $query, 0, 200 ) . '...';
			SecurityHelper::log_security_event(
				'GRAPHQL_SUSPICIOUS_QUERY',
				'Suspicious GraphQL query detected',
				$log_data
			);
		}

		// Log all requests in debug mode.
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			SecurityHelper::log_security_event(
				'GRAPHQL_REQUEST',
				'GraphQL request logged in debug mode',
				$log_data
			);
		}

		return $response;
	}

	/**
	 * Check if query contains suspicious patterns
	 *
	 * @since 1.1.1
	 * @param string $query The GraphQL query to analyze.
	 * @return bool
	 */
	private function is_suspicious_query( string $query ): bool {
		$max_query_length          = $this->max_query_complexity * 50;
		$alias_threshold           = max( 5, intval( $this->max_aliases / 2 ) );
		$directive_threshold       = max( 3, intval( $this->max_directives / 2 ) );
		$field_duplicate_threshold = max( 10, $this->max_field_duplicates * 5 );

		// Very long query: a length check, nothing to match.
		if ( strlen( $query ) >= $max_query_length ) {
			return true;
		}

		// Many aliases, directives or repeated fields: the counts validation runs. They are linear
		// scans, so a crafted query cannot exhaust PCRE's backtrack limit and go unflagged.
		if ( $this->count_aliases( $query ) >= $alias_threshold
			|| $this->count_directives( $query ) >= $directive_threshold
			|| $this->count_field_duplicates( $query ) >= $field_duplicate_threshold
		) {
			return true;
		}

		return $this->is_deep_introspection( $query );
	}

	/**
	 * Check whether a query introspects the schema with three or more selection sets below it
	 *
	 * Counts the selection sets opened from the first `__schema` or `__type` on, in one linear pass
	 * (word boundaries, so `__typename` is not introspection; line breaks do not matter).
	 *
	 * @since 1.5.4
	 * @param string $query GraphQL query string.
	 * @return bool
	 */
	private function is_deep_introspection( string $query ): bool {
		$cleaned = $this->strip_comments_and_strings( $query );

		if ( ! preg_match( '/\b__(?:schema|type)\b/', $cleaned, $match, PREG_OFFSET_CAPTURE ) ) {
			return false;
		}

		return substr_count( $cleaned, '{', (int) $match[0][1] ) >= 3;
	}

	/**
	 * Remove comments and string literals so counts do not see their content
	 *
	 * @since 1.5.4
	 * @param string $query GraphQL query string.
	 * @return string Query with comments removed and strings emptied.
	 */
	private function strip_comments_and_strings( string $query ): string {
		$cleaned = (string) preg_replace( '/\s*#[^\r\n]*/', '', $query );
		$cleaned = (string) preg_replace( '/"[^"]*"/', '""', $cleaned );

		return (string) preg_replace( "/'[^']*'/", "''", $cleaned );
	}

	/**
	 * Add the baseline security headers to the GraphQL response
	 *
	 * WPGraphQL handles the HTTP request on `parse_request` and exits before WordPress runs
	 * `send_headers`, so the headers the plugin sends there never reach the GraphQL response. This
	 * runs on `graphql_response_headers_to_send`, which WPGraphQL applies only to its own HTTP
	 * response (any endpoint path, and no other URL). Headers already present, from WPGraphQL or from
	 * another filter, are kept.
	 *
	 * @since 1.1.1
	 * @since 1.5.4 Hooked to `graphql_response_headers_to_send` (it was a `send_headers` callback that never ran for GraphQL).
	 * @param mixed $headers Headers WPGraphQL is about to send, name => value.
	 * @return mixed The headers with the baseline security headers added.
	 */
	public function add_response_security_headers( $headers ) {
		if ( ! \is_array( $headers ) ) {
			return $headers;
		}

		return $headers + GeneralSecurity::instance()->get_security_headers();
	}

	/**
	 * Validate query depth against security limits
	 *
	 * Analyzes GraphQL query depth to prevent deeply nested queries that could
	 * cause performance issues or be used in DoS attacks.
	 *
	 * @since 1.1.1
	 * @param mixed $context GraphQL context containing query information.
	 * @return array Validation errors, empty if valid
	 */
	public function validate_query_depth( $context ): array {
		if ( ! isset( $context['request_data']['query'] ) ) {
			return array();
		}

		$query     = $context['request_data']['query'];
		$max_depth = $this->get_max_query_depth();

		try {
			$current_depth = $this->calculate_query_depth( $query );

			if ( $current_depth > $max_depth ) {
				SecurityHelper::log_security_event(
					'GRAPHQL_DEPTH_EXCEEDED',
					"GraphQL query depth {$current_depth} exceeds limit {$max_depth}",
					array(
						'current_depth' => $current_depth,
						'max_depth'     => $max_depth,
						'query_preview' => substr( $query, 0, 200 ),
					)
				);

				return array(
					new \GraphQL\Error\UserError(
						sprintf(
							/* translators: 1: current depth, 2: maximum allowed depth */
							\__( 'Query depth %1$d exceeds maximum allowed depth %2$d', 'silver-assist-security' ),
							$current_depth,
							$max_depth
						)
					),
				);
			}

			return array();

		} catch ( \Throwable $e ) {
			SecurityHelper::log_security_event(
				'GRAPHQL_DEPTH_ERROR',
				"Error calculating query depth: {$e->getMessage()}",
				array( 'error' => $e->getMessage() )
			);

			// Fail closed: a query that could not be checked is not allowed.
			return array( new \GraphQL\Error\UserError( \__( 'The query could not be validated and was rejected.', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * Calculate the maximum depth of a GraphQL query
	 *
	 * @param string $query GraphQL query string.
	 * @return int Maximum depth found
	 * @since 1.1.1
	 */
	private function calculate_query_depth( string $query ): int {
		// Remove comments and normalize whitespace.
		$query = (string) preg_replace( '/\s*#[^\r\n]*/', '', $query );
		$query = trim( (string) preg_replace( '/\s+/', ' ', $query ) );

		$max_depth     = 0;
		$current_depth = 0;
		$in_string     = false;
		$string_char   = null;
		$query_length  = strlen( $query );

		for ( $i = 0; $i < $query_length; $i++ ) {
			$char = $query[ $i ];

			// Handle string literals.
			if ( ( '"' === $char || "'" === $char ) && ( 0 === $i || '\\' !== $query[ $i - 1 ] ) ) {
				if ( ! $in_string ) {
					$in_string   = true;
					$string_char = $char;
				} elseif ( $char === $string_char ) {
					$in_string   = false;
					$string_char = null;
				}
				continue;
			}

			if ( $in_string ) {
				continue;
			}

			// Count nesting levels.
			if ( '{' === $char ) {
				++$current_depth;
				$max_depth = max( $max_depth, $current_depth );
			} elseif ( '}' === $char ) {
				$current_depth = max( 0, $current_depth - 1 );
			}
		}

		return $max_depth;
	}

	// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter.Found -- Kept for signature consistency with the other validate_query_* methods in this class.
	/**
	 * Validate query complexity using hybrid approach
	 *
	 * Since WPGraphQL doesn't have native complexity analysis, we use a hybrid approach:
	 * 1. Delegate depth validation to WPGraphQL's native QueryDepth rule
	 * 2. Use enhanced proxy validation for complexity estimation
	 * 3. Integrate with WPGraphQL's connection limits and rate limiting
	 *
	 * @since 1.1.1
	 * @param mixed $context GraphQL context.
	 * @return array
	 */
	public function validate_query_complexity( $context ): array {
		// phpcs:enable Generic.CodeAnalysis.UnusedFunctionParameter.Found
		// WPGraphQL doesn't have native complexity analysis
		// Our complexity validation happens in validate_query_patterns()
		// using enhanced heuristics combined with WPGraphQL's native features:
		// - Query depth: Handled by WPGraphQL's QueryDepth validation rule
		// - Connection limits: Handled by WPGraphQL's AbstractConnectionResolver
		// - Rate limiting: Our implementation with WPGraphQL integration
		// - Complexity estimation: Our enhanced proxy validation.
		return array();
	}

	/**
	 * Validate GraphQL aliases to prevent alias abuse attacks
	 *
	 * Prevents attackers from using excessive aliases to bypass rate limiting
	 * or cause resource exhaustion by multiplying the same expensive field.
	 *
	 * @since 1.1.1
	 * @param mixed $context GraphQL context containing query information.
	 * @return array Validation errors, empty if valid
	 */
	public function validate_aliases( $context ): array {
		if ( ! isset( $context['request_data']['query'] ) ) {
			return array();
		}

		$query       = $context['request_data']['query'];
		$max_aliases = $this->config_manager->get_safe_limit( 'aliases' );

		try {
			$alias_count = $this->count_aliases( $query );

			if ( $alias_count > $max_aliases ) {
				SecurityHelper::log_security_event(
					'GRAPHQL_ALIAS_ABUSE',
					"GraphQL query contains {$alias_count} aliases, exceeding limit {$max_aliases}",
					array(
						'alias_count'   => $alias_count,
						'max_aliases'   => $max_aliases,
						'query_preview' => substr( $query, 0, 200 ),
					)
				);

				return array(
					new \GraphQL\Error\UserError(
						sprintf(
							/* translators: 1: current alias count, 2: maximum allowed aliases */
							\__( 'Query contains %1$d aliases, maximum %2$d allowed', 'silver-assist-security' ),
							$alias_count,
							$max_aliases
						)
					),
				);
			}

			return array();

		} catch ( \Throwable $e ) {
			SecurityHelper::log_security_event(
				'GRAPHQL_ALIAS_ERROR',
				"Error counting aliases: {$e->getMessage()}",
				array( 'error' => $e->getMessage() )
			);

			// Fail closed: a query that could not be checked is not allowed.
			return array( new \GraphQL\Error\UserError( \__( 'The query could not be validated and was rejected.', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * Count the number of aliases in a GraphQL query
	 *
	 * @param string $query GraphQL query string.
	 * @return int Number of aliases found
	 * @since 1.1.1
	 */
	private function count_aliases( string $query ): int {
		// Remove comments and strings to avoid false positives.
		$cleaned_query = $this->strip_comments_and_strings( $query );

		// Pattern to match aliases: fieldAlias: actualField
		// This matches word characters followed by colon and space/word.
		preg_match_all( '/\b[a-zA-Z_][a-zA-Z0-9_]*\s*:\s*[a-zA-Z_]/', $cleaned_query, $matches );

		return count( $matches[0] );
	}

	/**
	 * Validate GraphQL directives to prevent directive abuse
	 *
	 * Limits the number of directives in a query to prevent resource exhaustion
	 * and potential security issues from excessive directive usage.
	 *
	 * @since 1.1.1
	 * @param mixed $context GraphQL context containing query information.
	 * @return array Validation errors, empty if valid
	 */
	public function validate_directives( $context ): array {
		if ( ! isset( $context['request_data']['query'] ) ) {
			return array();
		}

		$query          = $context['request_data']['query'];
		$max_directives = $this->config_manager->get_safe_limit( 'directives' );

		try {
			$directive_count = $this->count_directives( $query );

			if ( $directive_count > $max_directives ) {
				SecurityHelper::log_security_event(
					'GRAPHQL_DIRECTIVE_ABUSE',
					"GraphQL query contains {$directive_count} directives, exceeding limit {$max_directives}",
					array(
						'directive_count' => $directive_count,
						'max_directives'  => $max_directives,
						'query_preview'   => substr( $query, 0, 200 ),
					)
				);

				return array(
					new \GraphQL\Error\UserError(
						sprintf(
							/* translators: 1: current directive count, 2: maximum allowed directives */
							\__( 'Query contains %1$d directives, maximum %2$d allowed', 'silver-assist-security' ),
							$directive_count,
							$max_directives
						)
					),
				);
			}

			return array();

		} catch ( \Throwable $e ) {
			SecurityHelper::log_security_event(
				'GRAPHQL_DIRECTIVE_ERROR',
				"Error counting directives: {$e->getMessage()}",
				array( 'error' => $e->getMessage() )
			);

			// Fail closed: a query that could not be checked is not allowed.
			return array( new \GraphQL\Error\UserError( \__( 'The query could not be validated and was rejected.', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * Count the number of directives in a GraphQL query
	 *
	 * @param string $query GraphQL query string.
	 * @return int Number of directives found
	 * @since 1.1.1
	 */
	private function count_directives( string $query ): int {
		// Remove comments and strings to avoid false positives.
		$cleaned_query = $this->strip_comments_and_strings( $query );

		// Pattern to match directives: @directiveName.
		preg_match_all( '/@[a-zA-Z_][a-zA-Z0-9_]*/', $cleaned_query, $matches );

		return count( $matches[0] );
	}

	/**
	 * Validate field duplicates to prevent field duplication attacks
	 *
	 * Prevents attackers from duplicating expensive fields multiple times
	 * in the same query to cause resource exhaustion.
	 *
	 * @since 1.1.1
	 * @param mixed $context GraphQL context containing query information.
	 * @return array Validation errors, empty if valid
	 */
	public function validate_field_duplicates( $context ): array {
		if ( ! isset( $context['request_data']['query'] ) ) {
			return array();
		}

		$query          = $context['request_data']['query'];
		$max_duplicates = $this->config_manager->get_safe_limit( 'field_duplicates' );

		try {
			$duplicate_count = $this->count_field_duplicates( $query );

			if ( $duplicate_count > $max_duplicates ) {
				SecurityHelper::log_security_event(
					'GRAPHQL_FIELD_DUPLICATION',
					"GraphQL query contains {$duplicate_count} field duplicates, exceeding limit {$max_duplicates}",
					array(
						'duplicate_count' => $duplicate_count,
						'max_duplicates'  => $max_duplicates,
						'query_preview'   => substr( $query, 0, 200 ),
					)
				);

				return array(
					new \GraphQL\Error\UserError(
						sprintf(
							/* translators: 1: current duplicate count, 2: maximum allowed duplicates */
							\__( 'Query contains %1$d field duplicates, maximum %2$d allowed', 'silver-assist-security' ),
							$duplicate_count,
							$max_duplicates
						)
					),
				);
			}

			return array();

		} catch ( \Throwable $e ) {
			SecurityHelper::log_security_event(
				'GRAPHQL_FIELD_DUPLICATE_ERROR',
				"Error counting field duplicates: {$e->getMessage()}",
				array( 'error' => $e->getMessage() )
			);

			// Fail closed: a query that could not be checked is not allowed.
			return array( new \GraphQL\Error\UserError( \__( 'The query could not be validated and was rejected.', 'silver-assist-security' ) ) );
		}
	}

	/**
	 * Count field duplicates in a GraphQL query
	 *
	 * @param string $query GraphQL query string.
	 * @return int Number of duplicate fields found
	 * @since 1.1.1
	 */
	private function count_field_duplicates( string $query ): int {
		// Remove comments and strings to avoid false positives.
		$cleaned_query = $this->strip_comments_and_strings( $query );

		// Extract all field names (simplified pattern).
		preg_match_all( '/\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[({]/', $cleaned_query, $matches );

		if ( empty( $matches[1] ) ) {
			return 0;
		}

		$field_names  = $matches[1];
		$field_counts = array_count_values( $field_names );

		// Count how many fields appear more than once.
		$duplicate_count = 0;
		foreach ( $field_counts as $field => $count ) {
			if ( $count > 1 ) {
				$duplicate_count += ( $count - 1 ); // Count excess occurrences.
			}
		}

		return $duplicate_count;
	}

	/**
	 * Get current GraphQL query depth limit
	 *
	 * @since 1.1.1
	 * @return int
	 */
	public function get_max_query_depth(): int {
		return $this->max_query_depth;
	}

	/**
	 * Get current GraphQL query complexity limit
	 *
	 * @since 1.1.1
	 * @return int
	 */
	public function get_max_query_complexity(): int {
		return $this->max_query_complexity;
	}

	/**
	 * Get current GraphQL query timeout
	 *
	 * @since 1.1.1
	 * @return int
	 */
	public function get_query_timeout(): int {
		return $this->query_timeout;
	}

	/**
	 * Refresh configuration values
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function refresh_configuration(): void {
		$this->init_configuration();
	}

	/**
	 * Enable headless CMS mode with relaxed security settings
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function enable_headless_mode(): void {
		\update_option( 'silver_assist_graphql_headless_mode', true );
		$this->init_configuration();
	}

	/**
	 * Disable headless CMS mode and use standard security settings
	 *
	 * @since 1.1.1
	 * @return void
	 */
	public function disable_headless_mode(): void {
		\update_option( 'silver_assist_graphql_headless_mode', false );
		$this->init_configuration();
	}

	/**
	 * Check if headless mode is enabled using ConfigManager
	 *
	 * @since 1.1.1
	 * @return bool
	 */
	public function is_headless_mode(): bool {
		return $this->config_manager->is_headless_mode();
	}

	/**
	 * Get recommended settings for headless CMS usage
	 *
	 * @since 1.1.1
	 * @return array
	 */
	public function get_headless_recommendations(): array {
		$recommendations = array(
			'max_query_depth'       => 20,
			'max_query_complexity'  => 1000,
			'query_timeout'         => 30,
			'rate_limit_per_minute' => 300,
			'recommended_settings'  => array(
				'Enable headless mode for relaxed limits',
				'Consider using query whitelisting for production',
				'Monitor query performance with logging',
				'Use query complexity analysis tools',
			),
		);

		// Add WPGraphQL-specific recommendations if available.
		if ( \class_exists( 'WPGraphQL' ) && \function_exists( 'get_graphql_setting' ) ) {
			$recommendations['wpgraphql_integration'] = array(
				'current_introspection' => get_graphql_setting( 'public_introspection_enabled', 'off' ),
				'current_batch_enabled' => get_graphql_setting( 'batch_queries_enabled', 'on' ),
				'current_batch_limit'   => get_graphql_setting( 'batch_limit', 10 ),
				'current_depth_enabled' => get_graphql_setting( 'query_depth_enabled', 'off' ),
				'current_max_depth'     => get_graphql_setting( 'query_depth_max_depth', 10 ),
				'recommendations'       => array(
					'For headless CMS: Enable query depth limiting with max depth 15-20',
					'For headless CMS: Keep batch queries enabled with limit 10-20',
					'For production: Disable public introspection',
					'For production: Disable debug mode',
					'Consider authentication restriction based on your use case',
				),
			);
		}

		return $recommendations;
	}

	/**
	 * Get current WPGraphQL configuration status using ConfigManager
	 *
	 * @since 1.1.1
	 * @return array
	 */
	public function get_wpgraphql_status(): array {
		if ( ! $this->config_manager->is_wpgraphql_available() ) {
			return array(
				'available' => false,
				'message'   => 'WPGraphQL plugin not detected',
			);
		}

		$config             = $this->config_manager->get_configuration();
		$integration_status = $this->config_manager->get_integration_status();

		return array(
			'available'       => true,
			'settings'        => array(
				'introspection_enabled' => $config['introspection_enabled'],
				'debug_mode'            => $config['debug_mode'],
				'batch_queries_enabled' => $config['batch_enabled'],
				'batch_limit'           => $config['batch_limit'],
				'query_depth_enabled'   => $config['query_depth_limit'] > 0,
				'query_depth_limit'     => $config['query_depth_limit'],
				'auth_required'         => 'restricted' === $config['endpoint_access'],
			),
			'security_status' => $integration_status['security_level'],
			'recommendations' => $integration_status['recommendations'],
		);
	}

	/**
	 * Enforce authentication requirement for GraphQL requests
	 *
	 * When enabled, all GraphQL queries require a logged-in user via
	 * WordPress session, Application Passwords, or API key.
	 *
	 * @since 1.3.0
	 * @return void
	 */
	public function enforce_authentication_requirement(): void {
		if ( ! $this->config_manager->is_authentication_required() ) {
			return;
		}

		// Hook before query execution to check authentication.
		\add_filter( 'graphql_request_data', array( $this, 'validate_authentication' ), 0, 5 );
	}

	// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required by the graphql_request_data filter signature.
	/**
	 * Validate that the current request is authenticated
	 *
	 * Checks is_user_logged_in() which returns true for:
	 * 1. WordPress session (admin/editor logged in)
	 * 2. Application Password sent via Authorization: Basic header
	 * 3. API key authenticated via determine_current_user filter
	 *
	 * @since 1.3.0
	 * @param array       $request_data   Request data including query.
	 * @param mixed       $request        HTTP request object (optional).
	 * @param string|null $operation_name GraphQL operation name (optional).
	 * @param array|null  $variables      Query variables (optional).
	 * @param mixed       $context        Request context (optional).
	 * @return array Request data passed through.
	 * @throws UserError When the request is not authenticated.
	 */
	public function validate_authentication( array $request_data, $request = null, ?string $operation_name = null, ?array $variables = null, $context = null ): array {
		// phpcs:enable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		// Allow unauthenticated access only in explicit local/development environments for tooling.
		if ( \in_array( $this->get_environment_type(), array( 'local', 'development' ), true ) ) {
			return $request_data;
		}

		if ( ! \is_user_logged_in() ) {
			SecurityHelper::log_security_event(
				'GRAPHQL_AUTH_DENIED',
				'Unauthenticated GraphQL request blocked',
				array(
					'ip'         => SecurityHelper::get_client_ip(),
					'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] )
						? \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) )
						: '',
				)
			);

			throw new UserError(
				\esc_html( \__( 'Authentication required to access GraphQL endpoint.', 'silver-assist-security' ) )
			);
		}

		return $request_data;
	}

	/**
	 * Authenticate GraphQL requests using a plugin-managed API key
	 *
	 * Hooks into determine_current_user at priority 30 to authenticate
	 * server-to-server requests before is_user_logged_in() is checked.
	 * Supports X-API-Key header and Authorization: Bearer token.
	 *
	 * @since 1.3.0
	 * @param int|false $user_id The current user ID, or false if not determined.
	 * @return int|false The authenticated user ID, or the original value.
	 */
	public function authenticate_api_key( $user_id ) {
		// Only process if no user is already authenticated.
		if ( $user_id ) {
			return $user_id;
		}

		// Only apply to GraphQL requests.
		if ( ! $this->is_graphql_request() ) {
			return $user_id;
		}

		$api_key = $this->get_api_key_from_request();
		if ( empty( $api_key ) ) {
			return $user_id;
		}

		$stored_key_hash = DefaultConfig::get_option( 'silver_assist_graphql_api_key' );
		if ( empty( $stored_key_hash ) ) {
			return $user_id;
		}

		// Verify API key against stored hash.
		if ( ! \wp_check_password( $api_key, $stored_key_hash ) ) {
			SecurityHelper::log_security_event(
				'GRAPHQL_API_KEY_INVALID',
				'Invalid GraphQL API key used',
				array( 'ip' => SecurityHelper::get_client_ip() )
			);
			return $user_id;
		}

		// Return the service account user ID.
		$service_user_id = (int) DefaultConfig::get_option( 'silver_assist_graphql_service_user_id' );
		if ( $service_user_id > 0 && \get_userdata( $service_user_id ) ) {
			$this->api_key_authenticated = true;

			SecurityHelper::log_security_event(
				'GRAPHQL_API_KEY_AUTH',
				'GraphQL request authenticated via API key',
				array(
					'ip'              => SecurityHelper::get_client_ip(),
					'service_user_id' => $service_user_id,
				)
			);
			return $service_user_id;
		}

		return $user_id;
	}

	/**
	 * Preserve API key authentication during WPGraphQL's CSRF validation
	 *
	 * WPGraphQL's Router downgrades cookie-authenticated users to guest when no
	 * nonce is provided. It only skips this check when an Authorization header
	 * is present. Since X-API-Key is not an Authorization header, this filter
	 * tells WPGraphQL to preserve the authenticated user when our API key was
	 * used for authentication.
	 *
	 * @since 1.3.1
	 * @param bool|null $errors Null to allow default behavior, false to preserve auth.
	 * @return bool|null False if API key auth was used, original value otherwise.
	 */
	public function preserve_api_key_authentication( $errors ) {
		// Only bypass CSRF check when API key auth actually succeeded.
		if ( $this->api_key_authenticated ) {
			return false;
		}

		return $errors;
	}

	/**
	 * Get the environment type the GraphQL protections follow
	 *
	 * Uses `wp_get_environment_type()`, which is `production` when the site declares nothing, so
	 * every environment-dependent protection (introspection, unauthenticated access) agrees with
	 * WordPress about what production is.
	 *
	 * @since 1.5.4
	 * @return string One of local, development, staging or production.
	 */
	private function get_environment_type(): string {
		/**
		 * Filters the environment type used by the GraphQL protections
		 *
		 * `wp_get_environment_type()` has no filter and caches its first answer, so this is the way to
		 * override it, for example in tests.
		 *
		 * @since 1.5.4
		 * @param string $environment Environment type reported by WordPress.
		 */
		return (string) \apply_filters( 'silver_assist_security_environment_type', \wp_get_environment_type() );
	}

	/**
	 * Whether the site runs in the production environment
	 *
	 * @since 1.5.4
	 * @return bool
	 */
	private function is_production_environment(): bool {
		return 'production' === $this->get_environment_type();
	}

	/**
	 * Check if the current request is a GraphQL request
	 *
	 * Asks WPGraphQL, which knows the configured endpoint (the default `/graphql` or a custom one) and
	 * matches the request path exactly. A plain substring search for `/graphql` would also match
	 * other URLs (`/wp-json/wp/v2/users/me?next=/graphql`) and miss a custom endpoint.
	 *
	 * @since 1.3.0
	 * @since 1.5.4 Follows WPGraphQL's endpoint detection instead of a substring search.
	 * @return bool True if the current request targets the GraphQL endpoint.
	 */
	private function is_graphql_request(): bool {
		if ( \is_callable( array( '\\WPGraphQL\\Router', 'is_graphql_http_request' ) ) ) {
			return (bool) \WPGraphQL\Router::is_graphql_http_request();
		}

		$request_uri = isset( $_SERVER['REQUEST_URI'] )
			? \sanitize_text_field( \wp_unslash( $_SERVER['REQUEST_URI'] ) )
			: '';
		$path        = (string) \wp_parse_url( $request_uri, \PHP_URL_PATH );

		return '/graphql' === \rtrim( $path, '/' );
	}

	/**
	 * Extract API key from request headers
	 *
	 * Supports X-API-Key header and Authorization: Bearer token.
	 *
	 * @since 1.3.0
	 * @return string The API key, or empty string if not found.
	 */
	private function get_api_key_from_request(): string {
		// Check X-API-Key header.
		if ( isset( $_SERVER['HTTP_X_API_KEY'] ) ) {
			$api_key = \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_X_API_KEY'] ) );
			if ( ! empty( $api_key ) ) {
				return $api_key;
			}
		}

		// Fallback: Check Authorization: Bearer <key>.
		if ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			$auth = \sanitize_text_field( \wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] ) );
			if ( str_starts_with( $auth, 'Bearer ' ) ) {
				return substr( $auth, 7 );
			}
		}

		return '';
	}
}
