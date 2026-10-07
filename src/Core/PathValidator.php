<?php
/**
 * Silver Assist Security Essentials - Admin Path Validator Utility
 *
 * Provides centralized validation logic for admin path security.
 * Used by both AdminHideSecurity and AdminPanel classes.
 *
 * @package SilverAssist\Security\Core
 * @since   1.1.4
 * @version 1.5.4
 */

namespace SilverAssist\Security\Core;

/**
 * Admin Path Validator Utility
 *
 * Provides centralized validation logic for admin path security.
 * Used by both AdminHideSecurity and AdminPanel classes.
 *
 * @package SilverAssist\Security\Core
 * @since   1.1.4
 * @version 1.5.4
 */
class PathValidator {

	/**
	 * List of forbidden admin path keywords for security
	 *
	 * @var array<string>
	 * @since 1.1.4
	 */
	private static array $forbidden_paths = array(
		'admin',
		'login',
		'wp-admin',
		'wp-login',
		'wp-content',
		'wp-includes',
		'dashboard',
		'backend',
		'administrator',
		'root',
		'user',
		'auth',
		'signin',
		'panel',
		'control',
		'manage',
		'system',
	);

	/**
	 * Slugs WordPress core and its bundled routes answer on
	 *
	 * `AdminHideSecurity::classify_request_path` matches the first path segment, so a custom admin path equal
	 * to one of these would hijack the route. Routes that depend on the site (REST prefix, rewrite bases,
	 * post type and taxonomy slugs) are added at validation time by `get_site_route_slugs()`.
	 *
	 * @var array<string>
	 * @since 1.5.4
	 */
	private const RESERVED_SLUGS = array(
		'wp-json',
		'wp-cron',
		'wp-signup',
		'wp-activate',
		'wp-trackback',
		'wp-comments-post',
		'wp-links-opml',
		'wp-mail',
		'wp-load',
		'wp-blog-header',
		'wp-settings',
		'wp-config',
		'wp-config-sample',
		'wp-sitemap',
		'xmlrpc',
		'sitemap',
		'feed',
		'feeds',
		'rss',
		'rss2',
		'rdf',
		'atom',
		'comments',
		'comment-page',
		'trackback',
		'embed',
		'robots',
		'favicon',
		'attachment',
		'page',
		'search',
		'author',
		'category',
		'tag',
	);

	/**
	 * Path that no rewrite rule is specific to, used to tell catch-all rules from specific ones
	 *
	 * @var string
	 * @since 1.5.4
	 */
	private const CONTROL_PATH = 'zz-no-such-route-0q9x';

	/**
	 * Validation result structure
	 *
	 * @var array
	 * @since 1.1.4
	 */
	public const RESULT_STRUCTURE = array(
		'is_valid'       => false,
		'error_message'  => '',
		'error_type'     => '',
		'sanitized_path' => '',
	);

	/**
	 * Validate admin path for security compliance
	 *
	 * The one validator for a custom admin path: the settings saver, the registered setting's sanitize
	 * callback and the live validation endpoint call it. Rules, in order: not empty, 3 to 50 characters,
	 * letters, numbers, hyphens and underscores, not a forbidden security keyword, not a reserved core slug
	 * (`error_type` `reserved`) and, when `$check_site` is true, not a route, post or rewrite rule of this site
	 * (`error_type` `collision`). The site checks query the database, so the per-request runtime check
	 * (`is_forbidden_path`) skips them.
	 *
	 * @since 1.1.4
	 * @param string $path       The path to validate.
	 * @param bool   $check_site Whether to also check this site's routes, pages and rewrite rules.
	 * @return array Validation result with structure: [is_valid, error_message, error_type, sanitized_path]
	 */
	public static function validate_admin_path( string $path, bool $check_site = true ): array {
		$result        = self::RESULT_STRUCTURE;
		$original_path = $path;
		$path          = strtolower( trim( $path ) );

		// Check if path is empty.
		if ( empty( $path ) ) {
			$result['error_message'] = \__( 'Path cannot be empty', 'silver-assist-security' );
			$result['error_type']    = 'empty';
			return $result;
		}

		// Check length constraints.
		if ( strlen( $path ) < 3 ) {
			$result['error_message'] = \__( 'Path must be at least 3 characters long', 'silver-assist-security' );
			$result['error_type']    = 'too_short';
			return $result;
		}

		if ( strlen( $path ) > 50 ) {
			$result['error_message'] = \__( 'Path must be 50 characters or less', 'silver-assist-security' );
			$result['error_type']    = 'too_long';
			return $result;
		}

		// Check character constraints (alphanumeric, hyphens, underscores only).
		if ( ! preg_match( '/^[a-zA-Z0-9-_]+$/', $path ) ) {
			$result['error_message'] = \__( 'Path can only contain letters, numbers, hyphens, and underscores', 'silver-assist-security' );
			$result['error_type']    = 'invalid_chars';
			return $result;
		}

		// Check forbidden paths using centralized logic.
		$forbidden_check = self::check_forbidden_patterns( $path );
		if ( ! $forbidden_check['is_valid'] ) {
			$result['error_message'] = $forbidden_check['error_message'];
			$result['error_type']    = 'forbidden';
			return $result;
		}

		// Check core routes and, when asked, what this site already serves.
		if ( in_array( $path, self::RESERVED_SLUGS, true ) ) {
			$result['error_message'] = sprintf(
				/* translators: %s: reserved path */
				\__( '"%s" is a WordPress route and cannot be used as the admin path', 'silver-assist-security' ),
				$path
			);
			$result['error_type'] = 'reserved';
			return $result;
		}

		if ( $check_site ) {
			$collision = self::find_site_collision( $path );
			if ( '' !== $collision ) {
				$result['error_message'] = $collision;
				$result['error_type']    = in_array( $path, self::get_site_route_slugs(), true ) ? 'reserved' : 'collision';
				return $result;
			}
		}

		// Path is valid - leave error_message empty.
		$result['is_valid']       = true;
		$result['sanitized_path'] = \sanitize_title( $original_path );

		return $result;
	}

	/**
	 * First path segments this site routes by design: REST prefix, rewrite bases, post type and taxonomy slugs
	 *
	 * @since 1.5.4
	 * @return array<string> Lowercase slugs.
	 */
	public static function get_site_route_slugs(): array {
		global $wp_rewrite;

		$slugs = array( \rest_get_url_prefix() );

		if ( $wp_rewrite instanceof \WP_Rewrite ) {
			$slugs = array_merge(
				$slugs,
				(array) $wp_rewrite->feeds,
				array(
					$wp_rewrite->pagination_base,
					$wp_rewrite->comments_base,
					$wp_rewrite->comments_pagination_base,
					$wp_rewrite->search_base,
					$wp_rewrite->author_base,
					$wp_rewrite->front,
				)
			);
		}

		$slugs[] = (string) \get_option( 'category_base' );
		$slugs[] = (string) \get_option( 'tag_base' );

		$objects = array_merge(
			\get_post_types( array( 'public' => true ), 'objects' ),
			\get_taxonomies( array( 'public' => true ), 'objects' )
		);
		foreach ( $objects as $object ) {
			if ( is_array( $object->rewrite ) && ! empty( $object->rewrite['slug'] ) ) {
				$slugs[] = (string) $object->rewrite['slug'];
			}
		}

		$first_segments = array();
		foreach ( $slugs as $slug ) {
			$segment = strtolower( (string) strtok( trim( (string) $slug, '/' ), '/' ) );
			if ( '' !== $segment ) {
				$first_segments[] = $segment;
			}
		}

		return array_values( array_unique( $first_segments ) );
	}

	/**
	 * Describe how a path collides with this site's routes, pages or rewrite rules
	 *
	 * @since 1.5.4
	 * @param string $path Lowercase, already syntax-validated path.
	 * @return string Error message, empty when nothing collides.
	 */
	private static function find_site_collision( string $path ): string {
		if ( in_array( $path, self::get_site_route_slugs(), true ) ) {
			return sprintf(
				/* translators: %s: path */
				\__( '"%s" is a route of this site and cannot be used as the admin path', 'silver-assist-security' ),
				$path
			);
		}

		$types = array_values( \get_post_types( array( 'public' => true ) ) );
		if ( \get_page_by_path( $path, OBJECT, $types ) instanceof \WP_Post ) {
			return sprintf(
				/* translators: %s: path */
				\__( 'A page or post already uses "%s", choose another admin path', 'silver-assist-security' ),
				$path
			);
		}

		if ( self::matches_specific_rewrite_rule( $path ) ) {
			return sprintf(
				/* translators: %s: path */
				\__( 'A rewrite rule of this site already answers on "%s", choose another admin path', 'silver-assist-security' ),
				$path
			);
		}

		return '';
	}

	/**
	 * Whether a rewrite rule that is not a catch-all matches the path
	 *
	 * A rule that also matches a path nobody uses (the post name or page rules) is a catch-all and is skipped.
	 *
	 * @since 1.5.4
	 * @param string $path Path to test.
	 * @return bool
	 */
	private static function matches_specific_rewrite_rule( string $path ): bool {
		global $wp_rewrite;

		if ( ! $wp_rewrite instanceof \WP_Rewrite ) {
			return false;
		}

		$rules = $wp_rewrite->wp_rewrite_rules();
		if ( ! is_array( $rules ) ) {
			return false;
		}

		foreach ( array_keys( $rules ) as $regex ) {
			$pattern = '#^' . $regex . '#';
			if ( ! self::regex_matches( $pattern, $path ) || self::regex_matches( $pattern, self::CONTROL_PATH ) ) {
				continue;
			}
			return true;
		}

		return false;
	}

	/**
	 * Match a rewrite regex against a path with and without the trailing slash
	 *
	 * @param string $pattern Delimited pattern.
	 * @param string $path    Path.
	 * @return bool
	 */
	private static function regex_matches( string $pattern, string $path ): bool {
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- A malformed third-party rule must not break validation.
		return 1 === @preg_match( $pattern, $path ) || 1 === @preg_match( $pattern, $path . '/' );
	}

	/**
	 * Check if path contains forbidden patterns
	 *
	 * @since 1.1.4
	 * @param string $path The path to check (should be lowercase and trimmed).
	 * @return array Result with is_valid and error_message keys
	 */
	private static function check_forbidden_patterns( string $path ): array {
		foreach ( self::$forbidden_paths as $forbidden ) {
			// Reject if:
			// 1. Exact match with forbidden word.
			if ( $path === $forbidden ) {
				return array(
					'is_valid'      => false,
					'error_message' => sprintf(
						/* translators: %s: forbidden path keyword */
						\__( 'Path cannot contain "%s" for security reasons', 'silver-assist-security' ),
						$forbidden
					),
				);
			}

			// 2. Starts with forbidden word followed by separator (admin-panel)
			if ( preg_match( "/^{$forbidden}[-_]/", $path ) ) {
				return array(
					'is_valid'      => false,
					'error_message' => sprintf(
						/* translators: %s: forbidden path keyword */
						\__( 'Path cannot contain "%s" for security reasons', 'silver-assist-security' ),
						$forbidden
					),
				);
			}

			// 3. Ends with forbidden word preceded by separator, but allow any valid prefix
			if ( preg_match( "/[-_]{$forbidden}$/", $path ) ) {
				// Allow if it has any prefix (regardless of length).
				$prefix = preg_replace( "/[-_]{$forbidden}$/", '', $path );
				// Only reject if no prefix or if prefix is also forbidden.
				if ( empty( $prefix ) || in_array( $prefix, self::$forbidden_paths, true ) ) {
					return array(
						'is_valid'      => false,
						'error_message' => sprintf(
							/* translators: %s: forbidden path keyword */
							\__( 'Path cannot contain "%s" for security reasons', 'silver-assist-security' ),
							$forbidden
						),
					);
				}
			}

			// 4. Forbidden word in the middle surrounded by separators
			if ( preg_match( "/[-_]{$forbidden}[-_]/", $path ) ) {
				return array(
					'is_valid'      => false,
					'error_message' => sprintf(
						/* translators: %s: forbidden path keyword */
						\__( 'Path cannot contain "%s" for security reasons', 'silver-assist-security' ),
						$forbidden
					),
				);
			}
		}

		return array(
			'is_valid'      => true,
			'error_message' => '',
		);
	}

	/**
	 * Simple boolean check if path is forbidden (for legacy compatibility)
	 *
	 * Static rules only (no database access), so it is cheap enough for every request.
	 *
	 * @since 1.1.4
	 * @param string $path The path to check.
	 * @return bool True if path is forbidden, false if allowed
	 */
	public static function is_forbidden_path( string $path ): bool {
		$result = self::validate_admin_path( $path, false );
		return ! $result['is_valid'];
	}

	/**
	 * Get the list of forbidden paths
	 *
	 * @since 1.1.4
	 * @return array<string> List of forbidden path keywords
	 */
	public static function get_forbidden_paths(): array {
		return self::$forbidden_paths;
	}

	/**
	 * Add custom forbidden path keyword
	 *
	 * @since 1.1.4
	 * @param string $path The forbidden path to add.
	 * @return void
	 */
	public static function add_forbidden_path( string $path ): void {
		$path = strtolower( trim( $path ) );
		if ( ! empty( $path ) && ! in_array( $path, self::$forbidden_paths, true ) ) {
			self::$forbidden_paths[] = $path;
		}
	}

	/**
	 * Remove custom forbidden path keyword
	 *
	 * @since 1.1.4
	 * @param string $path The forbidden path to remove.
	 * @return void
	 */
	public static function remove_forbidden_path( string $path ): void {
		$path = strtolower( trim( $path ) );
		$key  = array_search( $path, self::$forbidden_paths, true );
		if ( false !== $key ) {
			unset( self::$forbidden_paths[ $key ] );
			self::$forbidden_paths = array_values( self::$forbidden_paths ); // Re-index.
		}
	}
}
