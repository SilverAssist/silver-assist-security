<?php
/**
 * Silver Assist Security Essentials - GraphQL Security Loader
 *
 * Loads GraphQLSecurity on its own "plugins_loaded" (priority 5) tier,
 * deliberately earlier than "init" but later than SecurityLoader's
 * priority 1 — so that GraphQLSecurity's determine_current_user filter
 * (see GraphQLSecurity::register_hooks()) is registered before WordPress
 * resolves the current user for the request, while still giving WPGraphQL
 * a chance to define its WPGraphQL class first (which, unlike Contact
 * Form 7's WPCF7 class, is not reliably available at plugins_loaded
 * priority 1 — see the nextjs-graphql-hooks migration's should_load()
 * timing finding).
 *
 * @package SilverAssist\Security\GraphQL
 * @since 1.5.1
 * @author Silver Assist
 * @version 1.5.1
 */

namespace SilverAssist\Security\GraphQL;

use SilverAssist\PluginKernel\AbstractPlugin;

// Prevent direct access.
defined( 'ABSPATH' ) || exit;

/**
 * Class GraphQLLoader
 *
 * Singleton access (instance()) and the priority-ordered component loading
 * loop are inherited from AbstractPlugin (silverassist/wp-plugin-kernel).
 *
 * @since 1.5.1
 */
class GraphQLLoader extends AbstractPlugin {

	/**
	 * List the component classes this loader loads
	 *
	 * @since 1.5.1
	 * @return array<class-string>
	 */
	protected function get_components(): array {
		return array(
			GraphQLSecurity::class,
		);
	}
}
