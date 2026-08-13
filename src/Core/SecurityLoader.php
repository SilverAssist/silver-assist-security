<?php
/**
 * Silver Assist Security Essentials - Early Security Loader
 *
 * Loads the components that must register their WordPress hooks on
 * "plugins_loaded" (priority 1) rather than "init" — brute-force
 * protection, session timeout enforcement, and other login/auth-adjacent
 * hooks that wp-login.php can act on before "init" fires. Split out from
 * the main Plugin bootstrap (which loads on "init") so this timing
 * requirement is explicit and doesn't get accidentally collapsed into the
 * later, more common bootstrap hook.
 *
 * @package SilverAssist\Security\Core
 * @since 1.5.1
 * @author Silver Assist
 * @version 1.5.1
 */

namespace SilverAssist\Security\Core;

use SilverAssist\PluginKernel\AbstractPlugin;
use SilverAssist\Security\Security\AdminHideSecurity;
use SilverAssist\Security\Security\GeneralSecurity;
use SilverAssist\Security\Security\LoginBranding;
use SilverAssist\Security\Security\LoginSecurity;
use SilverAssist\Security\Security\RestAPISecurity;

// Prevent direct access.
defined( 'ABSPATH' ) || exit;

/**
 * Class SecurityLoader
 *
 * Singleton access (instance()) and the priority-ordered component loading
 * loop are inherited from AbstractPlugin (silverassist/wp-plugin-kernel).
 * Bootstrapped from the main plugin file on plugins_loaded at priority 1 —
 * the earliest of this plugin's three bootstrap hooks, matching
 * Plugin::init_security_components()'s pre-kernel timing exactly.
 *
 * @since 1.5.1
 */
class SecurityLoader extends AbstractPlugin {

	/**
	 * List the component classes this loader loads
	 *
	 * @since 1.5.1
	 * @return array<class-string>
	 */
	protected function get_components(): array {
		return array(
			LoginSecurity::class,
			GeneralSecurity::class,
			RestAPISecurity::class,
			LoginBranding::class,
			AdminHideSecurity::class,
		);
	}
}
