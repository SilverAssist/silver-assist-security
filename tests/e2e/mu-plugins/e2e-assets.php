<?php
/**
 * Plugin Name: E2E known assets
 * Description: Enqueues deterministic assets so E2E specs never pass vacuously. Test environment only.
 *
 * @package SilverAssist\Security\Tests
 */

add_action(
	'wp_enqueue_scripts',
	static function () {
		wp_enqueue_style( 'e2e-known-style', plugins_url( 'e2e-assets.css', __FILE__ ), array(), '9.9.9' );
		wp_enqueue_script( 'e2e-known-script', plugins_url( 'e2e-assets.js', __FILE__ ), array(), '9.9.9', true );
		wp_enqueue_script( 'jquery' ); // A WordPress core script under /wp-includes/.
	}
);
