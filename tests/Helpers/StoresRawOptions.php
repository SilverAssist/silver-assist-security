<?php
/**
 * Raw option storage helper
 *
 * The plugin's options are sanitized and clamped by their registered callbacks (#153). Tests that need an
 * out-of-range value (a one second window, a limit of one request) or a value an older version stored
 * write it with this helper, which skips the callbacks for that option for the rest of the test.
 *
 * @package SilverAssist\Security\Tests\Helpers
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Helpers;

/**
 * Trait for tests that store values the settings would not accept
 */
trait StoresRawOptions {

	/**
	 * Write an option without its sanitize callback
	 *
	 * WP_UnitTestCase restores the hooks after each test, so the callback is back for the next one.
	 *
	 * @param string $option Option name.
	 * @param mixed  $value  Value to store as is.
	 * @return void
	 */
	protected function store_raw_option( string $option, $value ): void {
		\remove_all_filters( "sanitize_option_{$option}" );
		\update_option( $option, $value );
	}
}
