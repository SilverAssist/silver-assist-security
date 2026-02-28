<?php
/**
 * AJAX Test Helper Trait
 *
 * Provides utility methods for testing AJAX handlers in PHPUnit.
 * Handles the wp_send_json() -> wp_die() -> WPAjaxDieContinueException flow
 * that WordPress test suite uses for AJAX testing.
 *
 * @package SilverAssist\Security\Tests\Helpers
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Tests\Helpers;

/**
 * Error thrown to halt AJAX execution in tests.
 *
 * Extends \Error (NOT \Exception) so that handler code with
 * `catch (\Exception $e)` won't intercept it. This prevents
 * double JSON output when wp_send_json calls wp_die().
 *
 * @since 1.1.15
 */
class AjaxTestDieError extends \Error {}

/**
 * Trait for AJAX test methods
 *
 * Usage: Add `use AjaxTestHelper;` in your test class, then call
 * `$this->setup_ajax_environment()` in setUp() and
 * `$this->teardown_ajax_environment()` in tearDown().
 *
 * To capture AJAX output use:
 * `$response = $this->call_ajax_handler( $handler, 'method_name' );`
 *
 * @since 1.1.15
 */
trait AjaxTestHelper {

	/**
	 * Last captured AJAX response (raw string)
	 *
	 * @var string
	 */
	protected string $_ajax_response = '';

	/**
	 * Saved error reporting level
	 *
	 * @var int
	 */
	protected int $_ajax_error_level = 0;

	/**
	 * Set up AJAX testing environment
	 *
	 * Call this in your test setUp() method to enable proper AJAX handling.
	 * This makes wp_send_json() call wp_die() instead of die, and
	 * wp_die() throw WPAjaxDieContinueException instead of exiting.
	 */
	protected function setup_ajax_environment(): void {
		// Make wp_doing_ajax() return true so wp_send_json uses wp_die() not die
		\add_filter( 'wp_doing_ajax', '__return_true' );

		// Override the wp_die handler for AJAX to throw exceptions instead of dying
		\add_filter( 'wp_die_ajax_handler', [ $this, 'get_ajax_die_handler' ], 1, 1 );

		// Set screen to ajax
		\set_current_screen( 'ajax' );

		// Suppress "headers already sent" warnings
		$this->_ajax_error_level = error_reporting();
		error_reporting( $this->_ajax_error_level & ~E_WARNING );
	}

	/**
	 * Tear down AJAX testing environment
	 *
	 * Call this in your test tearDown() method to restore normal behavior.
	 */
	protected function teardown_ajax_environment(): void {
		\remove_filter( 'wp_doing_ajax', '__return_true' );
		\remove_filter( 'wp_die_ajax_handler', [ $this, 'get_ajax_die_handler' ], 1 );
		error_reporting( $this->_ajax_error_level );
		\set_current_screen( 'front' );
	}

	/**
	 * Returns the die handler callback for AJAX tests
	 *
	 * @return callable
	 */
	public function get_ajax_die_handler(): callable {
		return [ $this, 'handle_ajax_die' ];
	}

	/**
	 * Custom wp_die handler for AJAX tests
	 *
	 * Captures output and throws an exception to stop execution
	 * without killing PHPUnit.
	 *
	 * @param string $message Die message.
	 * @throws \WPAjaxDieContinueException When there is buffered output.
	 * @throws \WPAjaxDieStopException     When there is no buffered output.
	 */
	public function handle_ajax_die( $message ): void {
		$this->_ajax_response .= ob_get_clean();

		// Throw Error (not Exception) to prevent handler's catch(\Exception) from intercepting
		throw new AjaxTestDieError( is_scalar( $message ) ? (string) $message : '0' );
	}

	/**
	 * Call an AJAX handler method and capture its JSON response
	 *
	 * This method handles the full AJAX lifecycle:
	 * 1. Starts output buffering
	 * 2. Calls the handler method
	 * 3. Catches the WPAjaxDie exceptions
	 * 4. Returns the decoded JSON response
	 *
	 * @param object $handler The AJAX handler object.
	 * @param string $method  The method name to call.
	 * @return array|null Decoded JSON response, or null if invalid.
	 */
	protected function call_ajax_handler( object $handler, string $method ): ?array {
		$this->_ajax_response = '';
		$ob_level = ob_get_level();

		try {
			ob_start();
			$handler->$method();
			// If we reach here, no wp_die was called — grab any buffered output
			$this->_ajax_response = ob_get_clean();
		} catch ( AjaxTestDieError $e ) {
			// Normal AJAX termination — response already captured in handle_ajax_die
			// Clean any extra output buffers we may have added
			while ( ob_get_level() > $ob_level ) {
				ob_end_clean();
			}
		}

		return json_decode( $this->_ajax_response, true );
	}

	/**
	 * Get the raw AJAX response string
	 *
	 * @return string
	 */
	protected function get_ajax_raw_response(): string {
		return $this->_ajax_response;
	}
}
