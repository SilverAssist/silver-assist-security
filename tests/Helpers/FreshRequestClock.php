<?php
/**
 * Gives every test a fresh request start time
 *
 * @package SilverAssist\Security\Tests\Helpers
 * @since 1.5.4
 */

declare(strict_types=1);

namespace SilverAssist\Security\Tests\Helpers;

use PHPUnit\Runner\BeforeTestHook;

/**
 * PHPUnit extension that resets `$_SERVER['REQUEST_TIME_FLOAT']` and `REQUEST_TIME` before each test
 *
 * In a PHPUnit process those values are the start of the whole suite. `GraphQLSecurity` measures its
 * 30 second query timeout from `REQUEST_TIME_FLOAT`, so once a slow runner had run the suite for 30
 * seconds, every later GraphQL test failed with "Query execution timeout exceeded". Each test is one
 * request, so it starts the clock itself. A test that simulates a slow request sets its own value
 * after this hook runs.
 */
final class FreshRequestClock implements BeforeTestHook {

	/**
	 * Reset the request clock
	 *
	 * @param string $test Test name.
	 * @return void
	 */
	public function executeBeforeTest( string $test ): void {
		$_SERVER['REQUEST_TIME_FLOAT'] = \microtime( true );
		$_SERVER['REQUEST_TIME']       = \time();
	}
}
