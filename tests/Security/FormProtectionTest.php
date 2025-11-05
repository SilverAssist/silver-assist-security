<?php
/**
 * Tests for Form Protection functionality
 *
 * Tests rate limiting, obsolete browser detection, and SQL injection detection
 * for form submissions across the site (not just login forms).
 *
 * @package SilverAssist\Security\Tests\Security
 * @since 1.1.15
 */

use SilverAssist\Security\Security\FormProtection;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * Form Protection Test class
 *
 * @since 1.1.15
 */
class FormProtectionTest extends WP_UnitTestCase {

	/**
	 * Test form rate limiting functionality
	 *
	 * Verifies that multiple form submissions from same IP are limited
	 * according to configured thresholds.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_form_rate_limiting_blocks_excessive_submissions(): void {
		$form_protection = new FormProtection();
		$test_ip = '45.148.8.70'; // Same IP from the attack

		// First 2 submissions should be allowed (default rate limit: 2/minute)
		$this->assertTrue(
			$form_protection->allow_form_submission( $test_ip ),
			'First form submission should be allowed'
		);

		$this->assertTrue(
			$form_protection->allow_form_submission( $test_ip ),
			'Second form submission should be allowed'
		);

		// Third submission should be blocked
		$this->assertFalse(
			$form_protection->allow_form_submission( $test_ip ),
			'Third form submission should be blocked due to rate limiting'
		);
	}

	/**
	 * Test that rate limiting resets after time window
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_form_rate_limiting_resets_after_time_window(): void {
		$form_protection = new FormProtection();
		$test_ip = '192.168.1.100';

		// Use up rate limit
		$form_protection->allow_form_submission( $test_ip );
		$form_protection->allow_form_submission( $test_ip );

		// Should be blocked
		$this->assertFalse( $form_protection->allow_form_submission( $test_ip ) );

		// Simulate time passing by clearing the transient (simulating expiry)
		$rate_key = SecurityHelper::generate_ip_transient_key( $test_ip, 'form_rate' );
		\delete_transient( $rate_key );

		// Should be allowed again after reset
		$this->assertTrue(
			$form_protection->allow_form_submission( $test_ip ),
			'Form submission should be allowed after rate limit reset'
		);
	}

	/**
	 * Test obsolete browser detection
	 *
	 * Verifies detection of old browsers like IE 7.0 and suspicious patterns
	 * from the actual attack.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_obsolete_browser_detection(): void {
		// Test the exact User-Agent from the attack
		$attack_user_agent = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)';
		$this->assertTrue(
			FormProtection::is_obsolete_browser( $attack_user_agent ),
			'Should detect the attack User-Agent as obsolete'
		);

		// Test other obsolete patterns
		$obsolete_agents = [
			'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)',
			'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0)',
			'Mozilla/3.0 (compatible)',
			'QQBrowser/10.0',
			'Baidu Spider'
		];

		foreach ( $obsolete_agents as $user_agent ) {
			$this->assertTrue(
				FormProtection::is_obsolete_browser( $user_agent ),
				"Should detect obsolete browser: {$user_agent}"
			);
		}

		// Test modern browsers (should NOT be detected as obsolete)
		$modern_agents = [
			'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
			'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
			'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
		];

		foreach ( $modern_agents as $user_agent ) {
			$this->assertFalse(
				FormProtection::is_obsolete_browser( $user_agent ),
				"Should NOT detect modern browser as obsolete: {$user_agent}"
			);
		}
	}

	/**
	 * Test SQL injection detection in URL parameters
	 *
	 * Tests detection of the exact SQL injection pattern from the attack.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_sql_injection_detection_in_url_parameters(): void {
		// Test the exact SQL injection from the attack
		$_SERVER['QUERY_STRING'] = 'location=1-1+OR+128%3D%28SELECT+128+FROM+PG_SLEEP%2815%29%29--';
		
		$this->assertTrue(
			FormProtection::has_sql_injection_attempt(),
			'Should detect PG_SLEEP SQL injection attempt from query string'
		);

		// Test other common SQL injection patterns
		$injection_patterns = [
			'id=1 UNION SELECT * FROM users--',
			'search=\' OR 1=1--',
			'user=admin\'; DROP TABLE users;--',
			'param=1 AND (SELECT SLEEP(5))',
			'field=test\' OR \'1\'=\'1',
			'value=1; EXEC xp_cmdshell(\'dir\')',
		];

		foreach ( $injection_patterns as $pattern ) {
			$_SERVER['QUERY_STRING'] = $pattern;
			$this->assertTrue(
				FormProtection::has_sql_injection_attempt(),
				"Should detect SQL injection pattern: {$pattern}"
			);
		}

		// Clean up
		unset( $_SERVER['QUERY_STRING'] );
	}

	/**
	 * Test SQL injection detection in POST data
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_sql_injection_detection_in_post_data(): void {
		// Simulate POST data with SQL injection
		$_POST['message'] = "Hello'; DROP TABLE wp_posts;--";
		$_POST['email'] = "test@test.com' UNION SELECT user_pass FROM wp_users--";

		$this->assertTrue(
			FormProtection::has_sql_injection_attempt(),
			'Should detect SQL injection in POST data'
		);

		// Test clean POST data
		$_POST = [
			'name' => 'John Doe',
			'email' => 'john@example.com',
			'message' => 'This is a legitimate message.'
		];

		$this->assertFalse(
			FormProtection::has_sql_injection_attempt(),
			'Should NOT detect SQL injection in clean POST data'
		);

		// Clean up
		$_POST = [];
	}

	/**
	 * Test combined security validation
	 *
	 * Tests multiple security checks working together as they would
	 * in a real attack scenario.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_combined_security_validation(): void {
		$form_protection = new FormProtection();
		$malicious_ip = '45.148.8.70';

		// Simulate the exact attack scenario
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)';
		$_SERVER['QUERY_STRING'] = 'location=1-1+OR+128%3D%28SELECT+128+FROM+PG_SLEEP%2815%29%29--';

		// Should detect obsolete browser
		$this->assertTrue(
			FormProtection::is_obsolete_browser( $_SERVER['HTTP_USER_AGENT'] ),
			'Should detect obsolete browser from attack'
		);

		// Should detect SQL injection
		$this->assertTrue(
			FormProtection::has_sql_injection_attempt(),
			'Should detect SQL injection from attack'
		);

		// Should allow first few submissions but then block
		$this->assertTrue( $form_protection->allow_form_submission( $malicious_ip ) );
		$this->assertTrue( $form_protection->allow_form_submission( $malicious_ip ) );
		$this->assertFalse( $form_protection->allow_form_submission( $malicious_ip ) );

		// Clean up
		unset( $_SERVER['HTTP_USER_AGENT'] );
		unset( $_SERVER['QUERY_STRING'] );
	}

	/**
	 * Test rate limiting with different IPs
	 *
	 * Verifies that rate limiting is per-IP, not global.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_rate_limiting_is_per_ip(): void {
		$form_protection = new FormProtection();
		$ip1 = '192.168.1.100';
		$ip2 = '192.168.1.101';

		// Use up rate limit for IP1
		$form_protection->allow_form_submission( $ip1 );
		$form_protection->allow_form_submission( $ip1 );
		$this->assertFalse(
			$form_protection->allow_form_submission( $ip1 ),
			'IP1 should be rate limited'
		);

		// IP2 should still be allowed
		$this->assertTrue(
			$form_protection->allow_form_submission( $ip2 ),
			'IP2 should not be affected by IP1 rate limiting'
		);
	}

	/**
	 * Test empty and malformed User-Agent detection
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_empty_and_malformed_user_agent_detection(): void {
		// Empty User-Agent
		$this->assertTrue(
			FormProtection::is_obsolete_browser( '' ),
			'Should detect empty User-Agent as suspicious'
		);

		// Very short User-Agent
		$this->assertTrue(
			FormProtection::is_obsolete_browser( 'Bot' ),
			'Should detect very short User-Agent as suspicious'
		);

		// Minimal valid User-Agent (should not be detected)
		$this->assertFalse(
			FormProtection::is_obsolete_browser( 'Mozilla/5.0 (compatible; legitimate browser)' ),
			'Should not detect minimal valid User-Agent'
		);
	}

	/**
	 * Clean up after each test
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function tearDown(): void {
		// Clean up transients created during tests
		$test_ips = [ '45.148.8.70', '192.168.1.100', '192.168.1.101' ];
		
		foreach ( $test_ips as $ip ) {
			$rate_key = SecurityHelper::generate_ip_transient_key( $ip, 'form_rate' );
			\delete_transient( $rate_key );
		}

		// Clean up globals
		unset( $_SERVER['HTTP_USER_AGENT'] );
		unset( $_SERVER['QUERY_STRING'] );
		$_POST = [];

		parent::tearDown();
	}
}