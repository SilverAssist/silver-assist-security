<?php
/**
 * Silver Assist Security Essentials - Contact Form 7 Integration Test
 *
 * TDD test suite for Contact Form 7 integration that applies all security
 * measures (rate limiting, IP blacklist) to CF7 forms.
 *
 * @package SilverAssist\Security\Tests
 * @since 1.1.15
 */

use SilverAssist\Security\Security\ContactForm7Integration;
use SilverAssist\Security\Security\IPBlacklist;
use SilverAssist\Security\Core\DefaultConfig;

/**
 * Contact Form 7 Integration Test Class
 *
 * Tests security integration with Contact Form 7 forms
 *
 * @since 1.1.15
 */
class ContactForm7IntegrationTest extends WP_UnitTestCase {

	/**
	 * Setup test environment
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function setUp(): void {
		parent::setUp();
		$this->clean_test_transients();
		
		// Mock CF7 environment
		$this->mock_cf7_environment();
	}

	/**
	 * Cleanup test environment
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function tearDown(): void {
		$this->clean_test_transients();
		parent::tearDown();
	}

	/**
	 * Clean up all security-related transients
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function clean_test_transients(): void {
		global $wpdb;
		
		$wpdb->query(
			"DELETE FROM {$wpdb->options} 
			WHERE option_name LIKE '_transient_form_rate_%'
			OR option_name LIKE '_transient_ip_blacklist_%'
			OR option_name LIKE '_transient_ip_violations_%'
			OR option_name LIKE '_transient_cf7_submission_%'"
		);
	}

	/**
	 * Mock Contact Form 7 environment for testing
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function mock_cf7_environment(): void {
		// Mock CF7 constants and globals if needed
		if ( ! defined( 'WPCF7_VERSION' ) ) {
			define( 'WPCF7_VERSION', '5.8' );
		}
	}

	/**
	 * Test CF7 integration hooks registration
	 *
	 * Should properly register all necessary WordPress hooks.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_cf7_hooks_registration(): void {
		$cf7_integration = new ContactForm7Integration();
		
		// Test hook registration
		$this->assertTrue(
			has_action( 'wpcf7_before_send_mail' ),
			'Should register wpcf7_before_send_mail hook'
		);
		
		$this->assertTrue(
			has_filter( 'wpcf7_validate' ),
			'Should register wpcf7_validate filter'
		);
		
		$this->assertTrue(
			has_action( 'wpcf7_spam' ),
			'Should register wpcf7_spam action'
		);
		
		$this->assertTrue(
			has_filter( 'wpcf7_form_elements' ),
			'Should register wpcf7_form_elements filter for honeypot'
		);
	}

	/**
	 * Test CF7 form submission security validation
	 *
	 * Should apply all security measures to form submissions.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_cf7_security_validation(): void {
		$cf7_integration = new ContactForm7Integration();
		$malicious_ip = '45.148.8.70'; // IP from actual attack
		
		// Mock CF7 submission data
		$submission_data = [
			'your-name' => 'Test User',
			'your-email' => 'test@example.com',
			'your-message' => 'PG_SLEEP(15)', // SQL injection attempt
		];
		
		// has_sql_injection_attempt() inspects $_POST, so populate it
		$_POST = $submission_data;
		
		$mock_contact_form = $this->create_mock_cf7_form();
		
		// Test security validation
		$is_valid = $cf7_integration->validate_cf7_submission( 
			$mock_contact_form, 
			$submission_data,
			$malicious_ip
		);
		
		// Cleanup
		$_POST = [];
		
		$this->assertFalse(
			$is_valid,
			'CF7 submission with SQL injection should be blocked'
		);
	}

	/**
	 * Test CF7 rate limiting integration
	 *
	 * Should apply form rate limiting to CF7 submissions.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_cf7_rate_limiting(): void {
		$cf7_integration = new ContactForm7Integration();
		$test_ip = '192.168.2.100'; // Use different subnet to avoid conflicts
		
		// Set modern user agent to avoid obsolete browser detection
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
		
		$mock_contact_form = $this->create_mock_cf7_form();
		$normal_submission = [
			'your-name' => 'John Doe',
			'your-email' => 'john@example.com',
			'your-message' => 'This is a normal test message without spam patterns'
		];
		
		// First submissions should be allowed
		$rate_limit = (int) DefaultConfig::get_option( 'silver_assist_form_rate_limit' );
		for ( $i = 0; $i < $rate_limit; $i++ ) {
			$this->assertTrue(
				$cf7_integration->validate_cf7_submission( $mock_contact_form, $normal_submission, $test_ip ),
				"Submission {$i} should be allowed within rate limit"
			);
		}
		
		// Next submission should be rate limited
		$this->assertFalse(
			$cf7_integration->validate_cf7_submission( $mock_contact_form, $normal_submission, $test_ip ),
			'Submission exceeding rate limit should be blocked'
		);
		
		// Reset user agent
		unset( $_SERVER['HTTP_USER_AGENT'] );
	}

	/**
	 * Test CF7 IP blacklist integration
	 *
	 * Should block submissions from blacklisted IPs.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_cf7_ip_blacklist_blocking(): void {
		$cf7_integration = new ContactForm7Integration();
		$blacklisted_ip = '45.148.8.70';
		
		// Blacklist the IP
		$ip_blacklist = new IPBlacklist();
		$ip_blacklist->add_to_blacklist( $blacklisted_ip, 'CF7 spam attack', 3600 );
		
		$mock_contact_form = $this->create_mock_cf7_form();
		$submission_data = [
			'your-name' => 'Spammer',
			'your-email' => 'spam@evil.com',
			'your-message' => 'Spam message'
		];
		
		// Submission from blacklisted IP should be blocked
		$this->assertFalse(
			$cf7_integration->validate_cf7_submission( $mock_contact_form, $submission_data, $blacklisted_ip ),
			'CF7 submission from blacklisted IP should be blocked'
		);
	}

	/**
	 * Test CF7 honeypot field integration
	 *
	 * Should block submissions with honeypot field filled.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_cf7_honeypot_protection(): void {
		$cf7_integration = new ContactForm7Integration();
		
		// Set modern user agent to avoid obsolete browser detection
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36';
		
		$mock_contact_form = $this->create_mock_cf7_form();
		
		// Submission with honeypot filled (bot behavior)
		$bot_submission = [
			'your-name' => 'Bot Name',
			'your-email' => 'bot@spam.com',
			'your-message' => 'Bot message content here',
			'silver_honeypot_field' => 'filled_by_bot' // Bots fill this field
		];
		
		$this->assertFalse(
			$cf7_integration->validate_cf7_submission( $mock_contact_form, $bot_submission, '192.168.3.100' ),
			'CF7 submission with filled honeypot should be blocked'
		);
		
		// Normal submission without honeypot
		$normal_submission = [
			'your-name' => 'Real User',
			'your-email' => 'real@example.com',
			'your-message' => 'This is a real message from a legitimate user'
			// silver_honeypot_field intentionally empty
		];
		
		$this->assertTrue(
			$cf7_integration->validate_cf7_submission( $mock_contact_form, $normal_submission, '192.168.3.101' ),
			'CF7 submission without filled honeypot should be allowed'
		);
		
		// Reset user agent
		unset( $_SERVER['HTTP_USER_AGENT'] );
	}

	/**
	 * Test CF7 obsolete browser detection
	 *
	 * Should block submissions from obsolete browsers.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_cf7_obsolete_browser_blocking(): void {
		$cf7_integration = new ContactForm7Integration();
		
		// Simulate obsolete browser (from actual attack)
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; 360SE)';
		
		$mock_contact_form = $this->create_mock_cf7_form();
		$submission_data = [
			'your-name' => 'Old Browser User',
			'your-email' => 'old@browser.com',
			'your-message' => 'Message from old browser'
		];
		
		$this->assertFalse(
			$cf7_integration->validate_cf7_submission( $mock_contact_form, $submission_data ),
			'CF7 submission from obsolete browser should be blocked'
		);
		
		// Reset user agent
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (compatible; modern browser)';
	}

	/**
	 * Test CF7 submission timing validation
	 *
	 * Should block submissions that are too fast (bot behavior).
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_cf7_submission_timing(): void {
		$cf7_integration = new ContactForm7Integration();
		
		// Set modern user agent to avoid obsolete browser detection
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36';
		
		$mock_contact_form = $this->create_mock_cf7_form();
		$submission_data = [
			'your-name' => 'Fast Submitter',
			'your-email' => 'fast@example.com',
			'your-message' => 'Normal test submission message'
		];
		
		// Simulate very fast submission (bot behavior)
		$form_start_time = microtime( true ) - 0.1; // 0.1 seconds ago
		
		$this->assertFalse(
			$cf7_integration->validate_cf7_submission( 
				$mock_contact_form, 
				$submission_data, 
				'192.168.1.200', // Different IP to avoid rate limiting 
				$form_start_time 
			),
			'CF7 submission too fast should be blocked as bot'
		);
		
		// Simulate normal submission timing
		$normal_start_time = microtime( true ) - 5; // 5 seconds ago
		
		$this->assertTrue(
			$cf7_integration->validate_cf7_submission( 
				$mock_contact_form, 
				$submission_data, 
				'192.168.1.201', // Different IP to avoid rate limiting
				$normal_start_time 
			),
			'CF7 submission with normal timing should be allowed'
		);
		
		// Reset user agent
		unset( $_SERVER['HTTP_USER_AGENT'] );
	}

	/**
	 * Test CF7 spam pattern detection
	 *
	 * Should detect and block common spam patterns.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_cf7_spam_pattern_detection(): void {
		$cf7_integration = new ContactForm7Integration();
		
		$mock_contact_form = $this->create_mock_cf7_form();
		
		// Common spam patterns
		$spam_submissions = [
			[
				'your-name' => 'CHEAP VIAGRA ONLINE',
				'your-email' => 'spam@viagra.com',
				'your-message' => 'Buy cheap viagra now!'
			],
			[
				'your-name' => 'Casino Winner',
				'your-email' => 'win@casino.com',
				'your-message' => 'You won $1000000 in our casino!'
			],
			[
				'your-name' => 'Bitcoin Trader',
				'your-email' => 'profit@bitcoin.com',
				'your-message' => 'Make money with Bitcoin! Click here!'
			]
		];
		
		foreach ( $spam_submissions as $index => $spam_data ) {
			$this->assertFalse(
				$cf7_integration->validate_cf7_submission( $mock_contact_form, $spam_data ),
				"Spam pattern {$index} should be detected and blocked"
			);
		}
	}

	/**
	 * Create mock Contact Form 7 form for testing
	 *
	 * @since 1.1.15
	 * @return object Mock CF7 form object
	 */
	private function create_mock_cf7_form(): object {
		return (object) [
			'id' => 123,
			'title' => 'Test Contact Form',
			'form' => '[text* your-name][email* your-email][textarea your-message][submit "Send"]',
			'mail' => [
				'subject' => 'Test Subject',
				'sender' => 'test@example.com',
				'body' => 'Test body',
				'recipient' => 'admin@example.com'
			]
		];
	}
}