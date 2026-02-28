<?php
/**
 * Silver Assist Security Essentials - Under Attack Mode Test
 *
 * TDD test suite for Under Attack Mode functionality that activates
 * CAPTCHA protection during coordinated attacks.
 *
 * @package SilverAssist\Security\Tests
 * @since 1.1.15
 */

use SilverAssist\Security\Security\UnderAttackMode;
use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * Under Attack Mode Test Class
 *
 * Tests the emergency mode that activates CAPTCHA during mass attacks
 *
 * @since 1.1.15
 */
class UnderAttackModeTest extends WP_UnitTestCase {

	/**
	 * Setup test environment
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function setUp(): void {
		parent::setUp();
		$this->clean_test_transients();
		// Enable the Under Attack toggle so is_under_attack() and record_attack() are not gated.
		\update_option( 'silver_assist_under_attack_enabled', 1 );
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
	 * Clean up test transients using aggressive database cleanup
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function clean_test_transients(): void {
		global $wpdb;
		
		// Clean all Under Attack mode transients from database directly
		$wpdb->query(
			"DELETE FROM {$wpdb->options} 
			WHERE option_name LIKE '_transient_under_attack_%' 
			OR option_name LIKE '_transient_timeout_under_attack_%'
			OR option_name LIKE '_transient_attack_counter_%'
			OR option_name LIKE '_transient_timeout_attack_counter_%'"
		);
	}

	/**
	 * Test Under Attack mode activation based on attack threshold
	 *
	 * Should activate when attack rate exceeds configured threshold.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_under_attack_mode_activation(): void {
		$under_attack = UnderAttackMode::getInstance();
		
		// Should start inactive
		$this->assertFalse(
			$under_attack->is_under_attack(),
			'Under Attack mode should start inactive'
		);
		
		// Record multiple attacks to trigger mode
		$threshold = (int) DefaultConfig::get_option('silver_assist_under_attack_threshold');
		
		for ($i = 0; $i < $threshold; $i++) {
			$under_attack->record_attack();
		}
		
		// Should now be under attack
		$this->assertTrue(
			$under_attack->is_under_attack(),
			'Under Attack mode should activate after threshold reached'
		);
	}

	/**
	 * Test Under Attack mode prevents form submissions without CAPTCHA
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_under_attack_blocks_submissions_without_captcha(): void {
		$under_attack = UnderAttackMode::getInstance();
		
		// Activate Under Attack mode manually
		$under_attack->activate_under_attack_mode('Test activation');
		
		// Form submission should be blocked without CAPTCHA
		$this->assertFalse(
			$under_attack->allow_form_submission(['test_field' => 'value']),
			'Form submission should be blocked without CAPTCHA in Under Attack mode'
		);
		
		// Form submission should be allowed with valid CAPTCHA
		$captcha_data = $under_attack->generate_captcha();
		$form_data_with_captcha = [
			'test_field' => 'value',
			'silver_captcha_answer' => $captcha_data['answer'],
			'silver_captcha_token' => $captcha_data['token']
		];
		
		$this->assertTrue(
			$under_attack->allow_form_submission($form_data_with_captcha),
			'Form submission should be allowed with valid CAPTCHA'
		);
	}

	/**
	 * Test CAPTCHA generation and validation
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_captcha_generation_and_validation(): void {
		$under_attack = UnderAttackMode::getInstance();
		
		// Generate CAPTCHA
		$captcha = $under_attack->generate_captcha();
		
		$this->assertIsArray($captcha, 'CAPTCHA should return array');
		$this->assertArrayHasKey('question', $captcha, 'CAPTCHA should have question');
		$this->assertArrayHasKey('answer', $captcha, 'CAPTCHA should have answer');
		$this->assertArrayHasKey('token', $captcha, 'CAPTCHA should have token');
		
		// Test correct answer validation
		$this->assertTrue(
			$under_attack->validate_captcha($captcha['answer'], $captcha['token']),
			'Correct CAPTCHA answer should validate'
		);
		
		// Test incorrect answer validation
		$this->assertFalse(
			$under_attack->validate_captcha('wrong_answer', $captcha['token']),
			'Incorrect CAPTCHA answer should fail validation'
		);
		
		// Test invalid token validation
		$this->assertFalse(
			$under_attack->validate_captcha($captcha['answer'], 'invalid_token'),
			'Invalid CAPTCHA token should fail validation'
		);
	}

	/**
	 * Test Under Attack mode automatic expiration
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_under_attack_mode_expiration(): void {
		$under_attack = UnderAttackMode::getInstance();
		
		// Activate with short duration for testing
		$under_attack->activate_under_attack_mode('Test expiration', 1);
		
		$this->assertTrue(
			$under_attack->is_under_attack(),
			'Under Attack mode should be active immediately after activation'
		);
		
		// Wait for expiration (simulate by manipulating transient)
		sleep(2);
		
		$this->assertFalse(
			$under_attack->is_under_attack(),
			'Under Attack mode should expire after duration'
		);
	}

	/**
	 * Test Under Attack mode can be manually deactivated
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_manual_deactivation(): void {
		$under_attack = UnderAttackMode::getInstance();
		
		// Activate mode
		$under_attack->activate_under_attack_mode('Test manual deactivation');
		$this->assertTrue($under_attack->is_under_attack());
		
		// Deactivate manually
		$under_attack->deactivate_under_attack_mode();
		$this->assertFalse(
			$under_attack->is_under_attack(),
			'Under Attack mode should be deactivated manually'
		);
	}

	/**
	 * Test attack counter resets after time window
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_attack_counter_window_reset(): void {
		$under_attack = UnderAttackMode::getInstance();
		
		// Record some attacks
		$under_attack->record_attack();
		$under_attack->record_attack();
		
		$this->assertEquals(
			2,
			$under_attack->get_current_attack_count(),
			'Attack counter should reflect recorded attacks'
		);
		
		// Simulate window expiration by manipulating transient
		$counter_key = 'attack_counter_' . date('Y-m-d-H-i');
		\delete_transient($counter_key);
		
		$this->assertEquals(
			0,
			$under_attack->get_current_attack_count(),
			'Attack counter should reset after window expiration'
		);
	}

	/**
	 * Test Under Attack mode statistics and monitoring
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_under_attack_statistics(): void {
		$under_attack = UnderAttackMode::getInstance();
		
		// Get initial stats
		$initial_stats = $under_attack->get_attack_statistics();
		$this->assertIsArray($initial_stats, 'Statistics should return array');
		
		// Record attacks and activate mode
		for ($i = 0; $i < 15; $i++) {
			$under_attack->record_attack();
		}
		
		$stats = $under_attack->get_attack_statistics();
		$this->assertGreaterThan(
			$initial_stats['total_attacks'],
			$stats['total_attacks'],
			'Total attacks should increase'
		);
		
		$this->assertTrue(
			$stats['is_under_attack'],
			'Statistics should show Under Attack mode is active'
		);
	}

	/**
	 * Test different CAPTCHA difficulty levels
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_captcha_difficulty_levels(): void {
		$under_attack = UnderAttackMode::getInstance();
		
		// Test easy CAPTCHA
		$easy_captcha = $under_attack->generate_captcha('easy');
		$this->assertIsArray($easy_captcha);
		$this->assertArrayHasKey('difficulty', $easy_captcha);
		$this->assertEquals('easy', $easy_captcha['difficulty']);
		
		// Test medium CAPTCHA  
		$medium_captcha = $under_attack->generate_captcha('medium');
		$this->assertEquals('medium', $medium_captcha['difficulty']);
		
		// Test hard CAPTCHA
		$hard_captcha = $under_attack->generate_captcha('hard');
		$this->assertEquals('hard', $hard_captcha['difficulty']);
	}

	/**
	 * Test Under Attack mode with coordinated attack simulation
	 *
	 * Simulates the actual Contact Form 7 attack pattern from multiple IPs.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function test_coordinated_attack_response(): void {
		$under_attack = UnderAttackMode::getInstance();
		
		// Simulate coordinated attack from multiple sources
		$attack_ips = ['45.148.8.70', '192.168.1.100', '10.0.0.1', '172.16.0.1'];
		
		foreach ($attack_ips as $ip) {
			// Simulate multiple rapid requests from each IP
			for ($i = 0; $i < 3; $i++) {
				$under_attack->record_attack($ip);
			}
		}
		
		// Should trigger Under Attack mode due to coordinated nature
		$this->assertTrue(
			$under_attack->is_under_attack(),
			'Coordinated attack should trigger Under Attack mode'
		);
		
		// Verify all subsequent requests require CAPTCHA
		$this->assertFalse(
			$under_attack->allow_form_submission(['normal_field' => 'value']),
			'All form submissions should require CAPTCHA during Under Attack mode'
		);
	}
}