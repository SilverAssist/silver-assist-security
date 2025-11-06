<?php
/**
 * Tests for Contact Form 7 Integration functionality
 *
 * @package SilverAssist\Security\Tests\Unit
 */

namespace SilverAssist\Security\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\Plugin;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * Test Contact Form 7 Integration
 */
class ContactForm7IntegrationTest extends TestCase {

	/**
	 * Test CF7 detection functions exist
	 */
	public function test_cf7_detection_functions_exist(): void {
		$this->assertTrue( method_exists( SecurityHelper::class, 'is_contact_form_7_active' ) );
		$this->assertTrue( method_exists( SecurityHelper::class, 'get_contact_form_7_info' ) );
	}

	/**
	 * Test CF7 detection returns boolean
	 */
	public function test_cf7_detection_returns_boolean(): void {
		$is_active = SecurityHelper::is_contact_form_7_active();
		$this->assertIsBool( $is_active );
	}

	/**
	 * Test CF7 info returns array with required keys
	 */
	public function test_cf7_info_returns_array_with_required_keys(): void {
		$info = SecurityHelper::get_contact_form_7_info();
		
		$this->assertIsArray( $info );
		$this->assertArrayHasKey( 'active', $info );
		$this->assertArrayHasKey( 'version', $info );
		$this->assertArrayHasKey( 'message', $info );
		$this->assertIsBool( $info['active'] );
		$this->assertIsString( $info['message'] );
	}

	/**
	 * Test CF7 default configuration values exist
	 */
	public function test_cf7_default_config_values_exist(): void {
		$defaults = DefaultConfig::get_defaults();
		
		// Check CF7 configuration keys exist
		$cf7_config_keys = [
			'silver_assist_cf7_protection_enabled',
			'silver_assist_cf7_rate_limit',
			'silver_assist_cf7_rate_window',
			'silver_assist_cf7_spam_threshold',
			'silver_assist_cf7_honeypot_enabled',
			'silver_assist_cf7_submission_delay',
			'silver_assist_cf7_auto_block_bots',
			'silver_assist_cf7_ip_block_duration',
		];

		foreach ( $cf7_config_keys as $key ) {
			$this->assertArrayHasKey( $key, $defaults, "Configuration key {$key} should exist in defaults" );
		}
	}

	/**
	 * Test CF7 configuration values are reasonable
	 */
	public function test_cf7_config_values_are_reasonable(): void {
		$defaults = DefaultConfig::get_defaults();
		
		// Test rate limit is reasonable
		$this->assertGreaterThan( 0, $defaults['silver_assist_cf7_rate_limit'] );
		$this->assertLessThanOrEqual( 10, $defaults['silver_assist_cf7_rate_limit'] );
		
		// Test rate window is reasonable
		$this->assertGreaterThanOrEqual( 30, $defaults['silver_assist_cf7_rate_window'] );
		$this->assertLessThanOrEqual( 300, $defaults['silver_assist_cf7_rate_window'] );
		
		// Test submission delay is reasonable (in milliseconds)
		$this->assertGreaterThan( 0, $defaults['silver_assist_cf7_submission_delay'] );
		$this->assertLessThanOrEqual( 10000, $defaults['silver_assist_cf7_submission_delay'] ); // Max 10 seconds
		
		// Test IP block duration is reasonable
		$this->assertGreaterThan( 0, $defaults['silver_assist_cf7_ip_block_duration'] );
	}

	/**
	 * Test Plugin has CF7 integration methods
	 */
	public function test_plugin_has_cf7_integration_methods(): void {
		$this->assertTrue( method_exists( Plugin::class, 'init_cf7_integration' ) );
		$this->assertTrue( method_exists( Plugin::class, 'get_cf7_integration' ) );
		$this->assertTrue( method_exists( Plugin::class, 'is_cf7_integration_active' ) );
	}

	/**
	 * Test CF7 integration conditionally loads
	 */
	public function test_cf7_integration_conditionally_loads(): void {
		// This test verifies the integration only loads when CF7 is active
		// Since CF7 won't be active in test environment, integration should be null
		$plugin = Plugin::getInstance();
		$integration = $plugin->get_cf7_integration();
		
		// Should be null when CF7 is not active
		$this->assertNull( $integration );
		$this->assertFalse( $plugin->is_cf7_integration_active() );
	}

	/**
	 * Test CF7 configuration retrieval with fallbacks
	 */
	public function test_cf7_config_retrieval_with_fallbacks(): void {
		// Test that we can retrieve CF7 config values even when CF7 isn't active
		$rate_limit = DefaultConfig::get_option( 'silver_assist_cf7_rate_limit' );
		$rate_window = DefaultConfig::get_option( 'silver_assist_cf7_rate_window' );
		$protection_enabled = DefaultConfig::get_option( 'silver_assist_cf7_protection_enabled' );
		
		$this->assertIsInt( $rate_limit );
		$this->assertIsInt( $rate_window );
		$this->assertIsInt( $protection_enabled );
		
		// Values should be within expected ranges
		$this->assertGreaterThan( 0, $rate_limit );
		$this->assertGreaterThan( 0, $rate_window );
		$this->assertContains( $protection_enabled, [0, 1] );
	}
}