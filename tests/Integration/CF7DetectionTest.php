<?php
/**
 * Silver Assist Security Essentials - CF7 Detection Integration Tests
 *
 * Tests Contact Form 7 plugin detection logic including version checks,
 * class existence, and the removal of deprecated function_exists check.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.1.15
 * @author Silver Assist
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Core\SecurityHelper;
use WP_UnitTestCase;

/**
 * CF7 Detection integration tests
 *
 * @since 1.1.15
 */
class CF7DetectionTest extends WP_UnitTestCase {

	/**
	 * Test CF7 detected when WPCF7 class and version exist
	 *
	 * Note: Since constants/classes defined in prior tests persist in process,
	 * this test verifies the detection returns true when mocks are present.
	 */
	public function test_cf7_detected_when_class_exists(): void {
		// WPCF7 class and WPCF7_VERSION constant are typically defined
		// in the test bootstrap (from ContactForm7AjaxHandlerTest setUp).
		// If they exist, detection should return true.
		if ( class_exists( 'WPCF7' ) && defined( 'WPCF7_VERSION' ) ) {
			$this->assertTrue(
				SecurityHelper::is_contact_form_7_active(),
				'CF7 should be detected when WPCF7 class and version constant exist'
			);
		} else {
			// If WPCF7 hasn't been mocked yet, detection should return false
			$this->assertFalse(
				SecurityHelper::is_contact_form_7_active(),
				'CF7 should not be detected without WPCF7 class'
			);
		}
	}

	/**
	 * Test that detection method exists and is callable
	 */
	public function test_cf7_detection_method_is_callable(): void {
		$this->assertTrue(
			is_callable( [ SecurityHelper::class, 'is_contact_form_7_active' ] ),
			'is_contact_form_7_active should be a callable static method'
		);
	}

	/**
	 * Test CF7 detection does not require deprecated function_exists check
	 *
	 * The fix for CF7 v6.x removed the function_exists('wpcf7_get_contact_form_by_id')
	 * check. This regression test ensures the detection only checks class + version.
	 */
	public function test_cf7_detection_does_not_require_function_exists(): void {
		// Read the source code and verify it doesn't contain function_exists check
		$source_file = dirname( __DIR__, 2 ) . '/src/Core/SecurityHelper.php';
		$this->assertFileExists( $source_file );

		$source_code = file_get_contents( $source_file );

		$this->assertStringNotContainsString(
			'wpcf7_get_contact_form_by_id',
			$source_code,
			'SecurityHelper should NOT reference deprecated wpcf7_get_contact_form_by_id function'
		);
	}

	/**
	 * Test CF7 detection returns boolean type
	 */
	public function test_cf7_detection_returns_boolean(): void {
		$result = SecurityHelper::is_contact_form_7_active();

		$this->assertIsBool( $result, 'is_contact_form_7_active should return a boolean' );
	}
}
