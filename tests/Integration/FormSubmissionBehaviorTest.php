<?php
/**
 * Form Submission Behavior Tests
 *
 * A real Contact Form 7 visitor submits ordinary text and must get through; a
 * bot must not. These tests drive the same `wpcf7_validate` filter CF7 calls,
 * with realistic senior-care enquiries, instead of checking that hooks exist
 * (#124 audit of FormProtection and the CF7 integration).
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Security\ContactForm7Integration;
use SilverAssist\Security\Security\FormProtection;
use WP_UnitTestCase;

/**
 * Stand-in for CF7's WPCF7_Validation object
 */
class FakeCf7Validation {

	/**
	 * Invalidated field names
	 *
	 * @var array<int, string>
	 */
	public array $invalid = array();

	/**
	 * Record an invalidated field
	 *
	 * @param string $name    Field name.
	 * @param string $message Message.
	 * @return void
	 */
	public function invalidate( $name, $message ): void {
		unset( $message );
		$this->invalid[] = (string) $name;
	}

	/**
	 * Whether the submission passed
	 *
	 * @return bool
	 */
	public function is_valid(): bool {
		return array() === $this->invalid;
	}
}

/**
 * Behavior tests for CF7 and form protection
 */
class FormSubmissionBehaviorTest extends WP_UnitTestCase {

	/**
	 * Server and request globals changed by a test
	 *
	 * @var array<string, mixed>
	 */
	private array $server_backup = array();

	/**
	 * Integration under test (registers its hooks once per test)
	 *
	 * @var ContactForm7Integration|null
	 */
	private ?ContactForm7Integration $integration = null;

	/**
	 * Prepare a clean visitor with a modern browser
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();
		if ( ! class_exists( 'WPCF7' ) ) {
			eval( 'class WPCF7 {}' ); // phpcs:ignore Squiz.PHP.Eval.Discouraged -- Test-only CF7 class stub.
		}
		$this->server_backup               = $_SERVER;
		$_SERVER['REMOTE_ADDR']            = '198.51.100.' . wp_rand( 2, 250 );
		$_SERVER['HTTP_USER_AGENT']        = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15';
		$_SERVER['QUERY_STRING']           = '';
		$_POST                             = array();
		delete_transient( 'form_rate_' . md5( $_SERVER['REMOTE_ADDR'] ) );
	}

	/**
	 * Restore globals
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		$_SERVER = $this->server_backup;
		$_POST   = array();
		wp_cache_flush();
		parent::tearDown();
	}

	/**
	 * Submit a form through the filter CF7 itself calls
	 *
	 * @param array<string, string> $post Posted fields.
	 * @return FakeCf7Validation
	 */
	private function submit( array $post ): FakeCf7Validation {
		$this->integration ??= new ContactForm7Integration();
		$_POST  = $post;
		$result = new FakeCf7Validation();
		return apply_filters( 'wpcf7_validate', $result, array() );
	}

	/**
	 * An ordinary visitor's enquiry goes through
	 *
	 * @return void
	 */
	public function test_real_visitor_submit_succeeds(): void {
		$result = $this->submit(
			array(
				'your-name'    => 'Maria Lopez',
				'your-email'   => 'maria@example.com',
				'your-message' => 'Looking for memory care options near Denver for my mother.',
				'_wpcf7'       => '12',
			)
		);

		$this->assertTrue( $result->is_valid(), 'a normal enquiry must not be flagged' );
	}

	/**
	 * A bot that fills the honeypot is blocked
	 *
	 * @return void
	 */
	public function test_bot_filling_honeypot_is_blocked(): void {
		$result = $this->submit(
			array(
				'your-name'             => 'Maria Lopez',
				'your-message'          => 'Hello there, interested in a tour.',
				'silver_honeypot_field' => 'http://spam.example',
			)
		);

		$this->assertFalse( $result->is_valid() );
	}

	/**
	 * A bot that sends no browser identity is blocked
	 *
	 * @return void
	 */
	public function test_bot_without_browser_identity_is_blocked(): void {
		$_SERVER['HTTP_USER_AGENT'] = '';

		$result = $this->submit( array( 'your-message' => 'Hello there, interested in a tour.' ) );

		$this->assertFalse( $result->is_valid() );
	}

	/**
	 * A bot flooding the form is rate limited after the configured number of submits
	 *
	 * @return void
	 */
	public function test_flooding_is_rate_limited(): void {
		$limit = ( new FormProtection() )->get_rate_limit();

		for ( $i = 0; $i < $limit; $i++ ) {
			$this->assertTrue( $this->submit( array( 'your-message' => 'Hello there, a question.' ) )->is_valid(), "submit {$i} is within the limit" );
		}

		$this->assertFalse( $this->submit( array( 'your-message' => 'Hello there, a question.' ) )->is_valid() );
	}

	/**
	 * A classic SQL injection payload is blocked
	 *
	 * @return void
	 */
	public function test_sql_injection_payload_is_blocked(): void {
		$result = $this->submit( array( 'your-message' => "x' UNION SELECT user_pass FROM wp_users" ) );

		$this->assertFalse( $result->is_valid() );
	}

	/**
	 * Realistic enquiries that merely contain SQL-looking or money-looking text
	 *
	 * A family describing income, or a person typing a double hyphen, is not an
	 * attack or spam. These were rejected (and counted toward an IP blacklist)
	 * by bare `--`, `make $`, `earn $` and `win $` patterns.
	 *
	 * @return array<string, array{string}>
	 */
	public static function legitimate_messages(): array {
		return array(
			'double hyphen as a dash'  => array( 'We need care soon -- my father fell last week.' ),
			'income statement make $'  => array( 'My mother and I make $3,200 a month, can she afford assisted living?' ),
			'income statement earn $'  => array( 'She can earn $1,500 a month from her pension, is that enough?' ),
			'cost question win $'      => array( 'Is the twin $2,400 suite still available next month?' ),
			'sql comment-like slashes' => array( 'Visiting hours 9/* on weekdays? Please confirm.' ),
		);
	}

	/**
	 * Ordinary text is not mistaken for an attack or spam
	 *
	 * @dataProvider legitimate_messages
	 * @param string $message Visitor message.
	 * @return void
	 */
	public function test_legitimate_message_is_not_blocked( string $message ): void {
		$result = $this->submit(
			array(
				'your-name'    => 'Sam Rivera',
				'your-message' => $message,
			)
		);

		$this->assertTrue( $result->is_valid(), $message );
	}

	/**
	 * Multi-value fields (CF7 checkboxes) post arrays and must not break validation
	 *
	 * Casting an array to string raised a warning ("Array to string conversion")
	 * and made the submission text the word "Array".
	 *
	 * @return void
	 */
	public function test_checkbox_array_values_are_accepted(): void {
		$result = $this->submit(
			array(
				'your-name'   => 'Sam Rivera',
				'care-needs'  => array( 'Memory care', 'Respite stays' ),
				'your-message' => 'Please call me this week about a tour.',
			)
		);

		$this->assertTrue( $result->is_valid() );
	}

	/**
	 * Obvious spam phrases are still blocked after the false positives were removed
	 *
	 * @return void
	 */
	public function test_spam_phrase_is_still_blocked(): void {
		$result = $this->submit( array( 'your-message' => 'Make money fast with our offer, cheap viagra included.' ) );

		$this->assertFalse( $result->is_valid() );
	}

	/**
	 * Sites can tune the spam phrases without editing the plugin
	 *
	 * @return void
	 */
	public function test_spam_patterns_are_filterable(): void {
		add_filter(
			'silver_assist_security_cf7_spam_patterns',
			static function ( array $patterns ): array {
				$patterns[] = 'crypto airdrop';
				return $patterns;
			}
		);

		$this->assertFalse( $this->submit( array( 'your-message' => 'Claim your crypto airdrop today please.' ) )->is_valid() );
	}

	/**
	 * Shouting in all capitals is detected on the text as typed
	 *
	 * The check lowercased the text before counting capitals, so the ratio was
	 * always zero and the rule never fired.
	 *
	 * @return void
	 */
	public function test_excessive_capitals_are_detected(): void {
		$result = $this->submit( array( 'your-message' => 'BUY OUR AMAZING PRODUCT NOW BEFORE THE OFFER ENDS FOR EVERYONE TODAY' ) );

		$this->assertFalse( $result->is_valid() );
	}

	/**
	 * The honeypot is invisible to people and does not break a normal form
	 *
	 * @return void
	 */
	public function test_honeypot_is_injected_hidden_before_submit(): void {
		$this->integration = new ContactForm7Integration();

		$form = apply_filters( 'wpcf7_form_elements', '<input type="text" name="your-name" /><input class="wpcf7-submit" type="submit" value="Send" />' );

		$this->assertMatchesRegularExpression( '/silver_honeypot_field.*tabindex="-1".*type="submit"/s', $form );
		$this->assertStringContainsString( 'display: none', $form );
	}
}
