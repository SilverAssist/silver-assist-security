<?php
/**
 * Contact Form 7 end-to-end submit tests
 *
 * Submits a real Contact Form 7 form through CF7's own REST endpoint
 * (`/contact-form-7/v1/contact-forms/{id}/feedback`), so the whole pipeline runs: CF7 builds its
 * submission, calls `wpcf7_validate`, and the plugin's hooks decide. `FormSubmissionBehaviorTest`
 * drives the filter with a stand-in; this class proves the contract with the real plugin (#154, G3).
 *
 * Contact Form 7 is not loaded by the test bootstrap, because its presence changes what the rest of
 * the suite sees (admin tabs, block registration). Each test therefore runs in a separate PHP
 * process and loads it itself.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Security\ContactForm7Integration;
use SilverAssist\Security\Security\FormProtection;
use SilverAssist\Security\Security\IPBlacklist;
use WP_REST_Request;
use WP_UnitTestCase;

/**
 * Real Contact Form 7 submissions against the plugin's protection
 */
class ContactForm7SubmitTest extends WP_UnitTestCase {

	/**
	 * Visitor IP used by the test
	 *
	 * @var string
	 */
	private string $ip = '198.51.100.77';

	/**
	 * Real form created for the test
	 *
	 * @var int
	 */
	private int $form_id = 0;

	/**
	 * Load Contact Form 7, create a form and register the plugin's hooks
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();

		$main_file = WP_PLUGIN_DIR . '/contact-form-7/wp-contact-form-7.php';
		if ( ! \file_exists( $main_file ) ) {
			$message = 'Contact Form 7 is not installed: run scripts/install-cf7-for-tests.sh';
			if ( false !== \getenv( 'CI' ) && '' !== \getenv( 'CI' ) ) {
				$this->fail( $message . ' (CI must not skip the Contact Form 7 tests).' );
			}
			$this->markTestSkipped( $message . '.' );
		}

		require_once $main_file;
		\wpcf7();
		\wpcf7_init();

		$_SERVER['REMOTE_ADDR']     = $this->ip;
		$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15';
		$_SERVER['QUERY_STRING']    = '';

		\update_option( 'silver_assist_cf7_protection_enabled', 1 );
		\update_option( 'silver_assist_cf7_honeypot_enabled', 1 );
		\delete_transient( 'form_rate_' . \md5( $this->ip ) );

		$form = \WPCF7_ContactForm::get_template();
		$form->set_title( 'Tour request' );
		$form->set_properties(
			array(
				'form' => '<label>Name [text* your-name]</label><label>Email [email* your-email]</label><label>Message [textarea* your-message]</label>[submit "Send"]',
				'mail' => array(
					'active'             => true,
					'subject'            => 'Tour request',
					'sender'             => 'Site <wordpress@example.org>',
					'recipient'          => 'team@example.org',
					'body'               => '[your-name] [your-email] [your-message]',
					'additional_headers' => '',
					'attachments'        => '',
					'use_html'           => false,
					'exclude_blank'      => false,
				),
			)
		);
		$this->form_id = (int) $form->save();
		$this->assertGreaterThan( 0, $this->form_id, 'the CF7 form was created' );

		// The plugin registers its CF7 hooks once Contact Form 7 is active; they are the only thing
		// between a submission and the mail, so the tests below would be meaningless without them.
		$this->assertNotFalse( \has_filter( 'wpcf7_validate', array( ContactForm7Integration::instance(), 'validate_cf7_form' ) ), 'the plugin guards CF7 submissions' );
	}

	/**
	 * Submit the form through CF7's REST feedback endpoint
	 *
	 * @param array<string, string> $fields Posted fields.
	 * @return array<string, mixed> CF7's JSON response.
	 */
	private function submit( array $fields ): array {
		$fields = \array_merge(
			array(
				'_wpcf7'          => (string) $this->form_id,
				'_wpcf7_unit_tag' => 'wpcf7-f' . $this->form_id . '-o1',
			),
			$fields
		);

		// CF7 reads the posted data from $_POST, the same as in a browser multipart request.
		$_POST   = $fields;
		$request = new WP_REST_Request( 'POST', '/contact-form-7/v1/contact-forms/' . $this->form_id . '/feedback' );
		$request->set_header( 'Content-Type', 'multipart/form-data; boundary=x' );
		$request->set_body_params( $fields );

		// Each browser request is a new PHP request, where CF7 has no earlier submission.
		$instance = new \ReflectionProperty( \WPCF7_Submission::class, 'instance' );
		$instance->setAccessible( true );
		$instance->setValue( null, null );

		$response = \rest_do_request( $request );
		$this->assertSame( 200, $response->get_status(), 'CF7 answers its own JSON for a handled submission' );

		return (array) $response->get_data();
	}

	/**
	 * A normal enquiry reaches the mail step
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 * @return void
	 */
	public function test_legitimate_submission_is_sent(): void {
		$data = $this->submit(
			array(
				'your-name'    => 'Maria Lopez',
				'your-email'   => 'maria@example.com',
				'your-message' => 'Looking for memory care options near Denver for my mother.',
			)
		);

		$this->assertSame( 'mail_sent', $data['status'], (string) \wp_json_encode( $data ) );
		$this->assertSame( 0, IPBlacklist::get_instance()->get_violation_count( $this->ip ), 'a legitimate visitor is not recorded as a violator' );
	}

	/**
	 * A bot that fills the hidden field is stopped before any mail
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 * @return void
	 */
	public function test_honeypot_submission_is_blocked(): void {
		$data = $this->submit(
			array(
				'your-name'             => 'Maria Lopez',
				'your-email'            => 'maria@example.com',
				'your-message'          => 'Looking for memory care options near Denver.',
				'silver_honeypot_field' => 'http://spam.example',
			)
		);

		$this->assertSame( 'validation_failed', $data['status'] );
	}

	/**
	 * Requests within seconds from one IP are cut off after the configured limit
	 *
	 * This is the case the CF7 protection exists for.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 * @return void
	 */
	public function test_rapid_fire_from_one_ip_is_rate_limited(): void {
		$limit = ( new FormProtection() )->get_rate_limit();
		$post  = array(
			'your-name'    => 'Maria Lopez',
			'your-email'   => 'maria@example.com',
			'your-message' => 'Looking for memory care options near Denver.',
		);

		for ( $i = 1; $i <= $limit; $i++ ) {
			$this->assertSame( 'mail_sent', $this->submit( $post )['status'], "submit {$i} is within the limit" );
		}

		$this->assertSame( 'validation_failed', $this->submit( $post )['status'], 'the next one is a flood' );

		// A different visitor is not affected by that IP's flood.
		$_SERVER['REMOTE_ADDR'] = '198.51.100.78';
		$this->assertSame( 'mail_sent', $this->submit( $post )['status'], 'another IP still gets through' );

		// The flood is counted as a violation of the offending IP.
		$this->assertGreaterThan( 0, IPBlacklist::get_instance()->get_violation_count( $this->ip ), 'the rate limit hit is recorded against the flooding IP' );
		$this->assertSame( 0, IPBlacklist::get_instance()->get_violation_count( '198.51.100.78' ), 'the other IP has no violation' );
	}

	/**
	 * A SQL injection payload in a field is blocked
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 * @return void
	 */
	public function test_sql_injection_payload_is_blocked(): void {
		$data = $this->submit(
			array(
				'your-name'    => 'Maria Lopez',
				'your-email'   => 'maria@example.com',
				'your-message' => "x' UNION SELECT user_pass FROM wp_users",
			)
		);

		$this->assertSame( 'validation_failed', $data['status'] );
	}

	/**
	 * A submission that CF7 or another filter marks as spam stays spam and counts as a violation
	 *
	 * `wpcf7_spam` is a filter: the plugin must hand the verdict on untouched.
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 * @return void
	 */
	public function test_spam_verdict_is_kept_and_recorded(): void {
		\add_filter( 'wpcf7_spam', '__return_true', 5 );

		$data = $this->submit(
			array(
				'your-name'    => 'Maria Lopez',
				'your-email'   => 'maria@example.com',
				'your-message' => 'Looking for memory care options near Denver.',
			)
		);

		$this->assertSame( 'spam', $data['status'] );
		$this->assertSame( 1, IPBlacklist::get_instance()->get_violation_count( $this->ip ), 'one spam verdict is one violation' );
	}

	/**
	 * A blacklisted IP cannot submit
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 * @return void
	 */
	public function test_blacklisted_ip_is_blocked(): void {
		IPBlacklist::get_instance()->add_to_blacklist( $this->ip, 'test', 3600 );

		$data = $this->submit(
			array(
				'your-name'    => 'Maria Lopez',
				'your-email'   => 'maria@example.com',
				'your-message' => 'Looking for memory care options near Denver.',
			)
		);

		$this->assertSame( 'validation_failed', $data['status'] );
	}
}
