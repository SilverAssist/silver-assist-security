<?php
/**
 * Silver Assist Security Essentials - Contact Form 7 Integration
 *
 * Integrates all security measures with Contact Form 7 forms including
 * rate limiting, IP blacklist, and spam detection.
 *
 * @package SilverAssist\Security\Security
 * @since 1.1.15
 */

namespace SilverAssist\Security\Security;

use SilverAssist\PluginKernel\Interfaces\LoadableInterface;
use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * Contact Form 7 Integration Class
 *
 * Provides comprehensive security integration for Contact Form 7 forms
 *
 * @since 1.1.15
 */
class ContactForm7Integration implements LoadableInterface {

	/**
	 * Name of the hidden field that carries the signed render time of a form
	 *
	 * @since 1.5.4
	 * @var string
	 */
	private const TIMING_FIELD = 'silver_form_ts';

	/**
	 * Singleton instance
	 *
	 * @var self|null
	 */
	private static ?self $instance = null;

	/**
	 * Form Protection instance
	 *
	 * @since 1.1.15
	 * @var FormProtection|null
	 */
	private ?FormProtection $form_protection = null;

	/**
	 * IP Blacklist instance
	 *
	 * @since 1.1.15
	 * @var IPBlacklist|null
	 */
	private ?IPBlacklist $ip_blacklist = null;

	/**
	 * Constructor
	 *
	 * @since 1.1.15
	 */
	public function __construct() {
		$this->init_security_components();
		$this->register_hooks();
	}

	/**
	 * Get singleton instance
	 *
	 * @since 1.5.1
	 * @return self
	 */
	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * LoadableInterface entry point
	 *
	 * A no-op: hook registration already happens unconditionally in the
	 * constructor (see register_hooks(), which self-gates on the CF7
	 * protection setting), triggered the first time instance() constructs
	 * this singleton.
	 *
	 * @since 1.5.1
	 * @return void
	 */
	public function init(): void {
	}

	/**
	 * Get loading priority
	 *
	 * @since 1.5.1
	 * @return int
	 */
	public function get_priority(): int {
		return 10;
	}

	/**
	 * Whether this component should load
	 *
	 * Matches pre-kernel behavior, where Plugin::init_cf7_integration()
	 * only constructed ContactForm7Integration if Contact Form 7 was
	 * active and CF7 protection was enabled.
	 *
	 * @since 1.5.1
	 * @return bool
	 */
	public function should_load(): bool {
		return SecurityHelper::is_contact_form_7_active()
			&& (bool) DefaultConfig::get_option( 'silver_assist_cf7_protection_enabled' );
	}

	/**
	 * Initialize security components
	 *
	 * Self-gates on the same condition as should_load(). Pre-kernel, this
	 * only ran behind Plugin::init_cf7_integration()'s own is_contact_form_7_active()
	 * check, so this method only re-checked the option — now that
	 * instance() can construct this class directly (via the kernel, or any
	 * other caller), it needs to check both conditions itself.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function init_security_components(): void {
		if ( SecurityHelper::is_contact_form_7_active() && DefaultConfig::get_option( 'silver_assist_cf7_protection_enabled' ) ) {
			$this->form_protection = new FormProtection();
			$this->ip_blacklist    = IPBlacklist::get_instance();
		}
	}

	/**
	 * Register WordPress hooks
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function register_hooks(): void {
		if ( ! SecurityHelper::is_contact_form_7_active() || ! DefaultConfig::get_option( 'silver_assist_cf7_protection_enabled' ) ) {
			return;
		}

		// CF7 validation hook.
		\add_filter( 'wpcf7_validate', array( $this, 'validate_cf7_form' ), 10, 2 );

		// Before send mail hook.
		\add_action( 'wpcf7_before_send_mail', array( $this, 'process_cf7_submission' ), 10, 3 );

		// Spam verdict: `wpcf7_spam` is a filter, so the callback must return the verdict it received.
		// Late priority, after the other spam checks (Akismet, disallowed list) have decided.
		\add_filter( 'wpcf7_spam', array( $this, 'handle_cf7_spam' ), 20, 2 );

		// Timing field: when the form was shown, signed, for the minimum submission time check.
		\add_filter( 'wpcf7_form_elements', array( $this, 'inject_timing_field' ), 10, 1 );

		// Honeypot field injection.
		if ( DefaultConfig::get_option( 'silver_assist_cf7_honeypot_enabled' ) ) {
			\add_filter( 'wpcf7_form_elements', array( $this, 'inject_honeypot_field' ), 10, 1 );
		}
	}

	// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required by the wpcf7_validate filter signature.
	/**
	 * Validate CF7 form submission
	 *
	 * @since 1.1.15
	 * @param mixed $result CF7 validation result.
	 * @param mixed $tags Form tags.
	 * @return mixed Modified validation result
	 */
	public function validate_cf7_form( $result, $tags ) {
		// phpcs:enable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$client_ip       = SecurityHelper::get_client_ip();
		$submission_data = $this->get_cf7_submission_data();

		// Create mock contact form for validation.
		$contact_form = $this->get_current_cf7_form();

		if ( ! $this->validate_cf7_submission( $contact_form, $submission_data, $client_ip, $this->read_form_start_time( $submission_data ) ) ) {
			// Contact Form 7 only records an error for a field that exists in the form and ignores the
			// rest, so pass a tag object: a name string that matches no form tag would let the
			// submission through unchanged.
			$result->invalidate(
				$this->get_error_target( $tags ),
				\__( 'Security validation failed. Please try again.', 'silver-assist-security' )
			);
		}

		return $result;
	}

	/**
	 * Main CF7 submission validation method
	 *
	 * @since 1.1.15
	 * @param object      $contact_form CF7 form object.
	 * @param array       $submission_data Form submission data.
	 * @param string|null $client_ip Client IP address (optional).
	 * @param float|null  $form_start_time Form start time for timing validation.
	 * @return bool True if submission is valid, false otherwise
	 */
	public function validate_cf7_submission(
		object $contact_form,
		array $submission_data,
		?string $client_ip = null,
		?float $form_start_time = null
	): bool {
		$client_ip = $client_ip ?? SecurityHelper::get_client_ip();

		// Check IP blacklist first.
		if ( $this->ip_blacklist && $this->ip_blacklist->is_blacklisted( $client_ip ) ) {
			SecurityHelper::log_security_event(
				'CF7_BLOCKED_BLACKLISTED_IP',
				"CF7 submission blocked from blacklisted IP: {$client_ip}",
				array(
					'ip'      => $client_ip,
					'form_id' => $this->get_form_id( $contact_form ),
				)
			);
			return false;
		}

		// Check honeypot field.
		if ( DefaultConfig::get_option( 'silver_assist_cf7_honeypot_enabled' ) ) {
			if ( ! empty( $submission_data['silver_honeypot_field'] ) ) {
				SecurityHelper::log_security_event(
					'CF7_BLOCKED_HONEYPOT',
					"CF7 submission blocked by honeypot: {$client_ip}",
					array(
						'ip'             => $client_ip,
						'honeypot_value' => $submission_data['silver_honeypot_field'],
					)
				);
				return false;
			}
		}

		// Check submission timing if provided.
		if ( null !== $form_start_time ) {
			$submission_time     = microtime( true ) - $form_start_time;
			$min_submission_time = (float) DefaultConfig::get_option( 'silver_assist_cf7_submission_delay' ) / 1000; // Convert ms to seconds.

			if ( $submission_time < $min_submission_time ) {
				SecurityHelper::log_security_event(
					'CF7_BLOCKED_TOO_FAST',
					"CF7 submission too fast ({$submission_time}s): {$client_ip}",
					array(
						'ip'     => $client_ip,
						'timing' => $submission_time,
					)
				);
				return false;
			}
		}

		// Check rate limiting first.
		if ( $this->form_protection && ! $this->form_protection->allow_form_submission( $client_ip ) ) {
			SecurityHelper::log_security_event(
				'CF7_BLOCKED_RATE_LIMIT',
				"CF7 submission rate limited: {$client_ip}",
				array(
					'ip'      => $client_ip,
					'form_id' => $this->get_form_id( $contact_form ),
				)
			);

			// Record violation for potential blacklisting.
			if ( $this->ip_blacklist ) {
				$this->ip_blacklist->record_violation( $client_ip, 'CF7 rate limit exceeded' );
			}

			return false;
		}

		// Check for obsolete browsers.
		$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
		if ( $this->form_protection && FormProtection::is_obsolete_browser( $user_agent ) ) {
			SecurityHelper::log_security_event(
				'CF7_BLOCKED_OBSOLETE_BROWSER',
				"CF7 submission blocked from obsolete browser: {$client_ip}",
				array(
					'ip'         => $client_ip,
					'user_agent' => $user_agent,
				)
			);

			if ( $this->ip_blacklist ) {
				$this->ip_blacklist->record_violation( $client_ip, 'Obsolete browser usage' );
			}

			return false;
		}

		// Check for SQL injection attempts.
		if ( $this->form_protection && FormProtection::has_sql_injection_attempt() ) {
			$query_string = $_SERVER['QUERY_STRING'] ?? '';
			SecurityHelper::log_security_event(
				'CF7_BLOCKED_SQL_INJECTION',
				"CF7 submission blocked SQL injection attempt: {$client_ip}",
				array(
					'ip'           => $client_ip,
					'query_string' => $query_string,
				)
			);

			if ( $this->ip_blacklist ) {
				$this->ip_blacklist->record_violation( $client_ip, 'SQL injection attempt' );
			}

			return false;
		}

		// Check for spam patterns in submission data.
		if ( $this->contains_spam_patterns( $submission_data ) ) {
			SecurityHelper::log_security_event(
				'CF7_BLOCKED_SPAM_PATTERN',
				"CF7 submission blocked spam patterns: {$client_ip}",
				array(
					'ip'                => $client_ip,
					'patterns_detected' => true,
				)
			);

			if ( $this->ip_blacklist ) {
				$this->ip_blacklist->record_violation( $client_ip, 'Spam patterns detected' );
			}

			return false;
		}

		return true;
	}

	// phpcs:disable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed -- Required by the wpcf7_before_send_mail action signature.
	/**
	 * Process CF7 submission before sending
	 *
	 * @since 1.1.15
	 * @param object $contact_form CF7 form object.
	 * @param bool   $abort Whether to abort sending.
	 * @param object $submission CF7 submission object.
	 * @return void
	 */
	public function process_cf7_submission( $contact_form, &$abort, $submission ): void {
		// phpcs:enable Generic.CodeAnalysis.UnusedFunctionParameter.FoundAfterLastUsed
		$client_ip = SecurityHelper::get_client_ip();

		// Log successful submission for monitoring.
		SecurityHelper::log_security_event(
			'CF7_SUBMISSION_SUCCESS',
			"CF7 form submitted successfully from: {$client_ip}",
			array(
				'ip'      => $client_ip,
				'form_id' => $this->get_form_id( $contact_form ),
			)
		);
	}

	/**
	 * Handle CF7 spam detection
	 *
	 * Runs on the `wpcf7_spam` filter, which CF7 applies to every submission with the verdict
	 * so far. A spam verdict counts as a violation of the client IP; the verdict is returned as
	 * received so this filter never turns spam into a pass or the reverse.
	 *
	 * @since 1.1.15
	 * @since 1.5.4 Filter instead of an action: returns the verdict and acts only on spam.
	 * @param mixed       $spam       Verdict so far (true when the submission is spam).
	 * @param object|null $submission CF7 submission.
	 * @return mixed The verdict, unchanged.
	 */
	public function handle_cf7_spam( $spam, $submission = null ) {
		if ( ! $spam ) {
			return $spam;
		}

		$client_ip = SecurityHelper::get_client_ip();

		// Record spam attempt.
		if ( $this->ip_blacklist ) {
			$this->ip_blacklist->record_violation( $client_ip, 'CF7 marked as spam' );
		}

		$contact_form = ( \is_object( $submission ) && \method_exists( $submission, 'get_contact_form' ) ) ? $submission->get_contact_form() : null;

		SecurityHelper::log_security_event(
			'CF7_SPAM_DETECTED',
			"CF7 spam detected from: {$client_ip}",
			array(
				'ip'      => $client_ip,
				'form_id' => $this->get_form_id( $contact_form ),
			)
		);

		return $spam;
	}

	/**
	 * Pick the form tag that carries the security error
	 *
	 * @since 1.5.4
	 * @param mixed $tags CF7 form tags.
	 * @return object|array<string, string> First named tag, or a tag definition when the form has none.
	 */
	private function get_error_target( $tags ) {
		foreach ( (array) $tags as $tag ) {
			if ( \is_object( $tag ) && ! empty( $tag->name ) ) {
				return $tag;
			}
		}

		return array( 'name' => 'security_validation' );
	}

	/**
	 * Read the ID of a CF7 form object
	 *
	 * CF7 6.x removed the public `id` property in favor of `id()`.
	 *
	 * @since 1.5.4
	 * @param mixed $contact_form CF7 form, or the stand-in object this class builds.
	 * @return int|string Form ID, or "unknown".
	 */
	private function get_form_id( $contact_form ) {
		if ( \is_object( $contact_form ) && \method_exists( $contact_form, 'id' ) ) {
			return $contact_form->id();
		}

		return ( \is_object( $contact_form ) && isset( $contact_form->id ) ) ? $contact_form->id : 'unknown';
	}

	/**
	 * Add the signed timing field to a CF7 form
	 *
	 * The value is the time the form was rendered plus an HMAC of it, so a client cannot forge an
	 * older start. It is read back by read_form_start_time() to enforce the minimum submission time.
	 * The token is not single use: a bot that keeps one captured earlier looks slow, so the delay is a
	 * soft signal and the rate limit and the blacklist remain the flood defence.
	 *
	 * @since 1.5.4
	 * @param string $form CF7 form HTML.
	 * @return string Form HTML with the timing field.
	 */
	public function inject_timing_field( string $form ): string {
		$started = sprintf( '%.3f', microtime( true ) );
		$field   = '<input type="hidden" name="' . self::TIMING_FIELD . '" value="' . \esc_attr( $started . '.' . \wp_hash( $started, 'nonce' ) ) . '" />';

		return $form . $field;
	}

	/**
	 * Read and verify the render time posted with a submission
	 *
	 * A missing, malformed, forged or future value yields null, so the minimum time is not enforced:
	 * a cached page or a client that drops the field must never be blocked by it.
	 *
	 * @since 1.5.4
	 * @param array $submission_data Posted data.
	 * @return float|null Render time as a Unix timestamp with milliseconds.
	 */
	private function read_form_start_time( array $submission_data ): ?float {
		$value = $submission_data[ self::TIMING_FIELD ] ?? '';
		if ( ! \is_string( $value ) || 1 !== preg_match( '/^(\d{10}\.\d{3})\.([a-f0-9]{32})$/', \wp_unslash( $value ), $parts ) ) {
			return null;
		}

		if ( ! hash_equals( \wp_hash( $parts[1], 'nonce' ), $parts[2] ) || (float) $parts[1] > microtime( true ) + 1 ) {
			return null;
		}

		// The stamp is rounded to milliseconds, so it can be a hair ahead of now.
		return min( (float) $parts[1], microtime( true ) );
	}

	/**
	 * Inject honeypot field into CF7 form
	 *
	 * @since 1.1.15
	 * @param string $form CF7 form HTML.
	 * @return string Modified form HTML with honeypot
	 */
	public function inject_honeypot_field( string $form ): string {
		$honeypot_field = '<input type="text" name="silver_honeypot_field" value="" style="display: none !important; position: absolute; left: -9999px;" tabindex="-1" autocomplete="off" />';

		// Insert honeypot field before the submit button.
		// CF7 may place class/id attributes before type="submit", so use a regex.
		$pattern = '/<input\b[^>]*type=["\']submit["\']/i';
		if ( preg_match( $pattern, $form, $matches, PREG_OFFSET_CAPTURE ) ) {
			$pos  = $matches[0][1];
			$form = substr_replace( $form, $honeypot_field, $pos, 0 );
		} else {
			$form .= $honeypot_field;
		}

		return $form;
	}

	/**
	 * Get CF7 submission data from current request
	 *
	 * @since 1.1.15
	 * @return array Submission data
	 */
	private function get_cf7_submission_data(): array {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		return $_POST;
	}

	/**
	 * Get current CF7 form object
	 *
	 * @since 1.1.15
	 * @return object CF7 form object
	 */
	private function get_current_cf7_form(): object {
		// In a real implementation, this would get the actual CF7 form
		// For now, return a basic object structure.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing
		$form_id = isset( $_POST['_wpcf7'] ) ? (int) \sanitize_text_field( \wp_unslash( $_POST['_wpcf7'] ) ) : 0;

		return (object) array(
			'id'    => $form_id,
			'title' => 'Contact Form',
		);
	}

	/**
	 * Check submission data for spam patterns
	 *
	 * @since 1.1.15
	 * @param array $submission_data Form submission data.
	 * @return bool True if spam patterns detected
	 */
	private function contains_spam_patterns( array $submission_data ): bool {
		$spam_patterns = array(
			// Pharmaceutical spam - only obvious spam phrases.
			'cheap viagra',
			'buy viagra',
			'cialis online',
			'pharmacy online',

			// Casino/gambling spam - only obvious promotional phrases.
			'casino winner',
			'you won $',
			'jackpot winner',
			'lottery winner',

			// Finance spam - only obvious promotional phrases.
			'easy money',
			'quick profit',
			'get rich quick',
			'make money fast',
			'guaranteed profit',
			'risk-free investment',

			// Generic spam indicators - only obvious promotional phrases.
			'click here now',
			'act now!',
			'limited time offer',
			'special discount',
			'100% guaranteed',
			'no risk involved',

			// Suspicious promotional patterns.
			'cash prize',
		);

		/**
		 * Filters the spam phrases that block a Contact Form 7 submission.
		 *
		 * Phrases are matched case-insensitively anywhere in the submitted text. Keep
		 * them specific: a family describing income ("we make $3,000 a month") is a
		 * real enquiry, which is why bare "make $", "earn $" and "win $" are not listed.
		 *
		 * @since 1.5.4
		 * @param string[] $spam_patterns Spam phrases.
		 */
		$spam_patterns = \apply_filters( 'silver_assist_security_cf7_spam_patterns', $spam_patterns );

		// Combine message and name fields only (skip email field to avoid false positives).
		$text_fields = array();
		foreach ( $submission_data as $key => $value ) {
			// Skip email fields and the plugin's own fields; array values (checkboxes) are joined.
			if ( ! in_array( $key, array( 'your-email', 'email', 'silver_honeypot_field', self::TIMING_FIELD ), true ) ) {
				$text_fields[] = is_array( $value ) ? implode( ' ', array_map( 'strval', $value ) ) : (string) $value;
			}
		}
		// Keep the text as typed: the capitals check below needs the original case.
		$raw_text  = implode( ' ', $text_fields );
		$text_data = strtolower( $raw_text );

		// Skip empty submissions.
		if ( strlen( trim( $text_data ) ) < 5 ) {
			return false;
		}

		// Check for spam patterns.
		foreach ( $spam_patterns as $pattern ) {
			if ( stripos( $text_data, $pattern ) !== false ) {
				SecurityHelper::log_security_event(
					'SPAM_PATTERN_DETECTED',
					'Spam pattern detected in CF7 submission',
					array(
						'pattern'            => $pattern,
						'ip'                 => SecurityHelper::get_client_ip(),
						'submission_preview' => substr( $text_data, 0, 100 ),
					)
				);
				return true;
			}
		}

		// Check for excessive capitalization (common in spam) - more lenient threshold.
		$uppercase_ratio = 0;
		$total_chars     = strlen( $raw_text );
		if ( $total_chars > 30 ) { // Only check longer messages.
			$uppercase_result = preg_replace( '/[^A-Z]/', '', $raw_text );
			$uppercase_chars  = strlen( $uppercase_result ? $uppercase_result : '' );
			$uppercase_ratio  = $uppercase_chars / $total_chars;
		}

		// Higher threshold and longer text requirement to avoid false positives.
		if ( $uppercase_ratio > 0.7 && $total_chars > 50 ) {
			SecurityHelper::log_security_event(
				'EXCESSIVE_CAPS_DETECTED',
				'Excessive capitalization detected in CF7 submission',
				array(
					'uppercase_ratio' => $uppercase_ratio,
					'ip'              => SecurityHelper::get_client_ip(),
				)
			);
			return true;
		}

		return false;
	}
}
