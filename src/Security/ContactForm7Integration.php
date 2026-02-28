<?php
/**
 * Silver Assist Security Essentials - Contact Form 7 Integration
 *
 * Integrates all security measures with Contact Form 7 forms including
 * rate limiting, IP blacklist, Under Attack mode, and spam detection.
 *
 * @package SilverAssist\Security\Security
 * @since 1.1.15
 */

namespace SilverAssist\Security\Security;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * Contact Form 7 Integration Class
 *
 * Provides comprehensive security integration for Contact Form 7 forms
 *
 * @since 1.1.15
 */
class ContactForm7Integration {

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
	 * Under Attack Mode instance
	 *
	 * @since 1.1.15
	 * @var UnderAttackMode|null
	 */
	private ?UnderAttackMode $under_attack = null;

	/**
	 * Constructor
	 *
	 * @since 1.1.15
	 */
	public function __construct() {
		$this->init_security_components();
		$this->init_hooks();
	}

	/**
	 * Initialize security components
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function init_security_components(): void {
		if ( DefaultConfig::get_option( 'silver_assist_cf7_protection_enabled' ) ) {
			$this->form_protection = new FormProtection();
			$this->ip_blacklist    = IPBlacklist::getInstance();
			$this->under_attack    = UnderAttackMode::getInstance();
		}
	}

	/**
	 * Initialize WordPress hooks
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function init_hooks(): void {
		if ( ! DefaultConfig::get_option( 'silver_assist_cf7_protection_enabled' ) ) {
			return;
		}

		// CF7 validation hook
		\add_filter( 'wpcf7_validate', array( $this, 'validate_cf7_form' ), 10, 2 );

		// Before send mail hook
		\add_action( 'wpcf7_before_send_mail', array( $this, 'process_cf7_submission' ), 10, 3 );

		// Spam detection hook
		\add_action( 'wpcf7_spam', array( $this, 'handle_cf7_spam' ), 10, 1 );

		// Honeypot field injection
		if ( DefaultConfig::get_option( 'silver_assist_cf7_honeypot_enabled' ) ) {
			\add_filter( 'wpcf7_form_elements', array( $this, 'inject_honeypot_field' ), 10, 1 );
		}

		// Under Attack mode CAPTCHA injection into CF7 forms
		\add_filter( 'wpcf7_form_elements', array( $this, 'inject_captcha_field' ), 20, 1 );

		// AJAX endpoint for generating fresh CAPTCHAs (public — forms are on the frontend)
		\add_action( 'wp_ajax_silver_assist_generate_captcha', array( $this, 'ajax_generate_captcha' ) );
		\add_action( 'wp_ajax_nopriv_silver_assist_generate_captcha', array( $this, 'ajax_generate_captcha' ) );

		// Enqueue frontend CAPTCHA script when Under Attack mode is active
		\add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_captcha_assets' ) );
	}

	/**
	 * Validate CF7 form submission
	 *
	 * @since 1.1.15
	 * @param mixed $result CF7 validation result
	 * @param mixed $tags Form tags
	 * @return mixed Modified validation result
	 */
	public function validate_cf7_form( $result, $tags ) {
		$client_ip       = SecurityHelper::get_client_ip();
		$submission_data = $this->get_cf7_submission_data();

		// Create mock contact form for validation
		$contact_form = $this->get_current_cf7_form();

		if ( ! $this->validate_cf7_submission( $contact_form, $submission_data, $client_ip ) ) {
			// Add validation error
			$result->invalidate(
				'security_validation',
				\__( 'Security validation failed. Please try again.', 'silver-assist-security' )
			);
		}

		return $result;
	}

	/**
	 * Main CF7 submission validation method
	 *
	 * @since 1.1.15
	 * @param object      $contact_form CF7 form object
	 * @param array       $submission_data Form submission data
	 * @param string|null $client_ip Client IP address (optional)
	 * @param float|null  $form_start_time Form start time for timing validation
	 * @return bool True if submission is valid, false otherwise
	 */
	public function validate_cf7_submission(
		object $contact_form,
		array $submission_data,
		?string $client_ip = null,
		?float $form_start_time = null
	): bool {
		$client_ip = $client_ip ?? SecurityHelper::get_client_ip();

		// Check IP blacklist first
		if ( $this->ip_blacklist && $this->ip_blacklist->is_blacklisted( $client_ip ) ) {
			SecurityHelper::log_security_event(
				'CF7_BLOCKED_BLACKLISTED_IP',
				"CF7 submission blocked from blacklisted IP: {$client_ip}",
				array(
					'ip'      => $client_ip,
					'form_id' => $contact_form->id ?? 'unknown',
				)
			);
			return false;
		}

		// Check Under Attack mode
		if ( $this->under_attack && $this->under_attack->is_under_attack() ) {
			if ( ! $this->validate_under_attack_captcha( $submission_data ) ) {
				SecurityHelper::log_security_event(
					'CF7_BLOCKED_UNDER_ATTACK',
					"CF7 submission blocked in Under Attack mode: {$client_ip}",
					array(
						'ip'      => $client_ip,
						'form_id' => $contact_form->id ?? 'unknown',
					)
				);
				return false;
			}
		}

		// Check honeypot field
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

		// Check submission timing if provided
		if ( $form_start_time !== null ) {
			$submission_time     = microtime( true ) - $form_start_time;
			$min_submission_time = (float) DefaultConfig::get_option( 'silver_assist_cf7_submission_delay' ) / 1000; // Convert ms to seconds

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

		// Check rate limiting first
		if ( $this->form_protection && ! $this->form_protection->allow_form_submission( $client_ip ) ) {
			SecurityHelper::log_security_event(
				'CF7_BLOCKED_RATE_LIMIT',
				"CF7 submission rate limited: {$client_ip}",
				array(
					'ip'      => $client_ip,
					'form_id' => $contact_form->id ?? 'unknown',
				)
			);

			// Record violation for potential blacklisting
			if ( $this->ip_blacklist ) {
				$this->ip_blacklist->record_violation( $client_ip, 'CF7 rate limit exceeded' );
			}

			// Record attack for Under Attack mode
			if ( $this->under_attack ) {
				$this->under_attack->record_attack( $client_ip );
			}

			return false;
		}

		// Check for obsolete browsers
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

			if ( $this->under_attack ) {
				$this->under_attack->record_attack( $client_ip );
			}

			return false;
		}

		// Check for SQL injection attempts
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

			if ( $this->under_attack ) {
				$this->under_attack->record_attack( $client_ip );
			}

			return false;
		}

		// Check for spam patterns in submission data
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

			if ( $this->under_attack ) {
				$this->under_attack->record_attack( $client_ip );
			}

			return false;
		}

		return true;
	}

	/**
	 * Process CF7 submission before sending
	 *
	 * @since 1.1.15
	 * @param object $contact_form CF7 form object
	 * @param bool   $abort Whether to abort sending
	 * @param object $submission CF7 submission object
	 * @return void
	 */
	public function process_cf7_submission( $contact_form, &$abort, $submission ): void {
		$client_ip = SecurityHelper::get_client_ip();

		// Log successful submission for monitoring
		SecurityHelper::log_security_event(
			'CF7_SUBMISSION_SUCCESS',
			"CF7 form submitted successfully from: {$client_ip}",
			array(
				'ip'      => $client_ip,
				'form_id' => $contact_form->id ?? 'unknown',
			)
		);
	}

	/**
	 * Handle CF7 spam detection
	 *
	 * @since 1.1.15
	 * @param object $contact_form CF7 form object
	 * @return void
	 */
	public function handle_cf7_spam( $contact_form ): void {
		$client_ip = SecurityHelper::get_client_ip();

		// Record spam attempt
		if ( $this->ip_blacklist ) {
			$this->ip_blacklist->record_violation( $client_ip, 'CF7 marked as spam' );
		}

		if ( $this->under_attack ) {
			$this->under_attack->record_attack( $client_ip );
		}

		SecurityHelper::log_security_event(
			'CF7_SPAM_DETECTED',
			"CF7 spam detected from: {$client_ip}",
			array(
				'ip'      => $client_ip,
				'form_id' => $contact_form->id ?? 'unknown',
			)
		);
	}

	/**
	 * Inject honeypot field into CF7 form
	 *
	 * @since 1.1.15
	 * @param string $form CF7 form HTML
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
	 * Validate Under Attack mode CAPTCHA
	 *
	 * @since 1.1.15
	 * @param array $submission_data Form submission data
	 * @return bool True if CAPTCHA is valid or not required
	 */
	private function validate_under_attack_captcha( array $submission_data ): bool {
		if ( ! $this->under_attack || ! $this->under_attack->is_under_attack() ) {
			return true; // No CAPTCHA required
		}

		$captcha_answer = $submission_data['silver_captcha_answer'] ?? '';
		$captcha_token  = $submission_data['silver_captcha_token'] ?? '';

		// Use strict comparison instead of empty() since answer can be "0".
		if ( '' === $captcha_answer || '' === $captcha_token ) {
			return false; // CAPTCHA required but not provided
		}

		return $this->under_attack->validate_captcha( $captcha_answer, $captcha_token );
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
		// For now, return a basic object structure
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
	 * @param array $submission_data Form submission data
	 * @return bool True if spam patterns detected
	 */
	private function contains_spam_patterns( array $submission_data ): bool {
		$spam_patterns = array(
			// Pharmaceutical spam - only obvious spam phrases
			'cheap viagra',
			'buy viagra',
			'cialis online',
			'pharmacy online',

			// Casino/gambling spam - only obvious promotional phrases
			'casino winner',
			'you won $',
			'jackpot winner',
			'lottery winner',

			// Finance spam - only obvious promotional phrases
			'easy money',
			'quick profit',
			'get rich quick',
			'make money fast',
			'guaranteed profit',
			'risk-free investment',

			// Generic spam indicators - only obvious promotional phrases
			'click here now',
			'act now!',
			'limited time offer',
			'special discount',
			'100% guaranteed',
			'no risk involved',

			// Suspicious promotional patterns
			'make $',
			'earn $',
			'win $',
			'cash prize',
		);

		// Combine message and name fields only (skip email field to avoid false positives)
		$text_fields = array();
		foreach ( $submission_data as $key => $value ) {
			// Skip email fields and honeypot fields
			if ( ! in_array( $key, array( 'your-email', 'email', 'silver_honeypot_field', 'silver_captcha_answer', 'silver_captcha_token' ), true ) ) {
				$text_fields[] = strtolower( (string) $value );
			}
		}
		$text_data = implode( ' ', $text_fields );

		// Skip empty submissions
		if ( strlen( trim( $text_data ) ) < 5 ) {
			return false;
		}

		// Check for spam patterns
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

		// Check for excessive capitalization (common in spam) - more lenient threshold
		$uppercase_ratio = 0;
		$total_chars     = strlen( (string) $text_data );
		if ( $total_chars > 30 ) { // Only check longer messages
			$uppercase_result = preg_replace( '/[^A-Z]/', '', (string) $text_data );
			$uppercase_chars  = strlen( $uppercase_result ? $uppercase_result : '' );
			$uppercase_ratio  = $uppercase_chars / $total_chars;
		}

		// Higher threshold and longer text requirement to avoid false positives
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

	/**
	 * Inject CAPTCHA fields into CF7 forms when Under Attack mode is active.
	 *
	 * Uses the same wpcf7_form_elements filter pattern as inject_honeypot_field(),
	 * but only adds the CAPTCHA markup when Under Attack mode is active.
	 *
	 * @since 1.1.15
	 * @param string $form The CF7 form HTML.
	 * @return string Modified form HTML with CAPTCHA widget injected.
	 */
	public function inject_captcha_field( string $form ): string {
		if ( ! $this->under_attack->is_under_attack() ) {
			return $form;
		}

		$captcha = $this->under_attack->generate_captcha();

		$captcha_html = SecurityHelper::render_template( 'captcha-field.php', array(
			'question'     => $captcha['question'],
			'token'        => $captcha['token'],
			'show_refresh' => true,
			'input_class'  => '',
		) );

		// Insert CAPTCHA just before the submit button.
		// CF7 may place class/id attributes before type="submit", so use a regex
		// to match any <input …type="submit" variant.
		$pattern = '/<input\b[^>]*type=["\']submit["\']/i';
		if ( preg_match( $pattern, $form, $matches, PREG_OFFSET_CAPTURE ) ) {
			$pos  = $matches[0][1];
			$form = substr_replace( $form, $captcha_html, $pos, 0 );
		} else {
			$form .= $captcha_html;
		}

		return $form;
	}

	/**
	 * AJAX handler: generate a fresh CAPTCHA question + token.
	 *
	 * Registered on both wp_ajax_ and wp_ajax_nopriv_ because CF7 forms are
	 * rendered on the public frontend.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function ajax_generate_captcha(): void {
		// Verify nonce to prevent abuse.
		if ( ! isset( $_POST['nonce'] ) || ! \wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['nonce'] ) ), 'silver_assist_captcha_nonce' ) ) {
			\wp_send_json_error( array( 'message' => 'Invalid nonce' ), 403 );
		}

		if ( ! $this->under_attack->is_under_attack() ) {
			\wp_send_json_error( array( 'message' => 'Not in Under Attack mode' ), 400 );
		}

		$captcha = $this->under_attack->generate_captcha();

		\wp_send_json_success(
			array(
				'question' => $captcha['question'] . ' = ',
				'token'    => $captcha['token'],
			)
		);
	}

	/**
	 * Enqueue lightweight frontend assets for the CAPTCHA widget.
	 *
	 * Only loads when Under Attack mode is active.
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function enqueue_captcha_assets(): void {
		if ( ! $this->under_attack->is_under_attack() ) {
			return;
		}

		\wp_enqueue_style(
			'silver-assist-variables',
			SILVER_ASSIST_SECURITY_URL . 'assets/css/variables.css',
			array(),
			SILVER_ASSIST_SECURITY_VERSION
		);

		\wp_enqueue_style(
			'silver-assist-captcha',
			SILVER_ASSIST_SECURITY_URL . 'assets/css/captcha.css',
			array( 'silver-assist-variables' ),
			SILVER_ASSIST_SECURITY_VERSION
		);

		\wp_enqueue_script(
			'silver-assist-captcha',
			SILVER_ASSIST_SECURITY_URL . 'assets/js/captcha.js',
			array( 'jquery' ),
			SILVER_ASSIST_SECURITY_VERSION,
			true
		);

		\wp_localize_script(
			'silver-assist-captcha',
			'silverAssistCaptcha',
			array(
				'ajaxUrl' => \admin_url( 'admin-ajax.php' ),
				'nonce'   => \wp_create_nonce( 'silver_assist_captcha_nonce' ),
			)
		);
	}
}
