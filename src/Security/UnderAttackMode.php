<?php
/**
 * Silver Assist Security Essentials - Under Attack Mode
 *
 * Provides emergency CAPTCHA protection during coordinated attacks.
 * Automatically activates when attack thresholds are exceeded.
 *
 * @package SilverAssist\Security\Security
 * @since 1.1.15
 * @author Silver Assist
 * @version 1.1.15
 */

namespace SilverAssist\Security\Security;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * Under Attack Mode class
 *
 * Manages emergency CAPTCHA protection during coordinated attacks
 *
 * @since 1.1.15
 */
class UnderAttackMode {

	/**
	 * Constructor
	 *
	 * @since 1.1.15
	 */
	public function __construct() {
		// Initialize if needed
	}

	/**
	 * Check if site is currently under attack
	 *
	 * @since 1.1.15
	 * @return bool True if Under Attack mode is active
	 */
	public function is_under_attack(): bool {
		$attack_key = 'under_attack_mode';
		return \get_transient( $attack_key ) !== false;
	}

	/**
	 * Record an attack attempt
	 *
	 * Increments attack counter and activates Under Attack mode if threshold reached.
	 *
	 * @since 1.1.15
	 * @param string $ip Optional IP address of attacker
	 * @return void
	 */
	public function record_attack( string $ip = '' ): void {
		$window    = (int) DefaultConfig::get_option( 'silver_assist_under_attack_window' );
		$threshold = (int) DefaultConfig::get_option( 'silver_assist_under_attack_threshold' );

		// Use current minute as counter key for time-based grouping
		$counter_key   = 'attack_counter_' . gmdate( 'Y-m-d-H-i' );
		$current_count = (int) \get_transient( $counter_key );
		$new_count     = $current_count + 1;

		\set_transient( $counter_key, $new_count, $window );

		SecurityHelper::log_security_event(
			'ATTACK_RECORDED',
			'Attack attempt recorded',
			array(
				'ip'           => $ip ? $ip : SecurityHelper::get_client_ip(),
				'attack_count' => $new_count,
				'threshold'    => $threshold,
			)
		);

		// Activate Under Attack mode if threshold exceeded
		if ( $new_count >= $threshold ) {
			$this->activate_under_attack_mode( "Automatic: {$new_count} attacks detected" );
		}
	}

	/**
	 * Manually activate Under Attack mode
	 *
	 * @since 1.1.15
	 * @param string $reason Reason for activation
	 * @param int    $duration Optional custom duration (seconds)
	 * @return void
	 */
	public function activate_under_attack_mode( string $reason, int $duration = 0 ): void {
		if ( $duration === 0 ) {
			$duration = (int) DefaultConfig::get_option( 'silver_assist_under_attack_duration' );
		}

		$attack_key  = 'under_attack_mode';
		$attack_data = array(
			'reason'       => $reason,
			'activated_at' => time(),
			'duration'     => $duration,
			'activated_by' => 'system',
		);

		\set_transient( $attack_key, $attack_data, $duration );

		SecurityHelper::log_security_event(
			'UNDER_ATTACK_ACTIVATED',
			"Under Attack mode activated: {$reason}",
			array(
				'reason'   => $reason,
				'duration' => $duration,
			)
		);
	}

	/**
	 * Deactivate Under Attack mode
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function deactivate_under_attack_mode(): void {
		$attack_key = 'under_attack_mode';
		\delete_transient( $attack_key );

		SecurityHelper::log_security_event(
			'UNDER_ATTACK_DEACTIVATED',
			'Under Attack mode manually deactivated',
			array()
		);
	}

	/**
	 * Check if form submission is allowed
	 *
	 * During Under Attack mode, requires valid CAPTCHA.
	 *
	 * @since 1.1.15
	 * @param array $form_data Form submission data
	 * @return bool True if submission allowed, false otherwise
	 */
	public function allow_form_submission( array $form_data ): bool {
		// If not under attack, allow submission
		if ( ! $this->is_under_attack() ) {
			return true;
		}

		// Under attack - require CAPTCHA validation
		$captcha_answer = $form_data['silver_captcha_answer'] ?? '';
		$captcha_token  = $form_data['silver_captcha_token'] ?? '';

		// Use strict comparison instead of empty() since answer can be "0".
		if ( '' === $captcha_answer || '' === $captcha_token ) {
			SecurityHelper::log_security_event(
				'CAPTCHA_MISSING',
				'Form submission blocked - missing CAPTCHA',
				array(
					'ip' => SecurityHelper::get_client_ip(),
				)
			);
			return false;
		}

		return $this->validate_captcha( $captcha_answer, $captcha_token );
	}

	/**
	 * Generate CAPTCHA challenge
	 *
	 * @since 1.1.15
	 * @param string $difficulty CAPTCHA difficulty level
	 * @return array CAPTCHA data with question, answer, and token
	 */
	public function generate_captcha( string $difficulty = '' ): array {
		if ( empty( $difficulty ) ) {
			$difficulty = DefaultConfig::get_option( 'silver_assist_captcha_difficulty' );
		}

		$captcha_data = $this->create_math_captcha( $difficulty );
		$token        = $this->generate_captcha_token( $captcha_data['answer'] );

		return array(
			'question'   => $captcha_data['question'],
			'answer'     => $captcha_data['answer'],
			'token'      => $token,
			'difficulty' => $difficulty,
		);
	}

	/**
	 * Validate CAPTCHA response
	 *
	 * @since 1.1.15
	 * @param string $user_answer User's CAPTCHA answer
	 * @param string $token CAPTCHA token
	 * @return bool True if valid, false otherwise
	 */
	public function validate_captcha( string $user_answer, string $token ): bool {
		$stored_answer = $this->get_captcha_answer_from_token( $token );

		if ( $stored_answer === false ) {
			SecurityHelper::log_security_event(
				'CAPTCHA_INVALID_TOKEN',
				'CAPTCHA validation failed - invalid token',
				array(
					'ip'    => SecurityHelper::get_client_ip(),
					'token' => substr( $token, 0, 8 ) . '...',
				)
			);
			return false;
		}

		$is_valid = ( trim( $user_answer ) === trim( $stored_answer ) );

		if ( $is_valid ) {
			// Clean up used token
			$this->cleanup_captcha_token( $token );

			SecurityHelper::log_security_event(
				'CAPTCHA_VALIDATED',
				'CAPTCHA validation successful',
				array(
					'ip' => SecurityHelper::get_client_ip(),
				)
			);
		} else {
			SecurityHelper::log_security_event(
				'CAPTCHA_FAILED',
				'CAPTCHA validation failed - wrong answer',
				array(
					'ip'          => SecurityHelper::get_client_ip(),
					'user_answer' => $user_answer,
				)
			);
		}

		return $is_valid;
	}

	/**
	 * Get current attack count for monitoring
	 *
	 * @since 1.1.15
	 * @return int Current attack count in window
	 */
	public function get_current_attack_count(): int {
		$counter_key = 'attack_counter_' . gmdate( 'Y-m-d-H-i' );
		return (int) \get_transient( $counter_key );
	}

	/**
	 * Get attack statistics
	 *
	 * @since 1.1.15
	 * @return array Attack statistics and mode status
	 */
	public function get_attack_statistics(): array {
		$current_attacks = $this->get_current_attack_count();
		$is_under_attack = $this->is_under_attack();
		$attack_data     = \get_transient( 'under_attack_mode' );

		return array(
			'is_under_attack'  => $is_under_attack,
			'current_attacks'  => $current_attacks,
			'total_attacks'    => $current_attacks, // Simplified for now
			'attack_threshold' => (int) DefaultConfig::get_option( 'silver_assist_under_attack_threshold' ),
			'mode_data'        => $attack_data ? $attack_data : null,
		);
	}

	/**
	 * Create mathematical CAPTCHA based on difficulty
	 *
	 * @since 1.1.15
	 * @param string $difficulty Difficulty level (easy, medium, hard)
	 * @return array CAPTCHA question and answer
	 */
	private function create_math_captcha( string $difficulty ): array {
		switch ( $difficulty ) {
			case 'easy':
				$num1      = \wp_rand( 1, 10 );
				$num2      = \wp_rand( 1, 10 );
				$operation = '+';
				$answer    = $num1 + $num2;
				break;

			case 'hard':
				$num1      = \wp_rand( 10, 50 );
				$num2      = \wp_rand( 2, 12 );
				$operation = \wp_rand( 0, 1 ) ? '*' : '+';
				$answer    = ( $operation === '*' ) ? $num1 * $num2 : $num1 + $num2;
				break;

			case 'medium':
			default:
				$num1       = \wp_rand( 5, 20 );
				$num2       = \wp_rand( 1, 15 );
				$operations = array( '+', '-' );
				$operation  = $operations[ \wp_rand( 0, 1 ) ];
				$answer     = ( $operation === '+' ) ? $num1 + $num2 : $num1 - $num2;
				break;
		}

		return array(
			'question' => "What is {$num1} {$operation} {$num2}?",
			'answer'   => (string) $answer,
		);
	}

	/**
	 * Generate secure token for CAPTCHA
	 *
	 * @since 1.1.15
	 * @param string $answer CAPTCHA answer
	 * @return string Secure token
	 */
	private function generate_captcha_token( string $answer ): string {
		$token       = \wp_generate_password( 32, false );
		$captcha_key = "captcha_token_{$token}";

		// Store answer with token for 10 minutes
		\set_transient( $captcha_key, $answer, 600 );

		return $token;
	}

	/**
	 * Retrieve CAPTCHA answer from token
	 *
	 * @since 1.1.15
	 * @param string $token CAPTCHA token
	 * @return string|false CAPTCHA answer or false if invalid
	 */
	private function get_captcha_answer_from_token( string $token ) {
		$captcha_key = "captcha_token_{$token}";
		return \get_transient( $captcha_key );
	}

	/**
	 * Clean up used CAPTCHA token
	 *
	 * @since 1.1.15
	 * @param string $token CAPTCHA token to remove
	 * @return void
	 */
	private function cleanup_captcha_token( string $token ): void {
		$captcha_key = "captcha_token_{$token}";
		\delete_transient( $captcha_key );
	}
}
