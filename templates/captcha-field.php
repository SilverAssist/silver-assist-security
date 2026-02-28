<?php
/**
 * CAPTCHA field template for Under Attack mode.
 *
 * Shared by both the CF7 contact-form integration and the wp-login form.
 *
 * Expected variables (passed via extract):
 *
 * @var string $question     The math expression (e.g. "8 + 3").
 * @var string $token        The CAPTCHA verification token.
 * @var bool   $show_refresh Whether to render the refresh button (AJAX forms only).
 * @var string $input_class  Extra CSS classes for the answer input (e.g. "input" on login).
 *
 * @package SilverAssistSecurity
 * @since   1.1.15
 */

defined( 'ABSPATH' ) || exit;
?>
<div class="silver-assist-captcha-wrap">
	<div class="silver-assist-captcha-inner">
		<label class="silver-assist-captcha-label" for="silver_captcha_answer">
			<?php echo esc_html__( 'Security Check', 'silver-assist-security' ); ?>
		</label>
		<div class="silver-assist-captcha-question">
			<span class="silver-assist-captcha-text"><?php echo esc_html( $question ); ?> = </span>
			<input
				type="number"
				name="silver_captcha_answer"
				id="silver_captcha_answer"
				class="silver-assist-captcha-answer <?php echo esc_attr( $input_class ); ?>"
				required
				placeholder="<?php echo esc_attr__( 'Your answer', 'silver-assist-security' ); ?>"
			/>
			<?php if ( ! empty( $show_refresh ) ) : ?>
				<button type="button" class="silver-assist-captcha-refresh" title="<?php echo esc_attr__( 'Get a new question', 'silver-assist-security' ); ?>" aria-label="<?php echo esc_attr__( 'Get a new question', 'silver-assist-security' ); ?>">&#x21bb;</button>
			<?php endif; ?>
		</div>
		<input type="hidden" name="silver_captcha_token" value="<?php echo esc_attr( $token ); ?>" />
	</div>
</div>
