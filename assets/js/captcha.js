/**
 * Silver Assist Security — CAPTCHA widget (frontend).
 *
 * Loaded only when Under Attack mode is active.
 * Handles the refresh button so users can request a new question.
 *
 * @since 1.1.15
 */
(($) => {
	'use strict';

	$(() => {
		const { ajaxUrl, nonce } = silverAssistCaptcha;

		$('.silver-assist-captcha-refresh').on('click', function (e) {
			e.preventDefault();

			const $button = $(this);
			const $wrap = $button.closest('.silver-assist-captcha-wrap');

			if (!$wrap.length) {
				return;
			}

			const $question = $wrap.find('.silver-assist-captcha-text');
			const $token = $wrap.find('input[name="silver_captcha_token"]');
			const $answer = $wrap.find('input[name="silver_captcha_answer"]');

			if (!$question.length || !$token.length) {
				return;
			}

			// Disable button while loading.
			$button.prop('disabled', true).addClass('silver-assist-captcha-loading');

			$.post(ajaxUrl, {
				action: 'silver_assist_generate_captcha',
				nonce,
			})
				.done((response) => {
					if (response.success) {
						$question.text(response.data.question);
						$token.val(response.data.token);
						$answer.val('').trigger('focus');
					}
				})
				.always(() => {
					$button.prop('disabled', false).removeClass('silver-assist-captcha-loading');
				});
		});
	});
})(jQuery);
