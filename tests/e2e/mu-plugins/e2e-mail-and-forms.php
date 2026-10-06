<?php
/**
 * Plugin Name: E2E mail capture and public form endpoint
 * Description: Test environment only. Stores the latest outgoing email in an option so specs can follow reset and confirmation links, and registers a public admin-post.php action like a front-end form would.
 *
 * @package SilverAssist\Security\Tests
 */

// Capture instead of sending: wp-env has no mail server, and the spec reads the link from the message.
add_filter(
	'pre_wp_mail',
	static function ( $return, $atts ) {
		update_option(
			'e2e_last_mail',
			wp_json_encode(
				array(
					'to'      => $atts['to'],
					'subject' => $atts['subject'],
					'message' => $atts['message'],
				)
			),
			false
		);
		return true;
	},
	10,
	2
);

// A public form handler, as used by front-end forms posting to wp-admin/admin-post.php.
add_action(
	'admin_post_nopriv_e2e_public_form',
	static function () {
		wp_die( 'e2e-public-form-ok', '', array( 'response' => 200 ) );
	}
);
