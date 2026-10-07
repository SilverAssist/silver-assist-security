<?php
/**
 * Admin path validation tests
 *
 * A custom admin path must not shadow a core route, an existing page or a rewrite rule, and a rejected
 * path must be reported instead of silently replaced (#153).
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Admin\Settings\SettingsHandler;
use SilverAssist\Security\Admin\Settings\SettingsSaver;
use SilverAssist\Security\Core\PathValidator;
use WP_UnitTestCase;

/**
 * PathValidator reserved slugs and collisions, saver and handler reporting
 */
class AdminPathValidationTest extends WP_UnitTestCase {

	/**
	 * Core routes a custom admin path would hijack
	 *
	 * @return array<string, array{string}>
	 */
	public function reserved_slugs(): array {
		$slugs = array(
			'wp-json',
			'feed',
			'rss',
			'rss2',
			'atom',
			'comments',
			'wp-cron',
			'xmlrpc',
			'sitemap',
			'wp-sitemap',
			'robots',
			'wp-signup',
			'wp-activate',
			'wp-trackback',
			'wp-comments-post',
			'trackback',
			'embed',
			'wp-load',
			'wp-config',
			'WP-JSON',
		);

		return array_combine( $slugs, array_map( static fn( $slug ) => array( $slug ), $slugs ) );
	}

	/**
	 * A reserved slug is rejected, whatever its case
	 *
	 * @dataProvider reserved_slugs
	 * @param string $slug Slug.
	 * @return void
	 */
	public function test_reserved_core_slugs_are_rejected( string $slug ): void {
		$result = PathValidator::validate_admin_path( $slug );

		$this->assertFalse( $result['is_valid'], "'{$slug}' shadows a core route." );
		$this->assertSame( 'reserved', $result['error_type'] );
		$this->assertNotSame( '', $result['error_message'] );
	}

	/**
	 * The runtime check (is_forbidden_path) also refuses a reserved slug stored by an older version
	 *
	 * @return void
	 */
	public function test_runtime_check_refuses_reserved_slug(): void {
		$this->assertTrue( PathValidator::is_forbidden_path( 'wp-json' ) );
		$this->assertFalse( PathValidator::is_forbidden_path( 'my-private-door' ) );
	}

	/**
	 * The REST prefix and the rewrite bases of this site are reserved too
	 *
	 * @return void
	 */
	public function test_site_route_bases_are_rejected(): void {
		$this->set_permalink_structure( '/%postname%/' );

		$filter = static fn() => 'api-v1';
		\add_filter( 'rest_url_prefix', $filter );
		$result = PathValidator::validate_admin_path( 'api-v1' );
		\remove_filter( 'rest_url_prefix', $filter );
		$this->assertFalse( $result['is_valid'] );
		$this->assertSame( 'reserved', $result['error_type'] );

		$result = PathValidator::validate_admin_path( 'author' );
		$this->assertFalse( $result['is_valid'], 'The author base is a route.' );
		$result = PathValidator::validate_admin_path( 'search' );
		$this->assertFalse( $result['is_valid'], 'The search base is a route.' );
	}

	/**
	 * A published page with that slug is a collision
	 *
	 * @return void
	 */
	public function test_existing_page_slug_is_rejected(): void {
		$this->set_permalink_structure( '/%postname%/' );
		self::factory()->post->create(
			array(
				'post_type'   => 'page',
				'post_status' => 'publish',
				'post_name'   => 'our-team',
			)
		);

		$result = PathValidator::validate_admin_path( 'our-team' );

		$this->assertFalse( $result['is_valid'] );
		$this->assertSame( 'collision', $result['error_type'] );
	}

	/**
	 * A draft, a post and a public custom post type with that slug collide as well
	 *
	 * @return void
	 */
	public function test_post_and_custom_post_type_slugs_are_rejected(): void {
		$this->set_permalink_structure( '/%postname%/' );
		\register_post_type( 'faq', array( 'public' => true ) );

		self::factory()->post->create(
			array(
				'post_status' => 'publish',
				'post_name'   => 'news-flash',
			)
		);
		self::factory()->post->create(
			array(
				'post_status' => 'draft',
				'post_name'   => 'coming-soon-page',
			)
		);
		self::factory()->post->create(
			array(
				'post_type'   => 'faq',
				'post_status' => 'publish',
				'post_name'   => 'help-center',
			)
		);

		foreach ( array( 'news-flash', 'coming-soon-page', 'help-center' ) as $slug ) {
			$result = PathValidator::validate_admin_path( $slug );
			$this->assertFalse( $result['is_valid'], "'{$slug}' is an existing entry." );
			$this->assertSame( 'collision', $result['error_type'] );
		}

		\unregister_post_type( 'faq' );
	}

	/**
	 * A specific rewrite rule that matches the path is a collision, the catch-all page rule is not
	 *
	 * @return void
	 */
	public function test_rewrite_rule_collision_is_rejected(): void {
		$this->set_permalink_structure( '/%postname%/' );
		\add_rewrite_rule( '^member-area/?$', 'index.php?member_area=1', 'top' );
		\flush_rewrite_rules( false );

		$result = PathValidator::validate_admin_path( 'member-area' );
		$this->assertFalse( $result['is_valid'] );
		$this->assertSame( 'collision', $result['error_type'] );

		$result = PathValidator::validate_admin_path( 'unused-private-door' );
		$this->assertTrue( $result['is_valid'], 'The catch-all rules must not reject every path.' );
	}

	/**
	 * Paths that clash with nothing stay valid
	 *
	 * @return void
	 */
	public function test_unused_path_is_valid(): void {
		$this->set_permalink_structure( '/%postname%/' );

		$this->assertTrue( PathValidator::validate_admin_path( 'my-private-door' )['is_valid'] );
		$this->assertTrue( PathValidator::validate_admin_path( 'silver-admin' )['is_valid'] );
	}

	/**
	 * The saver refuses a bad path, keeps the stored one and reports why
	 *
	 * @return void
	 */
	public function test_saver_rejects_instead_of_resetting(): void {
		\update_option( 'silver_assist_admin_hide_path', 'my-private-door' );

		foreach ( array( 'wp-json', 'feed', 'login', 'ab', '', '!!!' ) as $bad ) {
			$result = ( new SettingsSaver() )->save(
				array( 'silver_assist_admin_hide_path' => $bad ),
				'admin_hide'
			);

			$this->assertSame( 'my-private-door', \get_option( 'silver_assist_admin_hide_path' ), "'{$bad}' must not overwrite the stored path." );
			$this->assertArrayHasKey( 'silver_assist_admin_hide_path', $result->errors, "'{$bad}' must be reported." );
			$this->assertArrayNotHasKey( 'silver_assist_admin_hide_path', $result->saved );
			$this->assertSame( array(), $result->adjusted );
		}
	}

	/**
	 * The saver refuses the slug of an existing page
	 *
	 * @return void
	 */
	public function test_saver_rejects_existing_page_slug(): void {
		$this->set_permalink_structure( '/%postname%/' );
		self::factory()->post->create(
			array(
				'post_type'   => 'page',
				'post_status' => 'publish',
				'post_name'   => 'contact-us',
			)
		);

		$result = ( new SettingsSaver() )->save(
			array( 'silver_assist_admin_hide_path' => 'contact-us' ),
			'admin_hide'
		);

		$this->assertArrayHasKey( 'silver_assist_admin_hide_path', $result->errors );
		$this->assertNotSame( 'contact-us', \get_option( 'silver_assist_admin_hide_path' ) );
	}

	/**
	 * A valid path is saved; a rejected path keeps the stored one and never enables Admin Hide
	 *
	 * @return void
	 */
	public function test_valid_path_saves_and_a_rejected_path_never_enables_admin_hide(): void {
		$saver  = new SettingsSaver();
		$result = $saver->save( array( 'silver_assist_admin_hide_path' => 'My Private Door' ), 'admin_hide' );
		$this->assertSame( 'my-private-door', \get_option( 'silver_assist_admin_hide_path' ) );
		$this->assertSame( array(), $result->errors );

		$result = $saver->save(
			array(
				'silver_assist_admin_hide_enabled'      => '1',
				'silver_assist_admin_hide_path'         => 'wp-json',
				SettingsSaver::ADMIN_HIDE_CONFIRM_FIELD => '1',
			),
			'admin_hide'
		);
		$this->assertSame( 0, (int) \get_option( 'silver_assist_admin_hide_enabled' ), 'A rejected path never turns Admin Hide on.' );
		$this->assertSame( 'my-private-door', \get_option( 'silver_assist_admin_hide_path' ) );
		$this->assertArrayHasKey( 'silver_assist_admin_hide_path', $result->errors );
		$this->assertArrayHasKey( 'silver_assist_admin_hide_enabled', $result->errors );
	}

	/**
	 * The form handler shows an error notice for a rejected path, not a plain success notice
	 *
	 * @return void
	 */
	public function test_handler_shows_error_notice_for_rejected_path(): void {
		\wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		\update_option( 'silver_assist_admin_hide_path', 'my-private-door' );

		// phpcs:disable WordPress.Security.NonceVerification.Missing
		$_POST = array(
			'save_silver_assist_security'   => '1',
			'_wpnonce'                      => \wp_create_nonce( 'silver_assist_security_settings' ),
			'settings_section'              => 'admin_hide',
			'silver_assist_admin_hide_path' => 'wp-json',
		);
		// phpcs:enable

		\remove_all_actions( 'admin_notices' );
		( new SettingsHandler() )->save_security_settings();
		\ob_start();
		\do_action( 'admin_notices' );
		$html  = (string) \ob_get_clean();
		$_POST = array();

		$this->assertStringContainsString( 'notice-error', $html );
		$this->assertStringContainsString( 'wp-json', $html );
		$this->assertStringNotContainsString( 'saved successfully', $html );
		$this->assertSame( 'my-private-door', \get_option( 'silver_assist_admin_hide_path' ) );
	}
}
