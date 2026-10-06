<?php
/**
 * Settings forms, posted the way the browser posts them
 *
 * Renders every settings tab, parses the HTML and, for each form with a submit button, builds the POST
 * from the form's own named inputs (the way a browser would), changes every field and runs it through
 * SettingsHandler::save_security_settings(). A form whose Save button persists nothing (a missing gate
 * field, a nonce under the wrong name, no section) fails here, which hand-built POST arrays hide (#159).
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use DOMElement;
use SilverAssist\Security\Admin\Renderer\SettingsRenderer;
use SilverAssist\Security\Admin\Settings\SettingsHandler;
use SilverAssist\Security\Admin\Settings\SettingsRegistry;
use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use SilverAssist\Security\Tests\Helpers\RenderedSettingsForms;
use WP_UnitTestCase;

/**
 * Generic test of every form on the settings screen
 */
class SettingsFormsTest extends WP_UnitTestCase {

	use RenderedSettingsForms;

	/**
	 * Fields every settings form carries that are not options
	 *
	 * @var string[]
	 */
	private const NON_OPTION_FIELDS = array( 'save_silver_assist_security', 'settings_section', '_wpnonce', '_wp_http_referer', 'submit' );

	/**
	 * Sentinel for "option not stored"
	 *
	 * @var string
	 */
	private const MISSING = '__missing__';

	/**
	 * Administrator id
	 *
	 * @var int
	 */
	private int $admin_id;

	/**
	 * Settings handler
	 *
	 * @var SettingsHandler
	 */
	private SettingsHandler $handler;

	/**
	 * Prepare an administrator, the optional integrations the tabs depend on and a clean POST
	 *
	 * @return void
	 */
	protected function setUp(): void {
		parent::setUp();

		$this->require_full_settings_screen();

		$this->admin_id = $this->factory()->user->create( array( 'role' => 'administrator' ) );
		\wp_set_current_user( $this->admin_id );
		$this->handler = new SettingsHandler();
		$_POST         = array();
	}

	/**
	 * Clean POST state
	 *
	 * @return void
	 */
	protected function tearDown(): void {
		$_POST = array();
		parent::tearDown();
	}

	/**
	 * A valid value different from the current one
	 *
	 * @param array<string, mixed> $declaration Registry declaration.
	 * @param DOMElement           $element     The form's input.
	 * @param array<string, string> $fields      Current form fields.
	 * @return string|null Null means "unchecked" (omit the field).
	 */
	private function different_value( array $declaration, DOMElement $element, array $fields ): ?string {
		$name    = $declaration['option'];
		$current = $fields[ $name ] ?? null;

		switch ( $declaration['type'] ) {
			case SettingsRegistry::TYPE_BOOL:
				return null === $current ? '1' : null;

			case SettingsRegistry::TYPE_INT:
				$min = (int) $element->getAttribute( 'min' );
				$max = (int) $element->getAttribute( 'max' );
				foreach ( array( $min, $max, (int) \round( ( $min + $max ) / 2 ) ) as $candidate ) {
					if ( (string) $candidate !== (string) $current ) {
						return (string) $candidate;
					}
				}
				return (string) $min;

			case SettingsRegistry::TYPE_URL:
				return 'https://example.com/changed-logo.png';

			case SettingsRegistry::TYPE_HEX_COLOR:
				return '#123abc';

			case SettingsRegistry::TYPE_ADMIN_PATH:
				return 'my-private-door';

			case SettingsRegistry::TYPE_USER_ID:
				return (string) $this->factory()->user->create( array( 'role' => 'subscriber' ) );
		}

		$this->fail( 'Unhandled option type ' . $declaration['type'] );
	}

	/**
	 * Snapshot of every registered option as stored (not as defaulted)
	 *
	 * @return array<string, mixed>
	 */
	private function stored_options(): array {
		$stored = array();
		foreach ( \array_keys( SettingsRegistry::all() ) as $option ) {
			$stored[ $option ] = \get_option( $option, self::MISSING );
		}

		return $stored;
	}

	/**
	 * Post fields through the handler as the given user
	 *
	 * @param array<string, string> $fields Fields.
	 * @return void
	 */
	private function post( array $fields ): void {
		$_POST = $fields;
		$this->handler->save_security_settings();
	}

	/**
	 * The screen has one form per section, and every section of the registry has a form
	 *
	 * @return void
	 */
	public function test_every_registry_section_has_exactly_one_form(): void {
		$sections = array();
		foreach ( $this->submit_forms() as $form ) {
			$fields     = $this->form_fields( $form );
			$sections[] = $fields['settings_section'] ?? '(none)';
		}

		$this->assertSame( \count( $sections ), \count( \array_unique( $sections ) ), 'Two forms share a section: ' . \implode( ', ', $sections ) );
		$expected = SettingsRegistry::sections();
		\sort( $expected );
		\sort( $sections );
		$this->assertSame( $expected, $sections, 'Every registry section needs a rendered form, and every form a registry section.' );
	}

	/**
	 * Every form with a submit button carries the gate field, a known section and the _wpnonce field
	 *
	 * @return void
	 */
	public function test_every_form_carries_gate_section_and_nonce(): void {
		$forms = $this->submit_forms();
		$this->assertNotEmpty( $forms, 'No form with a submit button was rendered.' );

		foreach ( $forms as $form ) {
			$id     = $form->getAttribute( 'id' );
			$fields = $this->form_fields( $form );

			$this->assertSame( '1', $fields['save_silver_assist_security'] ?? null, "Form #{$id} lacks the hidden gate field." );
			$this->assertTrue( SettingsRegistry::has_section( $fields['settings_section'] ?? '' ), "Form #{$id} has no valid settings_section." );
			$this->assertNotEmpty( $fields['_wpnonce'] ?? '', "Form #{$id} lacks the _wpnonce field the handler verifies." );
			$this->assertArrayNotHasKey( 'silver_assist_security_nonce', $fields, "Form #{$id} still prints the old nonce field name." );
		}
	}

	/**
	 * No two elements on the screen share an id, so a submit button can be addressed
	 *
	 * @return void
	 */
	public function test_ids_on_the_screen_are_unique(): void {
		$renderer = new SettingsRenderer( GraphQLConfigManager::get_instance() );
		\ob_start();
		$renderer->render_all_tabs();
		$html = (string) \ob_get_clean();

		\preg_match_all( '/\sid="([^"]+)"/', $html, $matches );
		$counts     = \array_count_values( $matches[1] );
		$duplicates = \array_keys( \array_filter( $counts, static fn( int $count ): bool => $count > 1 ) );

		$this->assertSame( array(), $duplicates, 'Duplicate ids: ' . \implode( ', ', $duplicates ) );
	}

	/**
	 * Posting each form's own fields, every field changes its option and nothing else is touched
	 *
	 * @return void
	 */
	public function test_each_form_persists_every_field_and_only_its_own_section(): void {
		$forms = $this->submit_forms();
		$this->assertNotEmpty( $forms );

		foreach ( $forms as $form ) {
			$id      = $form->getAttribute( 'id' );
			$fields  = $this->form_fields( $form );
			$section = $fields['settings_section'] ?? '';
			$options = SettingsRegistry::for_section( $section );
			$before  = $this->stored_options();
			$expect  = array();

			// Every named input is a registered option of this form's section, or one of the form's own plumbing fields.
			foreach ( \array_keys( $fields ) as $name ) {
				if ( \in_array( $name, self::NON_OPTION_FIELDS, true ) ) {
					continue;
				}
				$this->assertArrayHasKey( $name, $options, "Form #{$id} has the input {$name}, which is not an option of section {$section}." );
			}

			$post = $fields;
			foreach ( $options as $option => $declaration ) {
				if ( ! $declaration['ui'] ) {
					continue;
				}
				$element = $this->field_element( $form, $option );
				$this->assertNotNull( $element, "Form #{$id} is missing the field for {$option}." );

				$new = $this->different_value( $declaration, $element, $fields );
				if ( null === $new ) {
					unset( $post[ $option ] );
					$expect[ $option ] = 0;
				} else {
					$post[ $option ]   = $new;
					$expect[ $option ] = SettingsRegistry::TYPE_INT === $declaration['type'] || SettingsRegistry::TYPE_BOOL === $declaration['type'] || SettingsRegistry::TYPE_USER_ID === $declaration['type'] ? (int) $new : $new;
				}
			}

			// Another section's option riding along in the same POST must not be written.
			$foreign_option          = 'rest_api' === $section ? 'silver_assist_login_attempts' : 'silver_assist_rest_rate_limit_requests';
			$post[ $foreign_option ] = '77';

			$this->post( $post );

			foreach ( $expect as $option => $value ) {
				$this->assertSame( $value, \is_int( $value ) ? (int) \get_option( $option ) : \get_option( $option ), "Form #{$id}: {$option} was not saved." );
			}

			$after = $this->stored_options();
			foreach ( $before as $option => $value ) {
				if ( ! isset( $options[ $option ] ) ) {
					$this->assertSame( $value, $after[ $option ], "Form #{$id} (section {$section}) changed {$option}, an option of another section." );
				}
			}
		}
	}

	/**
	 * A non-administrator posting a real form writes nothing
	 *
	 * @return void
	 */
	public function test_non_admin_post_writes_nothing(): void {
		$forms  = $this->submit_forms();
		$before = $this->stored_options();

		\wp_set_current_user( $this->factory()->user->create( array( 'role' => 'subscriber' ) ) );
		foreach ( $forms as $form ) {
			$fields                                = $this->form_fields( $form );
			$fields['silver_assist_login_attempts'] = '3';
			$fields['silver_assist_ip_blacklist_threshold'] = '9';
			$this->post( $fields );
		}

		$this->assertSame( $before, $this->stored_options() );
	}

	/**
	 * A bad nonce dies and writes nothing
	 *
	 * @return void
	 */
	public function test_bad_nonce_writes_nothing(): void {
		$before = $this->stored_options();

		foreach ( $this->submit_forms() as $form ) {
			$fields                                 = $this->form_fields( $form );
			$fields['_wpnonce']                     = 'not-a-nonce';
			$fields['silver_assist_login_attempts'] = '3';
			try {
				$this->post( $fields );
				$this->fail( 'A bad nonce must stop the request.' );
			} catch ( \WPDieException $e ) {
				$this->assertStringContainsString( 'Security check failed', $e->getMessage() );
			}
		}

		$this->assertSame( $before, $this->stored_options() );
	}

	/**
	 * The old nonce field name (silver_assist_security_nonce) no longer authorizes a save
	 *
	 * @return void
	 */
	public function test_post_without_gate_field_writes_nothing(): void {
		$before = $this->stored_options();

		$this->post(
			array(
				'settings_section'             => 'login',
				'_wpnonce'                     => \wp_create_nonce( 'silver_assist_security_settings' ),
				'silver_assist_login_attempts' => '3',
			)
		);

		$this->assertSame( $before, $this->stored_options() );
	}

	/**
	 * A missing or unknown section is rejected with no writes
	 *
	 * @return void
	 */
	public function test_missing_or_unknown_section_writes_nothing(): void {
		foreach ( array( null, '', 'nope', 'all' ) as $section ) {
			$before = $this->stored_options();
			$fields = array(
				'save_silver_assist_security'  => '1',
				'_wpnonce'                     => \wp_create_nonce( 'silver_assist_security_settings' ),
				'silver_assist_login_attempts' => '3',
				'silver_assist_bot_protection' => '1',
			);
			if ( null !== $section ) {
				$fields['settings_section'] = $section;
			}
			$this->post( $fields );

			$this->assertSame( $before, $this->stored_options(), 'A POST with section ' . \var_export( $section, true ) . ' must write nothing.' );
		}
	}

	/**
	 * The login form still shows the stored value after a save (the screen reads what was written)
	 *
	 * @return void
	 */
	public function test_saved_value_is_what_the_form_renders_next(): void {
		\update_option( 'silver_assist_login_attempts', 5 );
		$form   = $this->form_with_section( 'login' );
		$fields = $this->form_fields( $form );
		$fields['silver_assist_login_attempts'] = '12';
		$this->post( $fields );

		$this->assertSame( '12', $this->form_fields( $this->form_with_section( 'login' ) )['silver_assist_login_attempts'] );
		$this->assertSame( 12, (int) DefaultConfig::get_option( 'silver_assist_login_attempts' ) );
	}
}
