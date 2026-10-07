<?php
/**
 * Settings registry consistency tests
 *
 * The registry declares every option the settings screen saves. These tests keep the declarations,
 * the defaults and the rendered screen in step, so adding an option in one place and not the others
 * fails here.
 *
 * @package SilverAssist\Security\Tests\Integration
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Integration;

use SilverAssist\Security\Admin\Settings\SettingsRegistry;
use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Tests\Helpers\RenderedSettingsForms;
use WP_UnitTestCase;

/**
 * Registry consistency
 */
class SettingsRegistryTest extends WP_UnitTestCase {

	use RenderedSettingsForms;

	/**
	 * Every declaration is well formed
	 *
	 * @return void
	 */
	public function test_declarations_are_well_formed(): void {
		$types = array(
			SettingsRegistry::TYPE_BOOL,
			SettingsRegistry::TYPE_INT,
			SettingsRegistry::TYPE_URL,
			SettingsRegistry::TYPE_HEX_COLOR,
			SettingsRegistry::TYPE_ADMIN_PATH,
			SettingsRegistry::TYPE_USER_ID,
		);

		foreach ( SettingsRegistry::all() as $option => $declaration ) {
			$this->assertSame( $option, $declaration['option'] );
			$this->assertStringStartsWith( 'silver_assist_', $option );
			$this->assertContains( $declaration['type'], $types, "{$option} has an unknown type." );
			$this->assertTrue( SettingsRegistry::has_section( $declaration['section'] ), "{$option} has an unknown section." );
			$this->assertIsBool( $declaration['ui'] );

			if ( SettingsRegistry::TYPE_INT === $declaration['type'] ) {
				$this->assertIsInt( $declaration['min'], "{$option} needs a minimum." );
				$this->assertNotNull( SettingsRegistry::resolve_max( $declaration ), "{$option} needs a maximum." );
				$this->assertGreaterThan( $declaration['min'], SettingsRegistry::resolve_max( $declaration ), "{$option} has an empty range." );
			}
		}
	}

	/**
	 * Every option has a default, so the screen and the readers never see null
	 *
	 * @return void
	 */
	public function test_every_option_has_a_default_in_default_config(): void {
		foreach ( \array_keys( SettingsRegistry::all() ) as $option ) {
			$this->assertNotNull( DefaultConfig::get_default( $option ), "{$option} has no default in DefaultConfig." );
		}
	}

	/**
	 * Every default lies inside the registered range
	 *
	 * @return void
	 */
	public function test_int_defaults_are_inside_the_registered_range(): void {
		foreach ( SettingsRegistry::all() as $option => $declaration ) {
			if ( SettingsRegistry::TYPE_INT !== $declaration['type'] ) {
				continue;
			}
			$default = (int) DefaultConfig::get_default( $option );
			$this->assertGreaterThanOrEqual( $declaration['min'], $default, "{$option} default is below the minimum." );
			$this->assertLessThanOrEqual( SettingsRegistry::resolve_max( $declaration ), $default, "{$option} default is above the maximum." );
		}
	}

	/**
	 * Tabs list every section once, in sections that exist
	 *
	 * @return void
	 */
	public function test_tabs_cover_every_section_exactly_once(): void {
		$in_tabs = array();
		foreach ( SettingsRegistry::tabs() as $tab => $sections ) {
			$this->assertNotEmpty( $sections, "Tab {$tab} has no section." );
			$this->assertSame( $sections, SettingsRegistry::sections_for_tab( $tab ) );
			$in_tabs = array_merge( $in_tabs, $sections );
		}
		$expected = SettingsRegistry::sections();
		\sort( $expected );
		\sort( $in_tabs );

		$this->assertSame( $expected, $in_tabs, 'Every registry section is saved from exactly one tab.' );
		$this->assertSame( array(), SettingsRegistry::sections_for_tab( 'nope' ) );
	}

	/**
	 * Every option flagged as having a field is rendered, inside the form of the tab that saves its section
	 *
	 * Options without a field are not rendered anywhere.
	 *
	 * @return void
	 */
	public function test_ui_options_are_rendered_inside_their_own_sections_form(): void {
		$this->require_full_settings_screen();
		\wp_set_current_user( $this->factory()->user->create( array( 'role' => 'administrator' ) ) );

		$rendered = array();
		foreach ( $this->submit_forms() as $form ) {
			$sections = $this->form_sections( $form );
			foreach ( $this->form_field_names( $form ) as $name ) {
				if ( null !== SettingsRegistry::get( $name ) ) {
					$rendered[ $name ] = $sections;
				}
			}
		}

		foreach ( SettingsRegistry::all() as $option => $declaration ) {
			if ( $declaration['ui'] ) {
				$this->assertContains( $declaration['section'], $rendered[ $option ] ?? array(), "{$option} has a field, so it must be rendered in the form of the tab that saves section {$declaration['section']}." );
			} else {
				$this->assertArrayNotHasKey( $option, $rendered, "{$option} is declared without a field but a form renders it." );
			}
		}
	}

	/**
	 * Section helpers agree with the declarations
	 *
	 * @return void
	 */
	public function test_section_helpers(): void {
		$this->assertFalse( SettingsRegistry::has_section( '' ) );
		$this->assertFalse( SettingsRegistry::has_section( 'all' ) );
		$this->assertNull( SettingsRegistry::get( 'silver_assist_not_an_option' ) );

		$count = 0;
		foreach ( SettingsRegistry::sections() as $section ) {
			$count += \count( SettingsRegistry::for_section( $section ) );
		}
		$this->assertSame( \count( SettingsRegistry::all() ), $count );
	}
}
