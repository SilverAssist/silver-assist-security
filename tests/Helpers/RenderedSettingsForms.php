<?php
/**
 * Rendered settings forms helper
 *
 * Renders the settings tabs and parses the HTML, so tests can read the forms the way a browser does.
 *
 * @package SilverAssist\Security\Tests\Helpers
 * @since 1.5.4
 */

namespace SilverAssist\Security\Tests\Helpers;

use DOMDocument;
use DOMElement;
use DOMXPath;
use SilverAssist\Security\Admin\Renderer\SettingsRenderer;
use SilverAssist\Security\Admin\Settings\SettingsRegistry;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;

/**
 * Trait for tests that read the rendered settings forms
 */
trait RenderedSettingsForms {

	/**
	 * Make every settings tab render: WPGraphQL must be installed and Contact Form 7 is stubbed
	 *
	 * @return void
	 */
	protected function require_full_settings_screen(): void {
		if ( ! \class_exists( 'WPGraphQL' ) ) {
			$message = 'WPGraphQL is not installed: run scripts/install-wpgraphql-for-tests.sh';
			if ( false !== \getenv( 'CI' ) && '' !== \getenv( 'CI' ) ) {
				$this->fail( $message . ' (CI must not skip the GraphQL forms).' );
			}
			$this->markTestSkipped( $message . '.' );
		}

		// The CF7 tab only renders when Contact Form 7 is active; same test-only stub the CF7 tests use.
		if ( ! \defined( 'WPCF7_VERSION' ) ) {
			\define( 'WPCF7_VERSION', '5.8' );
		}
		if ( ! \class_exists( 'WPCF7' ) ) {
			eval( 'class WPCF7 {}' ); // phpcs:ignore Squiz.PHP.Eval.Discouraged -- Test-only CF7 class stub; excluded from the eval() security scan via --exclude-dir=tests.
		}
	}

	/**
	 * Render every settings tab and return the forms that have a submit button
	 *
	 * @return array<int, DOMElement>
	 */
	private function submit_forms(): array {
		$renderer = new SettingsRenderer( GraphQLConfigManager::get_instance() );
		\ob_start();
		$renderer->render_all_tabs();
		$html = (string) \ob_get_clean();

		$previous = \libxml_use_internal_errors( true );
		try {
			$dom = new DOMDocument();
			$dom->loadHTML( '<?xml encoding="utf-8" ?><body>' . $html . '</body>' );
		} finally {
			\libxml_clear_errors();
			\libxml_use_internal_errors( $previous );
		}

		$xpath = new DOMXPath( $dom );
		$forms = array();
		foreach ( $xpath->query( '//form' ) as $form ) {
			if ( $form instanceof DOMElement && $xpath->query( './/input[@type="submit"]', $form )->length > 0 ) {
				$forms[] = $form;
			}
		}

		return $forms;
	}

	/**
	 * The fields a browser would send for a form
	 *
	 * @param DOMElement $form Form element.
	 * @return array<string, string> Name => value, checkboxes only when checked.
	 */
	private function form_fields( DOMElement $form ): array {
		$fields = array();
		foreach ( $form->getElementsByTagName( 'input' ) as $input ) {
			$name = $input->getAttribute( 'name' );
			$type = $input->getAttribute( 'type' );
			if ( '' === $name || 'button' === $type ) {
				continue;
			}
			if ( 'checkbox' === $type && ! $input->hasAttribute( 'checked' ) ) {
				continue;
			}
			$fields[ $name ] = $input->getAttribute( 'value' );
		}
		foreach ( $form->getElementsByTagName( 'select' ) as $select ) {
			$name  = $select->getAttribute( 'name' );
			$value = '';
			foreach ( $select->getElementsByTagName( 'option' ) as $option ) {
				if ( $option->hasAttribute( 'selected' ) ) {
					$value = $option->getAttribute( 'value' );
				}
			}
			$fields[ $name ] = $value;
		}

		return $fields;
	}

	/**
	 * Every named input or select in a form, checked or not
	 *
	 * @param DOMElement $form Form element.
	 * @return string[]
	 */
	protected function form_field_names( DOMElement $form ): array {
		$names = array();
		foreach ( array( 'input', 'select' ) as $tag ) {
			foreach ( $form->getElementsByTagName( $tag ) as $element ) {
				if ( '' !== $element->getAttribute( 'name' ) ) {
					$names[] = $element->getAttribute( 'name' );
				}
			}
		}

		return $names;
	}

	/**
	 * The form's input element for a name
	 *
	 * @param DOMElement $form Form element.
	 * @param string     $name Field name.
	 * @return DOMElement|null
	 */
	private function field_element( DOMElement $form, string $name ): ?DOMElement {
		foreach ( array( 'input', 'select' ) as $tag ) {
			foreach ( $form->getElementsByTagName( $tag ) as $element ) {
				if ( $element->getAttribute( 'name' ) === $name ) {
					return $element;
				}
			}
		}

		return null;
	}

	/**
	 * The sections a rendered form saves: those of its tab
	 *
	 * @param DOMElement $form Form element.
	 * @return string[]
	 */
	private function form_sections( DOMElement $form ): array {
		return SettingsRegistry::sections_for_tab( $this->form_fields( $form )['settings_tab'] ?? '' );
	}

	/**
	 * The rendered form of a tab
	 *
	 * @param string $tab Tab slug.
	 * @return DOMElement
	 */
	private function form_for_tab( string $tab ): DOMElement {
		foreach ( $this->submit_forms() as $form ) {
			if ( ( $this->form_fields( $form )['settings_tab'] ?? '' ) === $tab ) {
				return $form;
			}
		}

		$this->fail( "No form for tab {$tab}." );
	}

	/**
	 * The rendered form that saves a section
	 *
	 * @param string $section Section slug.
	 * @return DOMElement
	 */
	private function form_with_section( string $section ): DOMElement {
		foreach ( $this->submit_forms() as $form ) {
			if ( in_array( $section, $this->form_sections( $form ), true ) ) {
				return $form;
			}
		}

		$this->fail( "No form for section {$section}." );
	}
}
