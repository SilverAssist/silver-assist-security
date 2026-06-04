<?php
/**
 * Silver Assist Security Essentials - Login Page Branding
 *
 * Custom branding for the WordPress login page with a modern split-layout
 * design. Replaces the default WordPress appearance with Silver Assist branding.
 *
 * @package SilverAssist\Security\Security
 * @since 1.4.0
 * @author Silver Assist
 */

namespace SilverAssist\Security\Security;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;

/**
 * Login Branding class
 *
 * Implements custom branding for the WordPress login page with split-layout
 * design, inline SVG logo, and decorative illustration panel.
 *
 * @since 1.4.0
 */
class LoginBranding {

	/**
	 * Plugin version for cache busting
	 *
	 * @var string
	 */
	private string $plugin_version;

	/**
	 * Whether branding is enabled
	 *
	 * @var bool
	 */
	private bool $enabled;

	/**
	 * Constructor
	 *
	 * @since 1.4.0
	 */
	public function __construct() {
		$this->plugin_version = SILVER_ASSIST_SECURITY_VERSION;
		$this->enabled        = (bool) DefaultConfig::get_option( 'silver_assist_login_branding_enabled' );

		if ( $this->enabled ) {
			$this->init();
		}
	}

	/**
	 * Initialize hooks
	 *
	 * @since 1.4.0
	 * @return void
	 */
	private function init(): void {
		// Enqueue custom login styles.
		\add_action( 'login_enqueue_scripts', array( $this, 'enqueue_login_assets' ) );

		// Replace WordPress logo.
		\add_filter( 'login_headerurl', array( $this, 'custom_login_url' ) );
		\add_filter( 'login_headertext', array( $this, 'custom_login_text' ) );

		// Inject layout HTML.
		\add_action( 'login_head', array( $this, 'inject_login_head' ) );
		\add_action( 'login_footer', array( $this, 'inject_login_footer' ) );
		\add_filter( 'login_body_class', array( $this, 'add_body_classes' ) );

		// Custom page title.
		\add_filter( 'login_title', array( $this, 'custom_login_title' ), 10, 2 );
	}

	/**
	 * Enqueue login page assets
	 *
	 * @since 1.4.0
	 * @return void
	 */
	public function enqueue_login_assets(): void {
		\wp_enqueue_style(
			'silver-assist-variables',
			SecurityHelper::get_asset_url( 'assets/css/variables.css' ),
			array(),
			$this->plugin_version
		);

		\wp_enqueue_style(
			'silver-assist-login-branding',
			SecurityHelper::get_asset_url( 'assets/css/login-branding.css' ),
			array( 'silver-assist-variables' ),
			$this->plugin_version
		);

		$this->add_dynamic_inline_styles();
	}

	/**
	 * Custom login header URL
	 *
	 * @since 1.4.0
	 * @return string Site home URL.
	 */
	public function custom_login_url(): string {
		return \home_url( '/' );
	}

	/**
	 * Custom login header text
	 *
	 * @since 1.4.0
	 * @return string Site name.
	 */
	public function custom_login_text(): string {
		return \esc_html( \get_bloginfo( 'name' ) );
	}

	/**
	 * Inject dynamic inline styles via wp_add_inline_style
	 *
	 * @since 1.4.0
	 * @return void
	 */
	private function add_dynamic_inline_styles(): void {
		$custom_logo_url = DefaultConfig::get_option( 'silver_assist_login_branding_logo_url' );
		$css             = '';

		if ( ! empty( $custom_logo_url ) ) {
			$css .= 'body.silver-assist-branded-login #login h1 a {'
				. 'background-image: url(' . \esc_url( $custom_logo_url ) . ') !important;'
				. 'background-size: contain;'
				. 'background-repeat: no-repeat;'
				. 'background-position: center;'
				. 'width: 200px;'
				. 'height: 60px;'
				. '}'
				. 'body.silver-assist-branded-login #login h1 a .silver-logo-icon,'
				. 'body.silver-assist-branded-login #login h1 a .silver-logo-text {'
				. 'display: none;'
				. '}';
		}

		$bg_color = DefaultConfig::get_option( 'silver_assist_login_branding_bg_color' );
		if ( ! empty( $bg_color ) ) {
			$sanitized_color = \sanitize_hex_color( $bg_color );
			if ( ! empty( $sanitized_color ) ) {
				$css .= '.silver-login-illustration-panel {'
					. 'background: ' . $sanitized_color . ';'
					. '}';
			}
		}

		if ( ! empty( $css ) ) {
			\wp_add_inline_style( 'silver-assist-login-branding', $css );
		}
	}

	/**
	 * Inject additional login head content
	 *
	 * @since 1.4.0
	 * @return void
	 */
	public function inject_login_head(): void {
		// No-op: dynamic styles are now attached via wp_add_inline_style in enqueue_login_assets().
	}

	/**
	 * Inject illustration panel and footer branding into login footer
	 *
	 * @since 1.4.0
	 * @return void
	 */
	public function inject_login_footer(): void {
		$show_illustration = (bool) DefaultConfig::get_option( 'silver_assist_login_branding_show_illustration' );

		if ( $show_illustration ) {
			?>
			<div class="silver-login-illustration-panel">
				<div class="silver-login-illustration-content">
					<?php echo $this->get_illustration_svg(); ?>
				</div>
				<div class="silver-login-illustration-watermark"><?php echo \esc_html__( 'Silver Assist', 'silver-assist-security' ); ?></div>
			</div>
			<?php
		}
	}

	/**
	 * Add custom body classes for layout
	 *
	 * @since 1.4.0
	 * @param array<int, string> $classes Body classes.
	 * @return array<int, string> Modified body classes.
	 */
	public function add_body_classes( array $classes ): array {
		$classes[] = 'silver-assist-branded-login';

		$show_illustration = (bool) DefaultConfig::get_option( 'silver_assist_login_branding_show_illustration' );
		if ( $show_illustration ) {
			$classes[] = 'silver-assist-split-layout';
		}

		return $classes;
	}

	/**
	 * Custom login page title
	 *
	 * @since 1.4.0
	 * @param string $login_title The full page title.
	 * @param string $title       The action-specific title portion.
	 * @return string Modified page title.
	 */
	public function custom_login_title( string $login_title, string $title ): string {
		/* translators: %s: The action-specific title (e.g. "Log In", "Register"). */
		return \sprintf( \__( '%s \u2014 Silver Assist', 'silver-assist-security' ), $title );
	}

	/**
	 * Get the Silver Assist logo SVG markup
	 *
	 * @since 1.4.0
	 * @return string SVG markup.
	 */
	public function get_logo_svg(): string {
		$svg_path = SILVER_ASSIST_SECURITY_PATH . 'assets/images/silver-assist-logo.svg';

		if ( ! file_exists( $svg_path ) ) {
			return '';
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file read, not a remote request.
		$svg = file_get_contents( $svg_path );

		if ( false === $svg ) {
			return '';
		}

		// Add the CSS class to the SVG element.
		return str_replace( '<svg ', '<svg class="silver-logo-icon" ', $svg );
	}

	/**
	 * Get the illustration SVG markup for the right panel
	 *
	 * @since 1.4.0
	 * @return string SVG markup.
	 */
	private function get_illustration_svg(): string {
		$svg_path = SILVER_ASSIST_SECURITY_PATH . 'assets/images/login-illustration.svg';

		if ( ! file_exists( $svg_path ) ) {
			return '';
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file read, not a remote request.
		$svg = file_get_contents( $svg_path );

		if ( false === $svg ) {
			return '';
		}

		return $svg;
	}

	/**
	 * Check if branding is enabled
	 *
	 * @since 1.4.0
	 * @return bool
	 */
	public function is_enabled(): bool {
		return $this->enabled;
	}
}
