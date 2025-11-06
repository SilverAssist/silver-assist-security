<?php
/**
 * Admin Page Renderer class
 *
 * Handles the rendering of the main admin page structure
 *
 * @package SilverAssist\Security\Admin\Renderer
 * @since   1.1.15
 */

namespace SilverAssist\Security\Admin\Renderer;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use SilverAssist\Security\Admin\Data\SecurityDataProvider;

/**
 * Admin Page Renderer class
 *
 * @since 1.1.15
 */
class AdminPageRenderer {

	/**
	 * GraphQL Configuration Manager instance
	 *
	 * @var GraphQLConfigManager
	 */
	private GraphQLConfigManager $config_manager;

	/**
	 * Security Data Provider instance
	 *
	 * @var SecurityDataProvider
	 */
	private SecurityDataProvider $data_provider;

	/**
	 * Constructor
	 *
	 * @param GraphQLConfigManager $config_manager GraphQL configuration manager
	 * @param SecurityDataProvider $data_provider  Security data provider
	 * @since 1.1.15
	 */
	public function __construct( GraphQLConfigManager $config_manager, SecurityDataProvider $data_provider ) {
		$this->config_manager = $config_manager;
		$this->data_provider  = $data_provider;
	}

	/**
	 * Render the complete admin page
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function render(): void {
		// Verify user has permission to manage options
		if ( ! \current_user_can( 'manage_options' ) ) {
			\wp_die(
				\esc_html__( 'You do not have sufficient permissions to access this page.', 'silver-assist-security' ),
				\esc_html__( 'Permission Denied', 'silver-assist-security' ),
				[ 'response' => 403 ]
			);
		}

		$this->render_page_header();
		$this->render_page_content();
		$this->render_page_footer();
	}

	/**
	 * Render page header with title and navigation
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function render_page_header(): void {
		// Get initial security status for display
		$security_status = $this->data_provider->get_security_status();

		?>
		<div class="wrap">
			<h1><?php echo \esc_html( \__( 'Silver Assist Security Essentials', 'silver-assist-security' ) ); ?></h1>

			<!-- Tab Navigation -->
			<nav class="nav-tab-wrapper">
				<a href="#dashboard" class="nav-tab nav-tab-active" id="dashboard-tab">
					<span class="dashicons dashicons-dashboard"></span>
					<?php \esc_html_e( 'Security Dashboard', 'silver-assist-security' ); ?>
				</a>
				<a href="#login-security" class="nav-tab" id="login-security-tab">
					<span class="dashicons dashicons-lock"></span>
					<?php \esc_html_e( 'Login Protection', 'silver-assist-security' ); ?>
				</a>
				<a href="#graphql-security" class="nav-tab" id="graphql-security-tab">
					<span class="dashicons dashicons-database"></span>
					<?php \esc_html_e( 'GraphQL Security', 'silver-assist-security' ); ?>
				</a>
				<?php if ( SecurityHelper::is_contact_form_7_active() ) : ?>
				<a href="#cf7-security" class="nav-tab" id="cf7-security-tab">
					<span class="dashicons dashicons-email-alt"></span>
					<?php \esc_html_e( 'Form Protection', 'silver-assist-security' ); ?>
				</a>
				<?php endif; ?>
				<a href="#ip-management" class="nav-tab" id="ip-management-tab">
					<span class="dashicons dashicons-shield"></span>
					<?php \esc_html_e( 'IP Management', 'silver-assist-security' ); ?>
				</a>
			</nav>
		<?php
	}

	/**
	 * Render main page content with all tabs
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function render_page_content(): void {
		$dashboard_renderer = new DashboardRenderer( $this->config_manager, $this->data_provider );
		$settings_renderer  = new SettingsRenderer( $this->config_manager );

		echo '<div class="tab-content-wrapper">';

		// Dashboard Tab
		echo '<div id="dashboard-content" class="tab-content active">';
		$dashboard_renderer->render();
		echo '</div>';

		// Settings Tabs
		$settings_renderer->render_all_tabs();

		echo '</div>';
	}

	/**
	 * Render page footer
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function render_page_footer(): void {
		?>
		</div> <!-- .wrap -->
		<?php
	}

	/**
	 * Get current configuration values
	 *
	 * @since 1.1.15
	 * @return array Configuration values
	 */
	public function get_current_config(): array {
		return [
			'login_attempts'                => DefaultConfig::get_option( 'silver_assist_login_attempts' ),
			'lockout_duration'              => DefaultConfig::get_option( 'silver_assist_lockout_duration' ),
			'session_timeout'               => DefaultConfig::get_option( 'silver_assist_session_timeout' ),
			'bot_protection'                => DefaultConfig::get_option( 'silver_assist_bot_protection' ),
			'password_strength_enforcement' => DefaultConfig::get_option( 'silver_assist_password_strength_enforcement' ),
			'graphql_headless_mode'         => DefaultConfig::get_option( 'silver_assist_graphql_headless_mode' ),
			'graphql_query_timeout'         => \get_option( 'silver_assist_graphql_query_timeout', $this->config_manager->get_php_execution_timeout() ),
			'cf7_protection_enabled'        => SecurityHelper::is_contact_form_7_active() ? DefaultConfig::get_option( 'silver_assist_cf7_protection_enabled' ) : 0,
			'cf7_rate_limit'                => SecurityHelper::is_contact_form_7_active() ? DefaultConfig::get_option( 'silver_assist_cf7_rate_limit' ) : DefaultConfig::get_default( 'silver_assist_cf7_rate_limit' ) ?? 2,
			'cf7_rate_window'               => SecurityHelper::is_contact_form_7_active() ? DefaultConfig::get_option( 'silver_assist_cf7_rate_window' ) : DefaultConfig::get_default( 'silver_assist_cf7_rate_window' ) ?? 60,
			'ip_blacklist_enabled'          => DefaultConfig::get_option( 'silver_assist_ip_blacklist_enabled' ),
			'ip_violation_threshold'        => DefaultConfig::get_option( 'silver_assist_ip_violation_threshold' ),
			'ip_blacklist_duration'         => DefaultConfig::get_option( 'silver_assist_ip_blacklist_duration' ),
			'under_attack_enabled'          => DefaultConfig::get_option( 'silver_assist_under_attack_enabled' ),
			'attack_threshold'              => DefaultConfig::get_option( 'silver_assist_attack_threshold' ),
		];
	}
}
