<?php
/**
 * Dashboard Renderer class
 *
 * Handles the rendering of the security dashboard tab
 *
 * @package SilverAssist\Security\Admin\Renderer
 * @since   1.1.15
 */

namespace SilverAssist\Security\Admin\Renderer;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;
use SilverAssist\Security\Admin\Data\SecurityDataProvider;
use SilverAssist\Security\Admin\Data\StatisticsProvider;
use SilverAssist\Security\Admin\Renderer\RenderHelper;

/**
 * Dashboard Renderer class
 *
 * @since 1.1.15
 */
class DashboardRenderer {

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
	 * Statistics Provider instance
	 *
	 * @var StatisticsProvider
	 */
	private StatisticsProvider $stats_provider;

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
		$this->stats_provider = new StatisticsProvider();
	}

	/**
	 * Render the security dashboard
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function render(): void {
		?>
		<!-- Dashboard Tab Content -->
		<div class="dashboard-grid">
			<?php
			$this->render_security_status_cards();
			$this->render_statistics_section();
			$this->render_recent_activity();
			?>
		</div>
		<?php
	}

	/**
	 * Render security status cards
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function render_security_status_cards(): void {
		$security_status = $this->data_provider->get_security_status();
		?>
		<div class="silver-stats-grid">
			
			<!-- Login Security Status -->
			<div class="status-card login-security">
				<div class="card-header">
					<h3><?php \esc_html_e( 'Login Security', 'silver-assist-security' ); ?></h3>
					<span class="status-indicator <?php echo \esc_attr( $security_status['login_security']['status'] ); ?>">
						<?php echo \esc_html( $security_status['login_security']['status'] ); ?>
					</span>
				</div>
				<div class="card-content">
					<?php
					RenderHelper::render_stat( $security_status['login_security']['max_attempts'], \__( 'Max Attempts', 'silver-assist-security' ) );
					RenderHelper::render_stat( $security_status['overall']['blocked_ips_count'], \__( 'Blocked IPs', 'silver-assist-security' ), '', 'blocked-ips-card' );
					RenderHelper::render_stat( round( $security_status['login_security']['lockout_duration'] / 60 ), \__( 'Lockout (min)', 'silver-assist-security' ) );
					?>
				</div>
			</div>

			<!-- Admin Security Status -->
			<div class="status-card admin-security">
				<div class="card-header">
					<h3><?php \esc_html_e( 'Admin Security', 'silver-assist-security' ); ?></h3>
					<span class="status-indicator <?php echo \esc_attr( $security_status['admin_security']['status'] ); ?>">
						<?php echo \esc_html( $security_status['admin_security']['status'] ); ?>
					</span>
				</div>
				<div class="card-content">
					<?php
					RenderHelper::render_feature_status( \__( 'Password Strength Enforcement', 'silver-assist-security' ), (bool) $security_status['admin_security']['password_strength_enforcement'] );
					RenderHelper::render_feature_status( \__( 'Bot Protection', 'silver-assist-security' ), (bool) $security_status['admin_security']['bot_protection'] );
					?>
				</div>
			</div>

			<!-- GraphQL Security Status -->
			<div class="status-card graphql-security">
				<div class="card-header">
					<h3><?php \esc_html_e( 'GraphQL Security', 'silver-assist-security' ); ?></h3>
					<span class="status-indicator <?php echo \esc_attr( $security_status['graphql_security']['status'] ); ?>">
						<?php echo \esc_html( $security_status['graphql_security']['status'] ); ?>
					</span>
				</div>
				<div class="card-content">
					<?php if ( $security_status['graphql_security']['enabled'] ) : ?>
						<?php
						RenderHelper::render_stat( $security_status['graphql_security']['query_depth_limit'], \__( 'Max Depth', 'silver-assist-security' ) );
						RenderHelper::render_stat( $security_status['graphql_security']['query_complexity_limit'], \__( 'Max Complexity', 'silver-assist-security' ) );
						RenderHelper::render_stat( $security_status['graphql_security']['query_timeout'], \__( 'Timeout', 'silver-assist-security' ), 's' );
						RenderHelper::render_feature_status(
							\__( 'Introspection', 'silver-assist-security' ),
							(bool) $security_status['graphql_security']['introspection_disabled'],
							\__( 'Disabled', 'silver-assist-security' ),
							\__( 'Public', 'silver-assist-security' )
						);
						?>
					<?php else : ?>
						<p class="description"><?php \esc_html_e( 'WPGraphQL not installed', 'silver-assist-security' ); ?></p>
					<?php endif; ?>
				</div>
			</div>

			<!-- General Security Status -->
			<div class="status-card general-security">
				<div class="card-header">
					<h3><?php \esc_html_e( 'General Security', 'silver-assist-security' ); ?></h3>
					<span class="status-indicator <?php echo \esc_attr( $security_status['general_security']['status'] ); ?>">
						<?php echo \esc_html( $security_status['general_security']['status'] ); ?>
					</span>
				</div>
				<div class="card-content">
					<?php
					RenderHelper::render_feature_status( \__( 'HTTPOnly Cookies', 'silver-assist-security' ), (bool) $security_status['general_security']['httponly_cookies'] );
					RenderHelper::render_feature_status( \__( 'XML-RPC Protection', 'silver-assist-security' ), (bool) $security_status['general_security']['xmlrpc_disabled'] );
					RenderHelper::render_feature_status( \__( 'Version Hiding', 'silver-assist-security' ), (bool) $security_status['general_security']['version_hiding'] );
					RenderHelper::render_feature_status( \__( 'SSL/HTTPS', 'silver-assist-security' ), (bool) $security_status['general_security']['ssl_enabled'] );
					?>
				</div>
			</div>

			<?php if ( SecurityHelper::is_contact_form_7_active() ) : ?>
			<!-- Contact Form 7 Security Status -->
			<div class="status-card cf7-security">
				<div class="card-header">
					<h3><?php \esc_html_e( 'Form Protection', 'silver-assist-security' ); ?></h3>
					<span class="status-indicator <?php echo $security_status['form_protection']['enabled'] ? 'active' : 'inactive'; ?>">
						<?php echo $security_status['form_protection']['enabled'] ? \esc_html__( 'active', 'silver-assist-security' ) : \esc_html__( 'inactive', 'silver-assist-security' ); ?>
					</span>
				</div>
				<div class="card-content">
					<?php
					RenderHelper::render_feature_status( \__( 'Form Protection', 'silver-assist-security' ), (bool) $security_status['form_protection']['enabled'] );
					RenderHelper::render_stat( $security_status['form_protection']['rate_limit'], \__( 'Rate Limit (min)', 'silver-assist-security' ) );
					?>
				</div>
			</div>
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Render statistics section
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function render_statistics_section(): void {
		?>
		<div class="statistics-section">
			<h2><?php \esc_html_e( 'Security Statistics', 'silver-assist-security' ); ?></h2>
			
			<div class="silver-stats-grid" id="security-stats-container">
				<?php
				RenderHelper::render_async_stat( 'blocked-ips-count', \__( 'Blocked IPs', 'silver-assist-security' ) );
				RenderHelper::render_async_stat( 'failed-attempts-count', \__( 'Failed Login Attempts (24h)', 'silver-assist-security' ) );
				RenderHelper::render_async_stat( 'security-events-count', \__( 'Security Events (7d)', 'silver-assist-security' ) );
				?>
			</div>
		</div>
		<?php
	}

	/**
	 * Render recent security activity
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function render_recent_activity(): void {
		?>
		<div class="status-card recent-activity-section">
			<div class="card-header">
				<h3><?php \esc_html_e( 'Recent Security Activity', 'silver-assist-security' ); ?></h3>
			</div>
			<div class="card-content">
				<div class="activity-tabs">
					<button class="activity-tab active" data-tab="blocked-ips">
						<span class="dashicons dashicons-dismiss"></span>
						<?php \esc_html_e( 'Blocked IPs', 'silver-assist-security' ); ?>
					</button>
					<button class="activity-tab" data-tab="security-logs">
						<span class="dashicons dashicons-list-view"></span>
						<?php \esc_html_e( 'Security Logs', 'silver-assist-security' ); ?>
					</button>
				</div>

				<div id="blocked-ips-content" class="activity-content active">
					<div id="blocked-ips-list">
						<div class="loading-spinner"></div>
						<p class="loading-text"><?php \esc_html_e( 'Loading blocked IPs...', 'silver-assist-security' ); ?></p>
					</div>
				</div>

				<div id="security-logs-content" class="activity-content">
					<div id="security-logs-list">
						<div class="loading-spinner"></div>
						<p class="loading-text"><?php \esc_html_e( 'Loading security logs...', 'silver-assist-security' ); ?></p>
					</div>
				</div>
			</div>
		</div>
		<?php
	}
}
