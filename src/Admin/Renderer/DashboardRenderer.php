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
		<div class="security-status-grid">
			
			<!-- Login Security Status -->
			<div class="security-card login-security">
				<div class="card-header">
					<span class="dashicons dashicons-lock"></span>
					<h3><?php \esc_html_e( 'Login Protection', 'silver-assist-security' ); ?></h3>
					<span class="status-indicator <?php echo \esc_attr( $security_status['login_security']['status'] ); ?>">
						<?php echo \esc_html( \ucfirst( $security_status['login_security']['status'] ) ); ?>
					</span>
				</div>
				<div class="card-content">
					<p>
						<?php
						printf(
							/* translators: %d: maximum login attempts */
							\esc_html__( 'Max attempts: %d', 'silver-assist-security' ),
							(int) $security_status['login_security']['max_attempts']
						);
						?>
					</p>
					<p>
						<?php
						printf(
							/* translators: %d: lockout duration in minutes */
							\esc_html__( 'Lockout: %d minutes', 'silver-assist-security' ),
							\round( $security_status['login_security']['lockout_duration'] / 60 )
						);
						?>
					</p>
				</div>
			</div>

			<!-- GraphQL Security Status -->
			<div class="security-card graphql-security">
				<div class="card-header">
					<span class="dashicons dashicons-database"></span>
					<h3><?php \esc_html_e( 'GraphQL Security', 'silver-assist-security' ); ?></h3>
					<span class="status-indicator <?php echo \esc_attr( $security_status['graphql_security']['status'] ); ?>">
						<?php echo \esc_html( \ucfirst( $security_status['graphql_security']['status'] ) ); ?>
					</span>
				</div>
				<div class="card-content">
					<?php if ( $security_status['graphql_security']['enabled'] ) : ?>
						<p>
							<?php
							printf(
								/* translators: %d: query depth limit */
								\esc_html__( 'Query depth limit: %d', 'silver-assist-security' ),
								(int) $security_status['graphql_security']['query_depth_limit']
							);
							?>
						</p>
						<p>
							<?php
							printf(
								/* translators: %d: query complexity limit */
								\esc_html__( 'Complexity limit: %d', 'silver-assist-security' ),
								(int) $security_status['graphql_security']['query_complexity_limit']
							);
							?>
						</p>
					<?php else : ?>
						<p><?php \esc_html_e( 'WPGraphQL not installed', 'silver-assist-security' ); ?></p>
					<?php endif; ?>
				</div>
			</div>

			<!-- General Security Status -->
			<div class="security-card general-security">
				<div class="card-header">
					<span class="dashicons dashicons-shield-alt"></span>
					<h3><?php \esc_html_e( 'General Security', 'silver-assist-security' ); ?></h3>
					<span class="status-indicator <?php echo \esc_attr( $security_status['general_security']['status'] ); ?>">
						<?php echo \esc_html( \ucfirst( $security_status['general_security']['status'] ) ); ?>
					</span>
				</div>
				<div class="card-content">
					<p>
						<span class="feature-status <?php echo $security_status['general_security']['httponly_cookies'] ? 'enabled' : 'disabled'; ?>">
							<?php \esc_html_e( 'HTTPOnly Cookies', 'silver-assist-security' ); ?>
						</span>
					</p>
					<p>
						<span class="feature-status <?php echo $security_status['general_security']['ssl_enabled'] ? 'enabled' : 'disabled'; ?>">
							<?php \esc_html_e( 'SSL/HTTPS', 'silver-assist-security' ); ?>
						</span>
					</p>
				</div>
			</div>

			<?php if ( SecurityHelper::is_contact_form_7_active() ) : ?>
			<!-- Contact Form 7 Security Status -->
			<div class="security-card cf7-security">
				<div class="card-header">
					<span class="dashicons dashicons-email-alt"></span>
					<h3><?php \esc_html_e( 'Form Protection', 'silver-assist-security' ); ?></h3>
					<span class="status-indicator active">
						<?php \esc_html_e( 'Active', 'silver-assist-security' ); ?>
					</span>
				</div>
				<div class="card-content">
					<p><?php \esc_html_e( 'Contact Form 7 protection enabled', 'silver-assist-security' ); ?></p>
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
			
			<div class="stats-grid" id="security-stats-container">
				<div class="stat-card">
					<div class="stat-number" id="blocked-ips-count">
						<span class="loading-spinner"></span>
					</div>
					<div class="stat-label"><?php \esc_html_e( 'Blocked IPs', 'silver-assist-security' ); ?></div>
				</div>
				
				<div class="stat-card">
					<div class="stat-number" id="failed-attempts-count">
						<span class="loading-spinner"></span>
					</div>
					<div class="stat-label"><?php \esc_html_e( 'Failed Login Attempts (24h)', 'silver-assist-security' ); ?></div>
				</div>
				
				<div class="stat-card">
					<div class="stat-number" id="security-events-count">
						<span class="loading-spinner"></span>
					</div>
					<div class="stat-label"><?php \esc_html_e( 'Security Events (7d)', 'silver-assist-security' ); ?></div>
				</div>
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
		<div class="recent-activity-section">
			<h2><?php \esc_html_e( 'Recent Security Activity', 'silver-assist-security' ); ?></h2>
			
			<div class="activity-tabs">
				<button class="activity-tab active" data-tab="blocked-ips">
					<?php \esc_html_e( 'Blocked IPs', 'silver-assist-security' ); ?>
				</button>
				<button class="activity-tab" data-tab="security-logs">
					<?php \esc_html_e( 'Security Logs', 'silver-assist-security' ); ?>
				</button>
			</div>
			
			<div id="blocked-ips-content" class="activity-content active">
				<div id="blocked-ips-list">
					<div class="loading-spinner"></div>
					<p><?php \esc_html_e( 'Loading blocked IPs...', 'silver-assist-security' ); ?></p>
				</div>
			</div>
			
			<div id="security-logs-content" class="activity-content">
				<div id="security-logs-list">
					<div class="loading-spinner"></div>
					<p><?php \esc_html_e( 'Loading security logs...', 'silver-assist-security' ); ?></p>
				</div>
			</div>
		</div>
		<?php
	}
}
