<?php
/**
 * Settings Renderer class
 *
 * Handles the rendering of all settings tabs
 *
 * @package SilverAssist\Security\Admin\Renderer
 * @since   1.1.15
 */

namespace SilverAssist\Security\Admin\Renderer;

use SilverAssist\Security\Core\DefaultConfig;
use SilverAssist\Security\Core\SecurityHelper;
use SilverAssist\Security\GraphQL\GraphQLConfigManager;

/**
 * Settings Renderer class
 *
 * @since 1.1.15
 */
class SettingsRenderer {

	/**
	 * GraphQL Configuration Manager instance
	 *
	 * @var GraphQLConfigManager
	 */
	private GraphQLConfigManager $config_manager;

	/**
	 * Constructor
	 *
	 * @param GraphQLConfigManager $config_manager GraphQL configuration manager
	 * @since 1.1.15
	 */
	public function __construct( GraphQLConfigManager $config_manager ) {
		$this->config_manager = $config_manager;
	}

	/**
	 * Render all settings tabs
	 *
	 * @since 1.1.15
	 * @return void
	 */
	public function render_all_tabs(): void {
		$this->render_login_security_tab();

		if ( \class_exists( 'WPGraphQL' ) ) {
			$this->render_graphql_security_tab();
		}

		if ( SecurityHelper::is_contact_form_7_active() ) {
			$this->render_cf7_security_tab();
		}

		$this->render_ip_management_tab();
	}

	/**
	 * Render login security settings tab
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function render_login_security_tab(): void {
		$config = $this->get_current_config();
		?>
		<!-- Login Security Tab -->
		<div id="login-security-content" class="silver-tab-content">
			<h2><?php \esc_html_e( 'Login Protection Settings', 'silver-assist-security' ); ?></h2>
			
			<form method="post" action="" id="security-settings-form">
				<?php \wp_nonce_field( 'silver_assist_security_settings', 'silver_assist_security_nonce' ); ?>
				
				<table class="form-table">
					<tbody>
						<!-- Login Attempts -->
						<tr>
							<th scope="row">
								<label for="silver_assist_login_attempts">
									<?php \esc_html_e( 'Failed Login Attempts', 'silver-assist-security' ); ?>
								</label>
							</th>
							<td>
								<input type="range" 
										id="silver_assist_login_attempts" 
										name="silver_assist_login_attempts" 
										min="1" 
										max="20" 
										value="<?php echo \esc_attr( $config['login_attempts'] ); ?>">
								<span class="slider-value" id="login-attempts-value"><?php echo \esc_html( $config['login_attempts'] ); ?></span>
								<p class="description">
									<?php \esc_html_e( 'Number of failed login attempts before IP lockout (1-20)', 'silver-assist-security' ); ?>
								</p>
							</td>
						</tr>
						
						<!-- Lockout Duration -->
						<tr>
							<th scope="row">
								<label for="silver_assist_lockout_duration">
									<?php \esc_html_e( 'Lockout Duration (minutes)', 'silver-assist-security' ); ?>
								</label>
							</th>
							<td>
								<input type="range" 
										id="silver_assist_lockout_duration" 
										name="silver_assist_lockout_duration" 
										min="60" 
										max="3600" 
										step="60" 
										value="<?php echo \esc_attr( $config['lockout_duration'] ); ?>">
								<span class="slider-value" id="lockout-duration-value">
									<?php echo \esc_html( \round( $config['lockout_duration'] / 60 ) ); ?>
								</span>
								<p class="description">
									<?php \esc_html_e( 'Duration to block IP after failed attempts (1-60 minutes)', 'silver-assist-security' ); ?>
								</p>
							</td>
						</tr>
						
						<!-- Session Timeout -->
						<tr>
							<th scope="row">
								<label for="silver_assist_session_timeout">
									<?php \esc_html_e( 'Session Timeout (minutes)', 'silver-assist-security' ); ?>
								</label>
							</th>
							<td>
								<input type="range" 
										id="silver_assist_session_timeout" 
										name="silver_assist_session_timeout" 
										min="5" 
										max="120" 
										value="<?php echo \esc_attr( $config['session_timeout'] ); ?>">
								<span class="slider-value" id="session-timeout-value"><?php echo \esc_html( $config['session_timeout'] ); ?></span>
								<p class="description">
									<?php \esc_html_e( 'Automatic logout after inactivity (5-120 minutes)', 'silver-assist-security' ); ?>
								</p>
							</td>
						</tr>
						
						<!-- Password Strength -->
						<tr>
							<th scope="row">
								<?php \esc_html_e( 'Password Strength Enforcement', 'silver-assist-security' ); ?>
							</th>
							<td>
								<label class="toggle-switch">
									<input type="checkbox" 
											id="silver_assist_password_strength_enforcement" 
											name="silver_assist_password_strength_enforcement" 
											value="1" 
											<?php \checked( $config['password_strength_enforcement'], 1 ); ?>>
									<span class="toggle-slider"></span>
								</label>
								<p class="description">
									<?php \esc_html_e( 'Require strong passwords (12+ chars, mixed case, numbers, symbols)', 'silver-assist-security' ); ?>
								</p>
							</td>
						</tr>
						
						<!-- Bot Protection -->
						<tr>
							<th scope="row">
								<?php \esc_html_e( 'Bot Protection', 'silver-assist-security' ); ?>
							</th>
							<td>
								<label class="toggle-switch">
									<input type="checkbox" 
											id="silver_assist_bot_protection" 
											name="silver_assist_bot_protection" 
											value="1" 
											<?php \checked( $config['bot_protection'], 1 ); ?>>
									<span class="toggle-slider"></span>
								</label>
								<p class="description">
									<?php \esc_html_e( 'Block known bots, crawlers, and security scanners', 'silver-assist-security' ); ?>
								</p>
							</td>
						</tr>
					</tbody>
				</table>
				
				<p class="submit">
					<input type="submit" 
							name="submit" 
							id="submit" 
							class="button button-primary" 
							value="<?php \esc_attr_e( 'Save Login Settings', 'silver-assist-security' ); ?>">
				</p>
			</form>
		</div>
		<?php
	}

	/**
	 * Render GraphQL security settings tab
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function render_graphql_security_tab(): void {
		$config = $this->get_current_config();
		?>
		<!-- GraphQL Security Tab -->
		<div id="graphql-security-content" class="silver-tab-content">
			<h2><?php \esc_html_e( 'GraphQL Security Settings', 'silver-assist-security' ); ?></h2>
			
			<?php if ( \class_exists( 'WPGraphQL' ) ) : ?>
				
				<!-- Display current GraphQL configuration -->
				<div class="graphql-config-display">
					<?php echo $this->config_manager->get_configuration_html(); ?>
				</div>
				
				<form method="post" action="" id="graphql-settings-form">
					<?php \wp_nonce_field( 'silver_assist_security_settings', 'silver_assist_security_nonce' ); ?>
					
					<table class="form-table">
						<tbody>
							<!-- Headless Mode -->
							<tr>
								<th scope="row">
									<?php \esc_html_e( 'Headless CMS Mode', 'silver-assist-security' ); ?>
								</th>
								<td>
									<label class="toggle-switch">
										<input type="checkbox" 
												id="silver_assist_graphql_headless_mode" 
												name="silver_assist_graphql_headless_mode" 
												value="1" 
												<?php \checked( $config['graphql_headless_mode'], 1 ); ?>>
										<span class="toggle-slider"></span>
									</label>
									<p class="description">
										<?php \esc_html_e( 'Enable higher limits for headless WordPress configurations', 'silver-assist-security' ); ?>
									</p>
								</td>
							</tr>
							
							<!-- Query Timeout -->
							<tr>
								<th scope="row">
									<label for="silver_assist_graphql_query_timeout">
										<?php \esc_html_e( 'Query Timeout (seconds)', 'silver-assist-security' ); ?>
									</label>
								</th>
								<td>
									<input type="range" 
											id="silver_assist_graphql_query_timeout" 
											name="silver_assist_graphql_query_timeout" 
											min="1" 
											max="30" 
											value="<?php echo \esc_attr( $config['graphql_query_timeout'] ); ?>"
									<span class="slider-value" id="graphql-timeout-value"><?php echo \esc_html( $config['graphql_query_timeout'] ); ?></span>
									<p class="description">
										<?php \esc_html_e( 'Maximum execution time for GraphQL queries (1-30 seconds)', 'silver-assist-security' ); ?>
									</p>
								</td>
							</tr>
						</tbody>
					</table>
					
					<p class="submit">
						<input type="submit" 
								name="submit" 
								id="submit" 
								class="button button-primary" 
								value="<?php \esc_attr_e( 'Save GraphQL Settings', 'silver-assist-security' ); ?>">
					</p>
				</form>
				
			<?php else : ?>
				
				<!-- WPGraphQL not installed message -->
				<div class="notice notice-info">
					<p>
						<strong><?php \esc_html_e( 'WPGraphQL Plugin Not Detected', 'silver-assist-security' ); ?></strong>
					</p>
					<p>
						<?php \esc_html_e( 'GraphQL security features require the WPGraphQL plugin to be installed and activated.', 'silver-assist-security' ); ?>
					</p>
					<p>
						<a href="<?php echo \esc_url( \admin_url( 'plugin-install.php?s=wpgraphql&tab=search&type=term' ) ); ?>" 
							class="button button-secondary">
							<?php \esc_html_e( 'Install WPGraphQL Plugin', 'silver-assist-security' ); ?>
						</a>
					</p>
				</div>
				
			<?php endif; ?>
		</div>
		<?php
	}

	/**
	 * Render Contact Form 7 security settings tab
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function render_cf7_security_tab(): void {
		$config = $this->get_current_config();
		?>
		<!-- CF7 Security Tab -->
		<div id="cf7-security-content" class="silver-tab-content">
			<h2><?php \esc_html_e( 'Contact Form 7 Protection', 'silver-assist-security' ); ?></h2>
			
			<form method="post" action="" id="cf7-settings-form">
				<?php \wp_nonce_field( 'silver_assist_security_settings', 'silver_assist_security_nonce' ); ?>
				
				<table class="form-table">
					<tbody>
						<!-- CF7 Protection Enable -->
						<tr>
							<th scope="row">
								<?php \esc_html_e( 'Form Protection', 'silver-assist-security' ); ?>
							</th>
							<td>
								<label class="toggle-switch">
									<input type="checkbox" 
											id="silver_assist_cf7_protection_enabled" 
											name="silver_assist_cf7_protection_enabled" 
											value="1" 
											<?php \checked( $config['cf7_protection_enabled'], 1 ); ?>>
									<span class="toggle-slider"></span>
								</label>
								<p class="description">
									<?php \esc_html_e( 'Enable protection for Contact Form 7 submissions', 'silver-assist-security' ); ?>
								</p>
							</td>
						</tr>
						
						<!-- CF7 Rate Limit -->
						<tr>
							<th scope="row">
								<label for="silver_assist_cf7_rate_limit">
									<?php \esc_html_e( 'Rate Limit (submissions/minute)', 'silver-assist-security' ); ?>
								</label>
							</th>
							<td>
								<input type="range" 
										id="silver_assist_cf7_rate_limit" 
										name="silver_assist_cf7_rate_limit" 
										min="1" 
										max="10" 
										value="<?php echo \esc_attr( $config['cf7_rate_limit'] ); ?>"
								<span class="slider-value" id="cf7-rate-limit-value"><?php echo \esc_html( $config['cf7_rate_limit'] ); ?></span>
								<p class="description">
									<?php \esc_html_e( 'Maximum form submissions per minute per IP address', 'silver-assist-security' ); ?>
								</p>
							</td>
						</tr>
					</tbody>
				</table>
				
				<p class="submit">
					<input type="submit" 
							name="submit" 
							id="submit" 
							class="button button-primary" 
							value="<?php \esc_attr_e( 'Save Form Settings', 'silver-assist-security' ); ?>">
				</p>
			</form>
			
			<!-- CF7 Blocked IPs Management -->
			<div class="cf7-blocked-ips-section">
				<h3><?php \esc_html_e( 'Blocked IPs Management', 'silver-assist-security' ); ?></h3>
				<div id="cf7-blocked-ips-container">
					<p><?php \esc_html_e( 'Loading blocked IPs...', 'silver-assist-security' ); ?></p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Render IP management settings tab
	 *
	 * @since 1.1.15
	 * @return void
	 */
	private function render_ip_management_tab(): void {
		$config = $this->get_current_config();
		?>
		<!-- IP Management Tab -->
		<div id="ip-management-content" class="silver-tab-content">
			<h2><?php \esc_html_e( 'IP Management & Attack Protection', 'silver-assist-security' ); ?></h2>
			
			<form method="post" action="" id="ip-management-form">
				<?php \wp_nonce_field( 'silver_assist_security_settings', 'silver_assist_security_nonce' ); ?>
				
				<table class="form-table">
					<tbody>
						<!-- IP Blacklist Enable -->
						<tr>
							<th scope="row">
								<?php \esc_html_e( 'IP Blacklist', 'silver-assist-security' ); ?>
							</th>
							<td>
								<label class="toggle-switch">
									<input type="checkbox" 
											id="silver_assist_ip_blacklist_enabled" 
											name="silver_assist_ip_blacklist_enabled" 
											value="1" 
											<?php \checked( $config['ip_blacklist_enabled'], 1 ); ?>>
									<span class="toggle-slider"></span>
								</label>
								<p class="description">
									<?php \esc_html_e( 'Enable automatic IP blacklisting for repeat offenders', 'silver-assist-security' ); ?>
								</p>
							</td>
						</tr>
						
						<!-- Under Attack Mode -->
						<tr>
							<th scope="row">
								<?php \esc_html_e( 'Under Attack Mode', 'silver-assist-security' ); ?>
							</th>
							<td>
								<label class="toggle-switch">
									<input type="checkbox" 
											id="silver_assist_under_attack_enabled" 
											name="silver_assist_under_attack_enabled" 
											value="1" 
											<?php \checked( $config['under_attack_enabled'], 1 ); ?>>
									<span class="toggle-slider"></span>
								</label>
								<p class="description">
									<?php \esc_html_e( 'Enable enhanced protection during active attacks', 'silver-assist-security' ); ?>
								</p>
							</td>
						</tr>
					</tbody>
				</table>
				
				<p class="submit">
					<input type="submit" 
							name="submit" 
							id="submit" 
							class="button button-primary" 
							value="<?php \esc_attr_e( 'Save IP Settings', 'silver-assist-security' ); ?>">
				</p>
			</form>

			<!-- Login Security Blocked IPs Section -->
			<div class="security-threats-section">
				<h3><?php \esc_html_e( 'Login Security - Blocked IPs', 'silver-assist-security' ); ?></h3>
				<div id="blocked-ips-list">
					<p class="loading"><?php \esc_html_e( 'Loading blocked IPs...', 'silver-assist-security' ); ?></p>
				</div>
			</div>

			<!-- CF7 Blocked IPs Section (conditional) -->
			<?php if ( SecurityHelper::is_contact_form_7_active() ) : ?>
			<div class="cf7-security-threats-section">
				<h3><?php \esc_html_e( 'Form Protection - Blocked IPs', 'silver-assist-security' ); ?></h3>
				<div id="cf7-blocked-ips-content">
					<p class="loading"><?php \esc_html_e( 'Loading CF7 blocked IPs...', 'silver-assist-security' ); ?></p>
				</div>
			</div>
			<?php endif; ?>

			<!-- Manual IP Management Section -->
			<div class="manual-ip-management-section">
				<h3><?php \esc_html_e( 'Manual IP Management', 'silver-assist-security' ); ?></h3>
				<div class="add-ip-form">
					<div class="add-ip-row">
						<input type="text" 
								id="manual-ip-address" 
								placeholder="<?php \esc_attr_e( 'Enter IP address (e.g., 192.168.1.100)', 'silver-assist-security' ); ?>" 
								pattern="^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$">
						<input type="text" 
								id="manual-ip-reason" 
								placeholder="<?php \esc_attr_e( 'Reason for blocking', 'silver-assist-security' ); ?>">
						<button type="button" 
								id="add-manual-ip" 
								class="button button-secondary">
							<?php \esc_html_e( 'Block IP', 'silver-assist-security' ); ?>
						</button>
					</div>
					<p class="description">
						<?php \esc_html_e( 'Manually block specific IP addresses. Blocked IPs will be denied access to login and forms.', 'silver-assist-security' ); ?>
					</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Get current configuration values
	 *
	 * @since 1.1.15
	 * @return array Configuration values
	 */
	private function get_current_config(): array {
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
