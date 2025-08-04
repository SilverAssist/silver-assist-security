<?php
/**
 * Silver Assist Security Suite - Admin Panel Interface
 *
 * Handles the WordPress admin interface for security configuration including
 * login settings, password policies, GraphQL limits, and security status display.
 * Provides comprehensive settings management and validation.
 *
 * @package SilverAssist\Security\Admin
 * @since 1.0.0
 * @author Silver Assist
 * @version 1.0.0
 */

namespace SilverAssist\Security\Admin;

/**
 * Admin Panel class
 * 
 * Handles the WordPress admin interface for security configuration
 * 
 * @since 1.0.0
 */
class AdminPanel {
    
    /**
     * Constructor
     * 
     * @since 1.0.0
     */
    public function __construct() {
        $this->init();
    }
    
    /**
     * Initialize admin panel
     * 
     * @since 1.0.0
     * @return void
     */
    private function init(): void {
        \add_action("admin_menu", [$this, "add_admin_menu"]);
        \add_action("admin_init", [$this, "register_settings"]);
        \add_action("admin_init", [$this, "save_security_settings"]);
        \add_action("admin_enqueue_scripts", [$this, "enqueue_admin_scripts"]);
    }
    
    /**
     * Add admin menu item
     * 
     * @since 1.0.0
     * @return void
     */
    public function add_admin_menu(): void {
        \add_options_page(
            \__("Silver Assist Security", "silver-assist-security"),
            \__("Security Suite", "silver-assist-security"),
            "manage_options",
            "silver-assist-security",
            [$this, "render_admin_page"]
        );
    }
    
    /**
     * Register plugin settings
     * 
     * @since 1.0.0
     * @return void
     */
    public function register_settings(): void {
        // Login Security Settings
        \register_setting("silver_assist_security_login", "silver_assist_login_attempts");
        \register_setting("silver_assist_security_login", "silver_assist_lockout_duration");
        \register_setting("silver_assist_security_login", "silver_assist_session_timeout");
        
        // Password Settings
        \register_setting("silver_assist_security_password", "silver_assist_password_reset_enforcement");
        \register_setting("silver_assist_security_password", "silver_assist_password_strength_enforcement");
        \register_setting("silver_assist_security_password", "silver_assist_admin_password_reset");
        
        // GraphQL Settings
        \register_setting("silver_assist_security_graphql", "silver_assist_graphql_query_depth");
        \register_setting("silver_assist_security_graphql", "silver_assist_graphql_query_complexity");
        \register_setting("silver_assist_security_graphql", "silver_assist_graphql_query_timeout");
    }
    
    /**
     * Enqueue admin scripts and styles
     * 
     * @since 1.0.0
     * @param string $hook_suffix Current admin page hook suffix
     * @return void
     */
    public function enqueue_admin_scripts(string $hook_suffix): void {
        if ($hook_suffix !== "settings_page_silver-assist-security") {
            return;
        }
        
        \wp_enqueue_style(
            "silver-assist-security-admin",
            SILVER_ASSIST_SECURITY_URL . "assets/css/admin.css",
            [],
            SILVER_ASSIST_SECURITY_VERSION
        );
        
        \wp_enqueue_script(
            "silver-assist-security-admin",
            SILVER_ASSIST_SECURITY_URL . "assets/js/admin.js",
            ["jquery"],
            SILVER_ASSIST_SECURITY_VERSION,
            true
        );
    }
    
    /**
     * Save security settings
     * 
     * @since 1.0.0
     * @return void
     */
    public function save_security_settings(): void {
        if (!isset($_POST["save_silver_assist_security"]) || !\current_user_can("manage_options")) {
            return;
        }
        
        // Verify nonce
        if (!\wp_verify_nonce($_POST["_wpnonce"], "silver_assist_security_settings")) {
            \wp_die(\__("Security check failed.", "silver-assist-security"));
        }
        
        // Save login security settings
        if (isset($_POST["silver_assist_login_attempts"])) {
            $login_attempts = intval($_POST["silver_assist_login_attempts"]);
            $login_attempts = max(1, min(20, $login_attempts));
            \update_option("silver_assist_login_attempts", $login_attempts);
        }
        
        if (isset($_POST["silver_assist_lockout_duration"])) {
            $lockout_duration = intval($_POST["silver_assist_lockout_duration"]);
            $lockout_duration = max(60, min(3600, $lockout_duration));
            \update_option("silver_assist_lockout_duration", $lockout_duration);
        }
        
        if (isset($_POST["silver_assist_session_timeout"])) {
            $session_timeout = intval($_POST["silver_assist_session_timeout"]);
            $session_timeout = max(5, min(120, $session_timeout));
            \update_option("silver_assist_session_timeout", $session_timeout);
        }
        
        // Save password settings
        \update_option("silver_assist_password_reset_enforcement", isset($_POST["silver_assist_password_reset_enforcement"]) ? 1 : 0);
        \update_option("silver_assist_password_strength_enforcement", isset($_POST["silver_assist_password_strength_enforcement"]) ? 1 : 0);
        \update_option("silver_assist_admin_password_reset", isset($_POST["silver_assist_admin_password_reset"]) ? 1 : 0);
        
        // Save GraphQL settings
        if (isset($_POST["silver_assist_graphql_query_depth"])) {
            $query_depth = intval($_POST["silver_assist_graphql_query_depth"]);
            $query_depth = max(1, min(20, $query_depth));
            \update_option("silver_assist_graphql_query_depth", $query_depth);
        }
        
        if (isset($_POST["silver_assist_graphql_query_complexity"])) {
            $query_complexity = intval($_POST["silver_assist_graphql_query_complexity"]);
            $query_complexity = max(10, min(1000, $query_complexity));
            \update_option("silver_assist_graphql_query_complexity", $query_complexity);
        }
        
        if (isset($_POST["silver_assist_graphql_query_timeout"])) {
            $query_timeout = intval($_POST["silver_assist_graphql_query_timeout"]);
            $query_timeout = max(1, min(30, $query_timeout));
            \update_option("silver_assist_graphql_query_timeout", $query_timeout);
        }
        
        // Add success message
        \add_action("admin_notices", function() {
            echo "<div class=\"notice notice-success is-dismissible\">";
            echo "<p>" . \__("Security settings have been saved successfully.", "silver-assist-security") . "</p>";
            echo "</div>";
        });
    }
    
    /**
     * Render admin page
     * 
     * @since 1.0.0
     * @return void
     */
    public function render_admin_page(): void {
        // Get current values
        $login_attempts = \get_option("silver_assist_login_attempts", 5);
        $lockout_duration = \get_option("silver_assist_lockout_duration", 900);
        $session_timeout = \get_option("silver_assist_session_timeout", 30);
        $password_reset_enforcement = \get_option("silver_assist_password_reset_enforcement", 1);
        $password_strength_enforcement = \get_option("silver_assist_password_strength_enforcement", 1);
        $admin_password_reset = \get_option("silver_assist_admin_password_reset", 0);
        $graphql_query_depth = \get_option("silver_assist_graphql_query_depth", 8);
        $graphql_query_complexity = \get_option("silver_assist_graphql_query_complexity", 100);
        $graphql_query_timeout = \get_option("silver_assist_graphql_query_timeout", 5);
        
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(__('Silver Assist Security Suite', 'silver-assist-security')); ?></h1>
            
            <form method="post" action="">
                <?php wp_nonce_field('silver_assist_security_settings'); ?>
                
                <!-- Login Security Settings -->
                <div class="card">
                    <h2><?php esc_html_e('Login Security Settings', 'silver-assist-security'); ?></h2>
                    <table class="form-table">
                        <tr>
                            <th scope="row">
                                <label for="silver_assist_login_attempts">
                                    <?php esc_html_e('Maximum Login Attempts', 'silver-assist-security'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="number" id="silver_assist_login_attempts" 
                                       name="silver_assist_login_attempts" 
                                       value="<?php echo esc_attr($login_attempts); ?>" 
                                       min="1" max="20" class="small-text" />
                                <p class="description">
                                    <?php esc_html_e('Number of failed login attempts before lockout (1-20)', 'silver-assist-security'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="silver_assist_lockout_duration">
                                    <?php esc_html_e('Lockout Duration (seconds)', 'silver-assist-security'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="number" id="silver_assist_lockout_duration" 
                                       name="silver_assist_lockout_duration" 
                                       value="<?php echo esc_attr($lockout_duration); ?>" 
                                       min="60" max="3600" class="small-text" />
                                <p class="description">
                                    <?php esc_html_e('How long to lock out users after failed attempts (60-3600 seconds)', 'silver-assist-security'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="silver_assist_session_timeout">
                                    <?php esc_html_e('Session Timeout (minutes)', 'silver-assist-security'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="number" id="silver_assist_session_timeout" 
                                       name="silver_assist_session_timeout" 
                                       value="<?php echo esc_attr($session_timeout); ?>" 
                                       min="5" max="120" class="small-text" />
                                <p class="description">
                                    <?php esc_html_e('Session timeout duration in minutes (5-120)', 'silver-assist-security'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                </div>
                
                <!-- Password Security Settings -->
                <div class="card">
                    <h2><?php esc_html_e('Password Security Settings', 'silver-assist-security'); ?></h2>
                    <table class="form-table">
                        <tr>
                            <th scope="row">
                                <?php esc_html_e('Password Reset Enforcement', 'silver-assist-security'); ?>
                            </th>
                            <td>
                                <label>
                                    <input type="checkbox" name="silver_assist_password_reset_enforcement" 
                                           value="1" <?php checked($password_reset_enforcement, 1); ?> />
                                    <?php esc_html_e('Force users to reset passwords on next login', 'silver-assist-security'); ?>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <?php esc_html_e('Password Strength Enforcement', 'silver-assist-security'); ?>
                            </th>
                            <td>
                                <label>
                                    <input type="checkbox" name="silver_assist_password_strength_enforcement" 
                                           value="1" <?php checked($password_strength_enforcement, 1); ?> />
                                    <?php esc_html_e('Enforce strong password requirements', 'silver-assist-security'); ?>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <?php esc_html_e('Admin Password Reset', 'silver-assist-security'); ?>
                            </th>
                            <td>
                                <label>
                                    <input type="checkbox" name="silver_assist_admin_password_reset" 
                                           value="1" <?php checked($admin_password_reset, 1); ?> />
                                    <?php esc_html_e('Allow admin password reset via email', 'silver-assist-security'); ?>
                                </label>
                            </td>
                        </tr>
                    </table>
                </div>
                
                <!-- GraphQL Security Settings -->
                <?php if (class_exists('WPGraphQL')): ?>
                <div class="card">
                    <h2><?php esc_html_e('GraphQL Security Settings', 'silver-assist-security'); ?></h2>
                    <table class="form-table">
                        <tr>
                            <th scope="row">
                                <label for="silver_assist_graphql_query_depth">
                                    <?php esc_html_e('Maximum Query Depth', 'silver-assist-security'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="number" id="silver_assist_graphql_query_depth" 
                                       name="silver_assist_graphql_query_depth" 
                                       value="<?php echo esc_attr($graphql_query_depth); ?>" 
                                       min="1" max="20" class="small-text" />
                                <p class="description">
                                    <?php esc_html_e('Maximum allowed GraphQL query depth (1-20)', 'silver-assist-security'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="silver_assist_graphql_query_complexity">
                                    <?php esc_html_e('Maximum Query Complexity', 'silver-assist-security'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="number" id="silver_assist_graphql_query_complexity" 
                                       name="silver_assist_graphql_query_complexity" 
                                       value="<?php echo esc_attr($graphql_query_complexity); ?>" 
                                       min="10" max="1000" class="small-text" />
                                <p class="description">
                                    <?php esc_html_e('Maximum allowed GraphQL query complexity (10-1000)', 'silver-assist-security'); ?>
                                </p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="silver_assist_graphql_query_timeout">
                                    <?php esc_html_e('Query Timeout (seconds)', 'silver-assist-security'); ?>
                                </label>
                            </th>
                            <td>
                                <input type="number" id="silver_assist_graphql_query_timeout" 
                                       name="silver_assist_graphql_query_timeout" 
                                       value="<?php echo esc_attr($graphql_query_timeout); ?>" 
                                       min="1" max="30" class="small-text" />
                                <p class="description">
                                    <?php esc_html_e('Maximum GraphQL query execution time (1-30 seconds)', 'silver-assist-security'); ?>
                                </p>
                            </td>
                        </tr>
                    </table>
                </div>
                <?php endif; ?>
                
                <?php submit_button(__('Save Security Settings', 'silver-assist-security'), 'primary', 'save_silver_assist_security'); ?>
            </form>
            
            <!-- Updates Information Section -->
            <?php $this->render_updates_section(); ?>
        </div>
        
        <style>
        .card {
            background: #fff;
            border: 1px solid #c3c4c7;
            border-radius: 4px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 1px 1px rgba(0,0,0,.04);
        }
        .card h2 {
            margin-top: 0;
            margin-bottom: 15px;
            font-size: 18px;
            font-weight: 600;
            color: #1d2327;
        }
        </style>
        <?php
    }
    
    /**
     * Render updates information section
     * 
     * @since 1.0.0
     * @return void
     */
    private function render_updates_section(): void {
        // Get updater instance from Plugin
        $plugin = \SilverAssist\Security\Core\Plugin::getInstance();
        $updater = $plugin->get_updater();
        
        if (!$updater) {
            return;
        }
        
        $current_version = $updater->get_current_version();
        $latest_version = $updater->get_latest_version();
        $update_available = $updater->is_update_available();
        $github_repo = $updater->get_github_repo();
        
        ?>
        <div class="card">
            <h2><?php echo \esc_html(\__("Plugin Updates", "silver-assist-security")); ?></h2>
            <table class="form-table">
                <tr>
                    <th scope="row"><?php echo \esc_html(\__("Current Version", "silver-assist-security")); ?></th>
                    <td><?php echo \esc_html($current_version); ?></td>
                </tr>
                <tr>
                    <th scope="row"><?php echo \esc_html(\__("Latest Version", "silver-assist-security")); ?></th>
                    <td>
                        <?php echo \esc_html($latest_version ?: "Unknown"); ?>
                        <?php if ($update_available): ?>
                            <span class="dashicons dashicons-update" style="color: #d63638;"></span>
                            <strong style="color: #d63638;"><?php echo \esc_html(\__("Update Available!", "silver-assist-security")); ?></strong>
                        <?php else: ?>
                            <span class="dashicons dashicons-yes-alt" style="color: #00a32a;"></span>
                            <span style="color: #00a32a;"><?php echo \esc_html(\__("Up to date", "silver-assist-security")); ?></span>
                        <?php endif; ?>
                    </td>
                </tr>
                <tr>
                    <th scope="row"><?php echo \esc_html(\__("Repository", "silver-assist-security")); ?></th>
                    <td>
                        <a href="https://github.com/<?php echo \esc_attr($github_repo); ?>" target="_blank">
                            <?php echo \esc_html($github_repo); ?>
                        </a>
                    </td>
                </tr>
            </table>

            <p class="submit">
                <button type="button" class="button button-secondary" onclick="checkSilverAssistVersion()">
                    <?php echo \esc_html(\__("Check for Updates", "silver-assist-security")); ?>
                </button>
                <?php if ($update_available): ?>
                    <a href="<?php echo \esc_url(\admin_url("update-core.php")); ?>" class="button button-primary">
                        <?php echo \esc_html(\__("Go to Updates", "silver-assist-security")); ?>
                    </a>
                <?php endif; ?>
            </p>
        </div>

        <script>
        function checkSilverAssistVersion() {
            const button = event.target;
            button.textContent = '<?php echo \esc_js(\__("Checking...", "silver-assist-security")); ?>';
            button.disabled = true;

            fetch(ajaxurl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    action: 'silver_assist_security_check_version'
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                } else {
                    alert('<?php echo \esc_js(\__("Failed to check for updates", "silver-assist-security")); ?>');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('<?php echo \esc_js(\__("Failed to check for updates", "silver-assist-security")); ?>');
            })
            .finally(() => {
                button.textContent = '<?php echo \esc_js(\__("Check for Updates", "silver-assist-security")); ?>';
                button.disabled = false;
            });
        }
        </script>
        <?php
    }
}
