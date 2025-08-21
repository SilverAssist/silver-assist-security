/**
 * Silver Assist Security Essentials - Admin Panel Scripts
 *
 * JavaScript functionality for the admin configuration panel including
 * form validation, AJAX security settings updates, and interactive
 * security status management.
 *
 * @file admin.js
 * @version 1.1.9
 * @author Silver Assist
 * @requires jQuery
 * @since 1.0.0
 */

(($ => {
    "use strict";

    // ========================================
    // TIMING CONSTANTS
    // ========================================

    /**
     * Admin panel timing constants
     * 
     * Centralized timeout values for consistent user experience
     * and easy maintenance of timing behavior across admin features.
     * 
     * @since 1.1.7
     */
    const TIMING = {
        AUTO_SAVE_DELAY: 2000,          // Auto-save delay after input changes (ms)
        VALIDATION_DEBOUNCE: 500,       // Real-time validation debounce (ms)
        ERROR_DISPLAY: 5000,            // Error message display duration (ms)
        SUCCESS_DISPLAY: 2000,          // Success message display duration (ms)
        LONG_ERROR_DISPLAY: 3000,       // Long error message display duration (ms)
        DASHBOARD_REFRESH: 2000,        // Dashboard refresh button delay (ms)
        DATABASE_UPDATE_DELAY: 500      // Small delay for database update completion (ms)
    };

    /**
     * Form validation constants
     * 
     * Centralized validation limits for all security settings form fields.
     * These values must match the server-side validation limits.
     * 
     * @since 1.1.7
     */
    const VALIDATION_LIMITS = {
        LOGIN_ATTEMPTS: { min: 1, max: 20 },           // Failed login attempts before lockout
        LOCKOUT_DURATION: { min: 60, max: 3600 },     // Lockout duration in seconds (1 min - 1 hour)
        SESSION_TIMEOUT: { min: 5, max: 120 },        // Session timeout in minutes (5 min - 2 hours)
        GRAPHQL_QUERY_DEPTH: { min: 1, max: 20 },     // GraphQL query depth limit
        GRAPHQL_QUERY_COMPLEXITY: { min: 10, max: 1000 }, // GraphQL query complexity limit
        GRAPHQL_QUERY_TIMEOUT: { min: 1, max: null }, // GraphQL timeout (max determined by PHP limit)
        ADMIN_PATH_LENGTH: { min: 3, max: 50 }        // Admin path character length limits
    };

    $(() => {
        // Add security admin class to wrap
        $(".wrap").addClass("silver-assist-security-admin");

        // Initialize form validation
        initFormValidation();

        // Initialize toggle switches
        initToggleSwitches();

        // Initialize tooltips
        initTooltips();

        // Auto-save feature
        initAutoSave();

        // Initialize GraphQL timeout slider
        initGraphQLTimeoutSlider();

        // Initialize admin path validation
        initAdminPathValidation();

        // Initialize dashboard
        initDashboard();
    });

    /**
     * Initialize form validation for security settings
     * 
     * Validates all form inputs including login attempts, session timeout,
     * and GraphQL settings using centralized validation limits.
     * 
     * @since 1.0.0
     * @returns {void}
     */
    const initFormValidation = () => {
        // Use destructuring for cleaner object access
        const { strings = {}, phpExecutionTimeout = 30 } = silverAssistSecurity || {};

        // Destructure validation limits for cleaner code
        const {
            LOGIN_ATTEMPTS,
            LOCKOUT_DURATION,
            SESSION_TIMEOUT,
            GRAPHQL_QUERY_DEPTH,
            GRAPHQL_QUERY_COMPLEXITY,
            GRAPHQL_QUERY_TIMEOUT,
            ADMIN_PATH_LENGTH
        } = VALIDATION_LIMITS;

        $("form").on("submit", e => {
            let isValid = true;
            const errors = [];

            // Validate login attempts using destructured limits
            const loginAttempts = $("#silver_assist_login_attempts").val();
            if (loginAttempts < LOGIN_ATTEMPTS.min || loginAttempts > LOGIN_ATTEMPTS.max) {
                errors.push(strings.loginAttemptsError || `Login attempts must be between ${LOGIN_ATTEMPTS.min} and ${LOGIN_ATTEMPTS.max}`);
                isValid = false;
            }

            // Validate lockout duration using destructured limits
            const lockoutDuration = $("#silver_assist_lockout_duration").val();
            if (lockoutDuration < LOCKOUT_DURATION.min || lockoutDuration > LOCKOUT_DURATION.max) {
                errors.push(strings.lockoutDurationError || `Lockout duration must be between ${LOCKOUT_DURATION.min} and ${LOCKOUT_DURATION.max} seconds`);
                isValid = false;
            }

            // Validate session timeout using destructured limits
            const sessionTimeout = $("#silver_assist_session_timeout").val();
            if (sessionTimeout < SESSION_TIMEOUT.min || sessionTimeout > SESSION_TIMEOUT.max) {
                errors.push(strings.sessionTimeoutError || `Session timeout must be between ${SESSION_TIMEOUT.min} and ${SESSION_TIMEOUT.max} minutes`);
                isValid = false;
            }

            // Validate GraphQL settings if they exist using destructured limits
            const graphqlDepth = $("#silver_assist_graphql_query_depth").val();
            if (graphqlDepth && (graphqlDepth < GRAPHQL_QUERY_DEPTH.min || graphqlDepth > GRAPHQL_QUERY_DEPTH.max)) {
                errors.push(strings.graphqlDepthError || `GraphQL query depth must be between ${GRAPHQL_QUERY_DEPTH.min} and ${GRAPHQL_QUERY_DEPTH.max}`);
                isValid = false;
            }

            const graphqlComplexity = $("#silver_assist_graphql_query_complexity").val();
            if (graphqlComplexity && (graphqlComplexity < GRAPHQL_QUERY_COMPLEXITY.min || graphqlComplexity > GRAPHQL_QUERY_COMPLEXITY.max)) {
                errors.push(strings.graphqlComplexityError || `GraphQL query complexity must be between ${GRAPHQL_QUERY_COMPLEXITY.min} and ${GRAPHQL_QUERY_COMPLEXITY.max}`);
                isValid = false;
            }

            const graphqlTimeout = $("#silver_assist_graphql_query_timeout").val();
            const maxGraphqlTimeout = GRAPHQL_QUERY_TIMEOUT.max || phpExecutionTimeout;
            if (graphqlTimeout && (graphqlTimeout < GRAPHQL_QUERY_TIMEOUT.min || graphqlTimeout > maxGraphqlTimeout)) {
                errors.push(strings.graphqlTimeoutError || `GraphQL query timeout must be between ${GRAPHQL_QUERY_TIMEOUT.min} and ${maxGraphqlTimeout} seconds`);
                isValid = false;
            }

            // Validate admin path if present and admin hide is enabled using destructured limits
            const adminHideEnabled = $("#silver_assist_admin_hide_enabled").is(":checked");
            const adminPath = $("#silver_assist_admin_hide_path").val();

            if (adminHideEnabled && adminPath) {
                // Check if current validation indicator shows invalid state
                const $validationIndicator = $("#admin-path-validation");
                if ($validationIndicator.length && $validationIndicator.hasClass("invalid")) {
                    errors.push(strings.pathForbidden || "Admin path contains invalid characters or forbidden keywords");
                    isValid = false;
                } else if (adminPath.length < ADMIN_PATH_LENGTH.min) {
                    errors.push(strings.pathTooShort || `Admin path must be at least ${ADMIN_PATH_LENGTH.min} characters long`);
                    isValid = false;
                } else if (adminPath.length > ADMIN_PATH_LENGTH.max) {
                    errors.push(strings.pathTooLong || `Admin path must be ${ADMIN_PATH_LENGTH.max} characters or less`);
                    isValid = false;
                }
            }

            if (!isValid) {
                e.preventDefault();
                showValidationErrors(errors);
            }
        });
    };

    /**
     * Display validation errors to the user
     * 
     * Creates and displays error notices for form validation failures.
     * Errors are automatically dismissed after 5 seconds.
     * 
     * @since 1.0.0
     * @param {Array<string>} errors - Array of error messages to display
     * @returns {void}
     */
    const showValidationErrors = errors => {
        // Destructure timing constants for cleaner code
        const { ERROR_DISPLAY } = TIMING;

        let errorHtml = "<div class=\"notice notice-error is-dismissible\"><ul>";
        errors.forEach(error => {
            errorHtml += `<li>${error}</li>`;
        });
        errorHtml += "</ul></div>";

        $(".wrap h1").after(errorHtml);

        // Auto-dismiss after configured time using destructured constant
        setTimeout(() => {
            $(".notice-error").fadeOut();
        }, ERROR_DISPLAY);
    };

    /**
     * Initialize toggle switches for checkbox inputs
     * 
     * Converts standard WordPress checkboxes into styled toggle switches
     * for better user experience in the admin panel.
     * 
     * @since 1.0.0
     * @returns {void}
     */
    const initToggleSwitches = () => {
        // Convert checkboxes to toggle switches
        $("input[type=\"checkbox\"]").each(function () {
            const $checkbox = $(this);
            const $label = $checkbox.closest("label");

            if (!$label.hasClass("silver-assist-toggle")) {
                $label.addClass("silver-assist-toggle");
                $checkbox.after("<span class=\"silver-assist-slider\"></span>");
            }
        });
    };

    /**
     * Initialize tooltips for form inputs
     * 
     * Adds tooltip functionality to form inputs using their description text.
     * Provides additional context for users when hovering over form fields.
     * 
     * @since 1.0.0
     * @returns {void}
     */
    const initTooltips = () => {
        // Add tooltips to description texts
        $(".description").each(function () {
            const $desc = $(this);
            const $input = $desc.closest("td").find("input");

            if ($input.length) {
                $input.attr("title", $desc.text());
            }
        });
    };

    /**
     * Initialize auto-save feature for form changes
     * 
     * Automatically saves form changes after a short delay to improve
     * user experience and prevent data loss.
     * 
     * @since 1.0.0
     * @returns {void}
     */
    const initAutoSave = () => {
        // Destructure timing constants for cleaner code
        const { AUTO_SAVE_DELAY } = TIMING;

        let saveTimeout;
        const $form = $("form");

        $form.find("input, select, textarea").on("change", () => {
            clearTimeout(saveTimeout);

            // Show saving indicator
            showSavingIndicator();

            // Auto-save after configured delay using destructured constant
            saveTimeout = setTimeout(() => {
                autoSaveSettings();
            }, AUTO_SAVE_DELAY);
        });
    };

    /**
     * Display saving indicator to the user
     * 
     * Shows a temporary saving indicator in the top-right corner
     * when auto-save is triggered.
     * 
     * @since 1.0.0
     * @returns {void}
     */
    const showSavingIndicator = () => {
        // Use destructuring for cleaner string access
        const { strings = {} } = silverAssistSecurity || {};

        if (!$(".saving-indicator").length) {
            $("form").append(`<div class="saving-indicator" style="position: fixed; top: 32px; right: 20px; background: #fff; border: 1px solid #ccc; padding: 10px; border-radius: 3px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); z-index: 9999;">${strings.saving || "Saving..."}</div>`);
        }
    };

    /**
     * Auto-save settings via AJAX
     * 
     * Automatically saves form data to the server without requiring
     * a page refresh or manual form submission.
     * 
     * @since 1.0.0
     * @returns {void}
     */
    const autoSaveSettings = () => {
        // Destructure timing constants for cleaner code
        const { SUCCESS_DISPLAY, LONG_ERROR_DISPLAY, DATABASE_UPDATE_DELAY } = TIMING;

        const $form = $("form");
        const formData = {};

        // Serialize form data manually to handle checkboxes correctly
        $form.find("input, select, textarea").each(function () {
            const $field = $(this);
            const name = $field.attr("name");

            if (!name) return;

            if ($field.attr("type") === "checkbox") {
                formData[name] = $field.is(":checked") ? "1" : "";
            } else {
                formData[name] = $field.val();
            }
        });

        // Use destructuring for cleaner object access
        const { ajaxurl, nonce, strings = {} } = silverAssistSecurity || {};

        // Add action and nonce
        formData.action = "silver_assist_auto_save";
        formData.nonce = nonce;

        $.ajax({
            url: ajaxurl,
            type: "POST",
            data: formData,
            success: response => {
                // Use destructuring for response handling
                const { success, data = {} } = response || {};

                if (success) {
                    // Normal save indication using destructured timing
                    $(".saving-indicator")
                        .html(strings.saved || "Saved!")
                        .delay(SUCCESS_DISPLAY)
                        .fadeOut();

                    // Update dashboard to reflect changes immediately
                    setTimeout(() => {
                        loadSecurityStatus();
                        loadLoginStats();
                    }, DATABASE_UPDATE_DELAY);
                } else {
                    // Show error message using destructured timing
                    $(".saving-indicator")
                        .html(data.message || (strings.saveFailed || "Save failed"))
                        .addClass("error")
                        .delay(LONG_ERROR_DISPLAY)
                        .fadeOut();
                }
            },
            error: () => {
                $(".saving-indicator")
                    .html(strings.saveFailed || "Save failed")
                    .addClass("error")
                    .delay(LONG_ERROR_DISPLAY)
                    .fadeOut();
            }
        });
    };

    /**
     * Initialize real-time validation feedback
     * 
     * Provides immediate visual feedback for numeric input fields
     * by validating values against their min/max attributes.
     * 
     * @since 1.0.0
     * @returns {void}
     */
    const initRealTimeValidation = () => {
        $("input[type=\"number\"]").on("input", function () {
            const $input = $(this);
            const value = parseInt($input.val());
            const min = parseInt($input.attr("min"));
            const max = parseInt($input.attr("max"));

            // Remove previous validation classes
            $input.removeClass("valid invalid");

            if (value >= min && value <= max) {
                $input.addClass("valid");
            } else {
                $input.addClass("invalid");
            }
        });
    };

    // Initialize real-time validation
    initRealTimeValidation();

    /**
     * Check for Silver Assist Security Essentials version updates
     * 
     * Displays notifications for available updates via AJAX.
     * Shows update notices in the admin panel when new versions are available.
     * 
     * @since 1.0.0
     * @returns {void}
     */
    const checkSilverAssistVersion = () => {
        // Use destructuring for cleaner object access
        const { ajaxurl, nonce, strings = {} } = silverAssistSecurity || {};

        $.post(ajaxurl, {
            action: "silver_assist_security_check_version",
            nonce: nonce
        }, response => {
            // Use destructuring for response handling
            const { success, data = {} } = response || {};

            if (success && data.update_available) {
                const updateNotice = `<div class="notice notice-info is-dismissible">` +
                    `<p><strong>Silver Assist Security Essentials:</strong> ` +
                    strings.newVersionAvailable.replace("%s", data.latest_version) + ` ` +
                    `<a href="${strings.updateUrl}">${strings.updateNow}</a></p>` +
                    `</div>`;
                $(".wrap h1").after(updateNotice);
            }
        }).fail(() => {
            console.log(strings.updateCheckFailed || "Failed to check for Silver Assist updates");
        });
    };

    // Check for updates on page load
    checkSilverAssistVersion();

    // Handle update check button click
    $(document).on("click", "#check-silver-assist-version", e => {
        e.preventDefault();
        const $button = $(e.target);
        const originalText = $button.text();

        // Use destructuring for cleaner object access
        const { ajaxurl, nonce, strings = {} } = silverAssistSecurity || {};

        $button.text(strings.checking).prop("disabled", true);

        $.post(ajaxurl, {
            action: "silver_assist_security_check_version",
            nonce: nonce
        })
            .done(response => {
                // Use destructuring for response handling
                const { success, data = {} } = response || {};

                if (success) {
                    if (data.update_available) {
                        alert(strings.newVersionFound.replace("%1$s", data.latest_version).replace("%2$s", data.current_version));
                        location.reload(); // Reload to show update notice
                    } else {
                        alert(strings.upToDate.replace("%s", data.current_version));
                    }
                } else {
                    alert(strings.checkError + " " + (data.message || strings.unknownError));
                }
            })
            .fail(() => {
                alert(strings.connectivityError);
            })
            .always(() => {
                $button.text(originalText).prop("disabled", false);
            });
    });

    /**
     * Initialize security dashboard functionality
     * 
     * Sets up the real-time security dashboard with initial data loading,
     * auto-refresh intervals, and manual refresh button handling.
     * 
     * @since 1.1.0
     * @returns {void}
     */
    const initDashboard = () => {
        // Load initial data
        loadSecurityStatus();
        loadLoginStats();
        loadBlockedIPs();

        // Set up auto-refresh
        if (typeof silverAssistSecurity !== "undefined" && silverAssistSecurity.refreshInterval) {
            setInterval(() => {
                loadSecurityStatus();
                loadLoginStats();
                loadBlockedIPs();
            }, silverAssistSecurity.refreshInterval);
        }

        // Manual refresh button
        $("#refresh-dashboard").on("click", e => {
            e.preventDefault();
            refreshDashboard();
        });
    };

    /**
     * Load and display current security status
     * 
     * Fetches current security configuration status via AJAX and updates
     * the dashboard indicators for each security component.
     * 
     * @since 1.0.0
     * @returns {void}
     */
    const loadSecurityStatus = () => {
        if (typeof silverAssistSecurity === "undefined") return;

        // Use destructuring for cleaner object access
        const { ajaxurl, nonce, strings = {} } = silverAssistSecurity || {};

        $.post(ajaxurl, {
            action: "silver_assist_get_security_status",
            nonce: nonce
        }, response => {
            // Use destructuring for response handling
            const { success, data } = response || {};

            if (success) {
                updateSecurityStatusDisplay(data);
            }
        }).fail(() => {
            console.log(strings.securityStatusFailed || "Failed to load security status");
        });
    };

    /**
     * Load and display login statistics
     * 
     * Fetches current login attempt statistics via AJAX and updates
     * the dashboard with failed login counts and security events.
     * 
     * @since 1.0.0
     * @returns {void}
     */
    const loadLoginStats = () => {
        if (typeof silverAssistSecurity === "undefined") return;

        // Use destructuring for cleaner object access
        const { ajaxurl, nonce, strings = {} } = silverAssistSecurity || {};

        $.post(ajaxurl, {
            action: "silver_assist_get_login_stats",
            nonce: nonce
        }, response => {
            // Use destructuring for response handling
            const { success, data } = response || {};

            if (success) {
                updateLoginStatsDisplay(data);
            }
        }).fail(() => {
            console.log(strings.loginStatsFailed || "Failed to load login stats");
        });
    };

    /**
     * Load and display blocked IP addresses
     * 
     * Fetches list of currently blocked IP addresses via AJAX and updates
     * the dashboard with threat information and blocking statistics.
     * 
     * @since 1.0.0
     * @returns {void}
     */
    const loadBlockedIPs = () => {
        if (typeof silverAssistSecurity === "undefined") return;

        // Use destructuring for cleaner object access
        const { ajaxurl, nonce, strings = {} } = silverAssistSecurity || {};

        // Local constant for DOM element used in this function
        const $blockedIpsListSelector = $("#blocked-ips-list");

        $.post(ajaxurl, {
            action: "silver_assist_get_blocked_ips",
            nonce: nonce
        }, response => {
            // Use destructuring for response handling
            const { success, data } = response || {};

            if (success) {
                updateBlockedIPsDisplay(data);
            } else {
                $blockedIpsListSelector.html(`<p class="no-threats">${strings.noThreats || "No active threats detected"}</p>`);
            }
        }).fail(() => {
            
            $blockedIpsListSelector.html(`<p class="error">${strings.error || "Error loading data"}</p>`);
        });
    };

    /**
     * Update security status display indicators
     * 
     * Updates the visual security status indicators on the dashboard
     * based on current security configuration and compliance status.
     * 
     * @since 1.0.0
     * @param {Object} data - Security status data object containing status information
     * @returns {void}
     */
    const updateSecurityStatusDisplay = data => {
        if (!data) return;

        // Update status indicators with correct selectors
        $("#login-status").text(data.login_security.status).removeClass().addClass("status-indicator " + data.login_security.status);
        $("#admin-status").text(data.admin_security.status).removeClass().addClass("status-indicator " + data.admin_security.status);
        $("#graphql-status").text(data.graphql_security.status).removeClass().addClass("status-indicator " + data.graphql_security.status);
        $("#general-status").text(data.general_security.status).removeClass().addClass("status-indicator " + data.general_security.status);

        // Update dynamic values that can change with settings
        updateDynamicDashboardValues(data);

        // Update last updated time
        updateLastUpdatedTime();
    };

    /**
     * Update dynamic dashboard values based on current settings
     * 
     * Updates specific dashboard elements that reflect current configuration
     * settings like max attempts, lockout duration, and feature statuses.
     * 
     * @since 1.0.3
     * @param {Object} data - Security status data object
     * @returns {void}
     */
    const updateDynamicDashboardValues = data => {
        if (!data) return;

        // Use destructuring for cleaner object access
        const { strings = {} } = silverAssistSecurity || {};

        // Update Login Security panel values
        if (data.login_security) {
            // Use destructuring for nested data
            const { max_attempts, lockout_duration } = data.login_security;

            // Update Max Attempts value
            const $maxAttemptsElement = $(".login-security .stat:first-child .stat-value");
            if ($maxAttemptsElement.length) {
                $maxAttemptsElement.text(max_attempts);
            }

            // Update Lockout duration
            const $lockoutElement = $(".login-security .stat:last-child .stat-value");
            if ($lockoutElement.length && lockout_duration) {
                $lockoutElement.text(Math.round(lockout_duration / 60));
            }
        }

        // Update Admin Security panel feature statuses
        if (data.admin_security) {
            // Use destructuring for nested data
            const { password_strength_enforcement, bot_protection } = data.admin_security;

            // Update Password Strength Enforcement status
            const $passwordElement = $(".admin-security .feature-status:first-child .feature-value");
            if ($passwordElement.length) {
                $passwordElement
                    .removeClass("enabled disabled")
                    .addClass(password_strength_enforcement ? "enabled" : "disabled")
                    .text(password_strength_enforcement ?
                        (strings.enabled || "Enabled") :
                        (strings.disabled || "Disabled"));
            }

            // Update Bot Protection status
            const $botElement = $(".admin-security .feature-status:last-child .feature-value");
            if ($botElement.length) {
                $botElement
                    .removeClass("enabled disabled")
                    .addClass(bot_protection ? "enabled" : "disabled")
                    .text(bot_protection ?
                        (strings.enabled || "Enabled") :
                        (strings.disabled || "Disabled"));
            }
        }

        // Update GraphQL Security panel if enabled
        if (data.graphql_security && data.graphql_security.enabled) {
            // Use destructuring for nested data
            const {
                headless_mode,
                query_depth_limit,
                query_complexity_limit,
                query_timeout
            } = data.graphql_security;

            // Update headless mode indicator
            const $headlessModeElement = $(".graphql-security .mode-value");
            if ($headlessModeElement.length) {
                $headlessModeElement
                    .removeClass("headless standard")
                    .addClass(headless_mode ? "headless" : "standard")
                    .text(headless_mode ?
                        (strings.headlessCms || "Headless CMS") :
                        (strings.standard || "Standard"));
            }

            // Update query depth, complexity, and timeout values
            $(".graphql-security .stat").each(function (index) {
                const $statValue = $(this).find(".stat-value");
                if ($statValue.length) {
                    switch (index) {
                        case 0: // Max Depth
                            $statValue.text(query_depth_limit);
                            break;
                        case 1: // Max Complexity
                            $statValue.text(query_complexity_limit);
                            break;
                        case 2: // Timeout
                            $statValue.text(query_timeout + "s");
                            break;
                    }
                }
            });
        }

        // Update General Security panel SSL status
        if (data.general_security) {
            // Use destructuring for nested data
            const { ssl_enabled } = data.general_security;

            // Find the SSL/HTTPS feature status (4th feature-status div in general-security)
            const $sslElement = $(".general-security .feature-status:nth-child(4) .feature-value");
            if ($sslElement.length) {
                $sslElement
                    .removeClass("enabled disabled")
                    .addClass(ssl_enabled ? "enabled" : "disabled")
                    .text(ssl_enabled ?
                        (strings.enabled || "Enabled") :
                        (strings.disabled || "Disabled"));
            }
        }
    };

    /**
     * Update login statistics display
     * 
     * Updates the dashboard with current login attempt statistics
     * including failed attempts and threat counts.
     * 
     * @since 1.0.0
     * @param {Object} data - Login statistics data object
     * @returns {void}
     */
    const updateLoginStatsDisplay = data => {
        if (!data) return;

        $("#recent-attempts").text(data.blocked_ips_count);
        $("#threat-count").text(data.blocked_ips_count);
    };

    /**
     * Update blocked IP addresses display
     * 
     * Updates the dashboard table with currently blocked IP addresses,
     * including hashed IP values, block times, and remaining duration.
     * 
     * @since 1.0.0
     * @param {Array} data - Array of blocked IP data objects
     * @returns {void}
     */
    const updateBlockedIPsDisplay = data => {
        const $container = $("#blocked-ips-list");
        const $threatCountSelector = $("#threat-count");

        // Use destructuring for cleaner object access
        const { strings = {} } = silverAssistSecurity || {};

        if (!data || data.length === 0) {
            $container.html(`<p class="no-threats">${strings.noThreats || "No active threats detected"}</p>`);
            $threatCountSelector.text("0");
            return;
        }

        let html = "<div class=\"blocked-ips-table\">";
        html += "<table class=\"wp-list-table widefat fixed striped\">";
        html += `<thead><tr><th>${strings.ipHash}</th><th>${strings.blockedTime}</th><th>${strings.remaining}</th></tr></thead>`;
        html += "<tbody>";

        data.forEach(ip => {
            // Use destructuring for cleaner object access
            const { hash, blocked_at, remaining_minutes } = ip;

            html += "<tr>";
            html += `<td>${hash.substring(0, 8)}...</td>`;
            html += `<td>${blocked_at}</td>`;
            html += `<td>${remaining_minutes} ${strings.minutes}</td>`;
            html += "</tr>";
        });

        html += "</tbody></table></div>";
        $container.html(html);
        $threatCountSelector.text(data.length);
    };

    /**
     * Refresh security dashboard data
     * 
     * Manually triggers a refresh of all dashboard components including
     * security status, login statistics, and blocked IP addresses.
     * 
     * @since 1.0.0
     * @returns {void}
     */
    const refreshDashboard = () => {
        // Destructure timing constants for cleaner code
        const { DASHBOARD_REFRESH } = TIMING;

        const $button = $("#refresh-dashboard");
        const originalText = $button.text();

        $button.text(silverAssistSecurity.strings.loading || "Loading...").prop("disabled", true);

        loadSecurityStatus();
        loadLoginStats();
        loadBlockedIPs();

        setTimeout(() => {
            $button.text(originalText).prop("disabled", false);
        }, DASHBOARD_REFRESH);
    };

    /**
     * Update last updated timestamp display
     * 
     * Updates the dashboard "last updated" time indicator to show
     * when the dashboard data was last refreshed.
     * 
     * @since 1.0.0
     * @returns {void}
     */
    const updateLastUpdatedTime = () => {
        const now = new Date();
        const timeString = now.toLocaleTimeString();
        $("#last-updated-time").text(timeString);
    };

    /**
     * Initialize GraphQL timeout slider functionality
     * 
     * Sets up the range slider for GraphQL query timeout configuration
     * with real-time value display and PHP limit awareness.
     * 
     * @since 1.1.0
     * @returns {void}
     */
    const initGraphQLTimeoutSlider = () => {
        const $timeoutSlider = $("#silver_assist_graphql_query_timeout");
        const $timeoutDisplay = $("#graphql-timeout-value");

        if ($timeoutSlider.length && $timeoutDisplay.length) {
            // Update display value when slider changes
            $timeoutSlider.on("input", function () {
                $timeoutDisplay.text($(this).val());
            });

            // Update validation on change
            $timeoutSlider.on("change", function () {
                const value = parseInt($(this).val());
                const maxValue = parseInt($(this).attr("max"));

                if (value > maxValue) {
                    $(this).val(maxValue);
                    $timeoutDisplay.text(maxValue);

                    // Show warning
                    const warningMessage = "GraphQL timeout cannot exceed PHP execution time limit (" + maxValue + "s)";
                    showValidationErrors([warningMessage]);
                }
            });
        }
    };

    /**
     * Initialize real-time admin path validation
     * 
     * Provides instant feedback for admin path input validation
     * while the user types, without requiring form submission.
     * 
     * @since 1.1.4
     * @returns {void}
     */
    const initAdminPathValidation = () => {
        // Destructure timing constants for cleaner code
        const { VALIDATION_DEBOUNCE } = TIMING;

        const $pathInput = $("#silver_assist_admin_hide_path");

        if (!$pathInput.length) {
            return; // Admin path input not found
        }

        let validationTimeout;
        let $validationIndicator = null;

        // Create validation indicator element
        const createValidationIndicator = () => {
            if (!$validationIndicator) {
                $validationIndicator = $(`<div id="admin-path-validation" class="validation-indicator"></div>`);
                $pathInput.after($validationIndicator);
            }
            return $validationIndicator;
        };

        // Update validation indicator
        const updateValidationIndicator = (type, message) => {
            const $indicator = createValidationIndicator();

            $indicator.removeClass("validating valid invalid")
                .addClass(type)
                .html(message);

            // Update input styling
            $pathInput.removeClass("validation-valid validation-invalid validation-validating")
                .addClass(`validation-${type}`);

            // Update preview URL if valid
            if (type === "valid" && message.includes("✓")) {
                updatePathPreview($pathInput.val());
            }
        };

        // Update path preview URL
        const updatePathPreview = (path) => {
            const $previewElement = $("code:contains('" + window.location.origin + "')").first();
            if ($previewElement.length && path) {
                const sanitizedPath = path.toLowerCase().replace(/[^a-zA-Z0-9-_]/g, "");
                const homeUrl = window.location.origin;
                $previewElement.text(`${homeUrl}/${sanitizedPath}`);
            }
        };

        // Validate path via AJAX
        const validatePath = (path) => {
            if (!path || path.length === 0) {
                updateValidationIndicator("invalid", silverAssistSecurity.strings.pathEmpty || "Path cannot be empty");
                return;
            }

            // Show validating state
            updateValidationIndicator("validating", silverAssistSecurity.strings.pathValidating || "Validating...");

            $.ajax({
                url: silverAssistSecurity.ajaxurl,
                type: "POST",
                data: {
                    action: "silver_assist_validate_admin_path",
                    nonce: silverAssistSecurity.nonce,
                    path: path
                },
                success: response => {
                    if (response.success) {
                        updateValidationIndicator("valid", silverAssistSecurity.strings.pathValid || "✓ Path is valid");
                        updatePathPreview(response.data.sanitized_path);
                    } else {
                        let errorMessage = response.data.message;

                        // Use localized error messages based on error type
                        switch (response.data.type) {
                            case "empty":
                                errorMessage = silverAssistSecurity.strings.pathEmpty || errorMessage;
                                break;
                            case "too_short":
                                errorMessage = silverAssistSecurity.strings.pathTooShort || errorMessage;
                                break;
                            case "too_long":
                                errorMessage = silverAssistSecurity.strings.pathTooLong || errorMessage;
                                break;
                            case "forbidden":
                                errorMessage = silverAssistSecurity.strings.pathForbidden || errorMessage;
                                break;
                            case "invalid_chars":
                                errorMessage = silverAssistSecurity.strings.pathInvalidChars || errorMessage;
                                break;
                        }

                        updateValidationIndicator("invalid", `✗ ${errorMessage}`);
                    }
                },
                error: () => {
                    updateValidationIndicator("invalid", "✗ " + (silverAssistSecurity.strings.error || "Validation error"));
                }
            });
        };

        // Attach real-time validation using destructured timing constant
        $pathInput.on("input", function () {
            const path = $(this).val().trim();

            // Clear previous validation timeout
            clearTimeout(validationTimeout);

            // Set new validation timeout using destructured constant
            validationTimeout = setTimeout(() => {
                validatePath(path);
            }, VALIDATION_DEBOUNCE);
        });

        // Validate on focus lost
        $pathInput.on("blur", function () {
            const path = $(this).val().trim();
            clearTimeout(validationTimeout);
            if (path) {
                validatePath(path);
            }
        });

        // Initial validation if field has value
        if ($pathInput.val()) {
            validatePath($pathInput.val());
        }
    };

}))(jQuery);
