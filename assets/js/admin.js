/**
 * Silver Assist Security Essentials - Admin Panel Scripts
 *
 * JavaScript functionality for the admin configuration panel including
 * form validation, AJAX security settings updates, and interactive
 * security status management.
 *
 * @file admin.js
 * @version 1.0.2
 * @author Silver Assist
 * @requires jQuery
 * @since 1.0.0
 */

(($ => {
    "use strict";

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

        // Initialize dashboard
        initDashboard();
    });

    /**
     * Initialize form validation for security settings
     * 
     * Validates all form inputs including login attempts, session timeout,
     * and GraphQL settings.
     * 
     * @since 1.0.0
     * @returns {void}
     */
    const initFormValidation = () => {
        $("form").on("submit", e => {
            let isValid = true;
            const errors = [];

            // Validate login attempts
            const loginAttempts = $("#silver_assist_login_attempts").val();
            if (loginAttempts < 1 || loginAttempts > 20) {
                errors.push(silverAssistSecurity.strings.loginAttemptsError || "Login attempts must be between 1 and 20");
                isValid = false;
            }

            // Validate lockout duration
            const lockoutDuration = $("#silver_assist_lockout_duration").val();
            if (lockoutDuration < 60 || lockoutDuration > 3600) {
                errors.push(silverAssistSecurity.strings.lockoutDurationError || "Lockout duration must be between 60 and 3600 seconds");
                isValid = false;
            }

            // Validate session timeout
            const sessionTimeout = $("#silver_assist_session_timeout").val();
            if (sessionTimeout < 5 || sessionTimeout > 120) {
                errors.push(silverAssistSecurity.strings.sessionTimeoutError || "Session timeout must be between 5 and 120 minutes");
                isValid = false;
            }

            // Validate GraphQL settings if they exist
            const graphqlDepth = $("#silver_assist_graphql_query_depth").val();
            if (graphqlDepth && (graphqlDepth < 1 || graphqlDepth > 20)) {
                errors.push(silverAssistSecurity.strings.graphqlDepthError || "GraphQL query depth must be between 1 and 20");
                isValid = false;
            }

            const graphqlComplexity = $("#silver_assist_graphql_query_complexity").val();
            if (graphqlComplexity && (graphqlComplexity < 10 || graphqlComplexity > 1000)) {
                errors.push(silverAssistSecurity.strings.graphqlComplexityError || "GraphQL query complexity must be between 10 and 1000");
                isValid = false;
            }

            const graphqlTimeout = $("#silver_assist_graphql_query_timeout").val();
            if (graphqlTimeout && (graphqlTimeout < 1 || graphqlTimeout > 30)) {
                errors.push(silverAssistSecurity.strings.graphqlTimeoutError || "GraphQL query timeout must be between 1 and 30 seconds");
                isValid = false;
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
        let errorHtml = "<div class=\"notice notice-error is-dismissible\"><ul>";
        errors.forEach(error => {
            errorHtml += `<li>${error}</li>`;
        });
        errorHtml += "</ul></div>";

        $(".wrap h1").after(errorHtml);

        // Auto-dismiss after 5 seconds
        setTimeout(() => {
            $(".notice-error").fadeOut();
        }, 5000);
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
        let saveTimeout;
        const $form = $("form");

        $form.find("input, select, textarea").on("change", () => {
            clearTimeout(saveTimeout);

            // Show saving indicator
            showSavingIndicator();

            // Auto-save after 2 seconds of inactivity
            saveTimeout = setTimeout(() => {
                autoSaveSettings();
            }, 2000);
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
        if (!$(".saving-indicator").length) {
            $("form").append(`<div class="saving-indicator" style="position: fixed; top: 32px; right: 20px; background: #fff; border: 1px solid #ccc; padding: 10px; border-radius: 3px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); z-index: 9999;">${silverAssistSecurity.strings.saving || "Saving..."}</div>`);
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

        // Add action and nonce
        formData.action = "silver_assist_auto_save";
        formData.nonce = silverAssistSecurity.nonce;

        $.ajax({
            url: silverAssistSecurity.ajaxurl,
            type: "POST",
            data: formData,
            success: response => {
                if (response.success) {
                    // Normal save indication
                    $(".saving-indicator")
                        .html(silverAssistSecurity.strings.saved || "Saved!")
                        .delay(2000)
                        .fadeOut();
                } else {
                    // Show error message
                    $(".saving-indicator")
                        .html(response.data.message || (silverAssistSecurity.strings.saveFailed || "Save failed"))
                        .addClass("error")
                        .delay(3000)
                        .fadeOut();
                }
            },
            error: () => {
                $(".saving-indicator")
                    .html(silverAssistSecurity.strings.saveFailed || "Save failed")
                    .addClass("error")
                    .delay(3000)
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
        $.post(silverAssistSecurity.ajaxurl, {
            action: "silver_assist_security_check_version",
            nonce: silverAssistSecurity.nonce
        }, response => {
            if (response.success && response.data.update_available) {
                const updateNotice = `<div class="notice notice-info is-dismissible">` +
                    `<p><strong>Silver Assist Security Essentials:</strong> ` + 
                    silverAssistSecurity.strings.newVersionAvailable.replace("%s", response.data.latest_version) + ` ` +
                    `<a href="${silverAssistSecurity.strings.updateUrl}">${silverAssistSecurity.strings.updateNow}</a></p>` +
                    `</div>`;
                $(".wrap h1").after(updateNotice);
            }
        }).fail(() => {
            console.log(silverAssistSecurity.strings.updateCheckFailed || "Failed to check for Silver Assist updates");
        });
    };

    // Check for updates on page load
    checkSilverAssistVersion();

    // Handle update check button click
    $(document).on("click", "#check-silver-assist-version", e => {
        e.preventDefault();
        const $button = $(e.target);
        const originalText = $button.text();
        
        $button.text(silverAssistSecurity.strings.checking).prop("disabled", true);
        
        $.post(silverAssistSecurity.ajaxurl, {
            action: "silver_assist_security_check_version",
            nonce: silverAssistSecurity.nonce
        })
        .done(response => {
            if (response.success) {
                if (response.data.update_available) {
                    alert(silverAssistSecurity.strings.newVersionFound.replace("%1$s", response.data.latest_version).replace("%2$s", response.data.current_version));
                    location.reload(); // Reload to show update notice
                } else {
                    alert(silverAssistSecurity.strings.upToDate.replace("%s", response.data.current_version));
                }
            } else {
                alert(silverAssistSecurity.strings.checkError + " " + (response.data.message || silverAssistSecurity.strings.unknownError));
            }
        })
        .fail(() => {
            alert(silverAssistSecurity.strings.connectivityError);
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
     * @since 1.0.0
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

        $.post(silverAssistSecurity.ajaxurl, {
            action: "silver_assist_get_security_status",
            nonce: silverAssistSecurity.nonce
        }, response => {
            if (response.success) {
                updateSecurityStatusDisplay(response.data);
            }
        }).fail(() => {
            console.log(silverAssistSecurity.strings.securityStatusFailed || "Failed to load security status");
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

        $.post(silverAssistSecurity.ajaxurl, {
            action: "silver_assist_get_login_stats",
            nonce: silverAssistSecurity.nonce
        }, response => {
            if (response.success) {
                updateLoginStatsDisplay(response.data);
            }
        }).fail(() => {
            console.log(silverAssistSecurity.strings.loginStatsFailed || "Failed to load login stats");
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

        $.post(silverAssistSecurity.ajaxurl, {
            action: "silver_assist_get_blocked_ips",
            nonce: silverAssistSecurity.nonce
        }, response => {
            if (response.success) {
                updateBlockedIPsDisplay(response.data);
            } else {
                $("#blocked-ips-list").html(`<p class="no-threats">${silverAssistSecurity.strings.noThreats || "No active threats detected"}</p>`);
            }
        }).fail(() => {
            $("#blocked-ips-list").html(`<p class="error">${silverAssistSecurity.strings.error || "Error loading data"}</p>`);
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

        // Update status indicators
        $("#login-status").text(data.login_security.status).removeClass().addClass("status-indicator " + data.login_security.status);
        $("#password-status").text(data.password_security.status).removeClass().addClass("status-indicator " + data.password_security.status);
        $("#graphql-status").text(data.graphql_security.status).removeClass().addClass("status-indicator " + data.graphql_security.status);
        $("#general-status").text(data.general_security.status).removeClass().addClass("status-indicator " + data.general_security.status);

        // Update last updated time
        updateLastUpdatedTime();
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
        
        if (!data || data.length === 0) {
            $container.html(`<p class="no-threats">${silverAssistSecurity.strings.noThreats || "No active threats detected"}</p>`);
            $("#threat-count").text("0");
            return;
        }

        let html = "<div class=\"blocked-ips-table\">";
        html += "<table class=\"wp-list-table widefat fixed striped\">";
        html += `<thead><tr><th>${silverAssistSecurity.strings.ipHash}</th><th>${silverAssistSecurity.strings.blockedTime}</th><th>${silverAssistSecurity.strings.remaining}</th></tr></thead>`;
        html += "<tbody>";

        data.forEach(ip => {
            html += "<tr>";
            html += `<td>${ip.hash.substring(0, 8)}...</td>`;
            html += `<td>${ip.blocked_at}</td>`;
            html += `<td>${ip.remaining_minutes} ${silverAssistSecurity.strings.minutes}</td>`;
            html += "</tr>";
        });

        html += "</tbody></table></div>";
        $container.html(html);
        $("#threat-count").text(data.length);
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
        const $button = $("#refresh-dashboard");
        const originalText = $button.text();
        
        $button.text(silverAssistSecurity.strings.loading || "Loading...").prop("disabled", true);
        
        loadSecurityStatus();
        loadLoginStats();
        loadBlockedIPs();
        
        setTimeout(() => {
            $button.text(originalText).prop("disabled", false);
        }, 2000);
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

}))(jQuery);
