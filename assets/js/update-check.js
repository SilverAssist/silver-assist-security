/**
 * Update Check Script for Silver Assist Security
 *
 * Handles AJAX update checking when triggered from Settings Hub action button.
 * Integrates with wp-github-updater for automatic plugin updates.
 *
 * @package SilverAssist\Security
 * @since 1.1.13
 */

(($ => {
    "use strict";

    /**
     * Show WordPress admin notice
     *
     * @since 1.1.13
     * @param {string} message - The message to display
     * @param {string} type - Notice type: 'success', 'error', 'warning', 'info'
     * @returns {void}
     */
    const showAdminNotice = (message, type = "info") => {
        const noticeClass = `notice notice-${type} is-dismissible`;
        const noticeHtml = `
            <div class="${noticeClass}" style="margin: 15px 0;">
                <p><strong>Silver Assist Security:</strong> ${message}</p>
                <button type="button" class="notice-dismiss">
                    <span class="screen-reader-text">Dismiss this notice.</span>
                </button>
            </div>
        `;

        // Insert notice at the top of the page (after h1)
        const $notice = $(noticeHtml);
        $("h1").first().after($notice);

        // Make dismiss button work
        $notice.find(".notice-dismiss").on("click", function() {
            $notice.fadeOut(300, function() {
                $(this).remove();
            });
        });

        // Auto-dismiss after 5 seconds for success/info messages
        if (type === "success" || type === "info") {
            setTimeout(() => {
                $notice.fadeOut(300, function() {
                    $(this).remove();
                });
            }, 5000);
        }
    };

    /**
     * Check for plugin updates via AJAX
     *
     * @since 1.1.13
     * @returns {void}
     */
    window.silverAssistCheckUpdates = function() {
        // Get localized data
        const { ajaxurl, nonce, updateUrl, strings = {} } = window.silverAssistUpdateCheck || {};

        if (!ajaxurl || !nonce) {
            console.error("Silver Assist Security: Update check configuration missing");
            showAdminNotice("Update check configuration error. Please contact support.", "error");
            return;
        }

        // Show checking notice
        showAdminNotice("Checking for updates...", "info");

        $.ajax({
            url: ajaxurl,
            type: "POST",
            data: {
                action: "silver_assist_check_updates",
                nonce: nonce
            },
            success: function(response) {
                if (response.success) {
                    if (response.data.update_available) {
                        const message = strings.updateAvailable || "Update available! Redirecting to Updates page...";
                        showAdminNotice(message, "success");
                        
                        // Redirect after 2 seconds
                        setTimeout(() => {
                            window.location.href = updateUrl;
                        }, 2000);
                    } else {
                        const message = strings.upToDate || "You're up to date!";
                        showAdminNotice(message, "success");
                    }
                } else {
                    const errorMessage = response.data?.message || strings.checkError || "Error checking updates. Please try again.";
                    showAdminNotice(errorMessage, "error");
                }
            },
            error: function() {
                const message = strings.connectError || "Error connecting to update server.";
                showAdminNotice(message, "error");
            }
        });
    };

}))(jQuery);
