/**
 * Update Check Script for Silver Assist Security
 *
 * Handles AJAX update checking when triggered from Settings Hub action button.
 * Integrates with wp-github-updater for automatic plugin updates.
 *
 * @package SilverAssist\Security
 * @since 1.1.14
 */

(($ => {
    "use strict";

    /**
     * Check for plugin updates via AJAX
     *
     * @since 1.1.14
     * @returns {void}
     */
    window.silverAssistCheckUpdates = function() {
        // Get localized data
        const { ajaxurl, nonce, updateUrl, strings = {} } = window.silverAssistUpdateCheck || {};

        if (!ajaxurl || !nonce) {
            console.error("Silver Assist Security: Update check configuration missing");
            return;
        }

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
                        alert(message);
                        window.location.href = updateUrl;
                    } else {
                        const message = strings.upToDate || "You're up to date!";
                        alert(message);
                    }
                } else {
                    const message = strings.checkError || "Error checking updates. Please try again.";
                    alert(message);
                }
            },
            error: function() {
                const message = strings.connectError || "Error connecting to update server.";
                alert(message);
            }
        });
    };

}))(jQuery);
