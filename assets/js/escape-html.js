/**
 * Silver Assist Security Essentials - Shared HTML escaping helpers
 *
 * One implementation for every admin script that builds markup from a string
 * (localized strings, AJAX responses, user input). Exposed as
 * window.SilverAssistSecurityUtils and loaded as a dependency of admin.js and
 * password-validation.js.
 *
 * @file escape-html.js
 * @version 1.5.4
 * @author Silver Assist
 * @since 1.5.4
 */

((window => {
    "use strict";

    /**
     * Escape a value for safe insertion into HTML text or a quoted attribute.
     *
     * Replaces &, <, >, " and ' with their entities. null and undefined become
     * an empty string; any other value is converted with String() first.
     *
     * @since 1.1.15
     * @param {*} value - The value to escape
     * @returns {string} HTML-safe string
     */
    const escapeHtml = value => {
        if (value === null || value === undefined) return "";
        return String(value)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    };

    /**
     * Return a URL that is safe to use as an href, or the fallback.
     *
     * Escaping does not stop a "javascript:" URL from running when clicked, so
     * only http, https and mailto URLs (absolute or relative, never protocol-relative) are accepted.
     * The result is NOT escaped: pass it through escapeHtml() when it goes into markup.
     *
     * @since 1.5.4
     * @param {string} url - The URL to check
     * @param {string} [fallback="#"] - Returned when the URL is not allowed
     * @returns {string} The URL, or the fallback
     */
    const safeUrl = (url, fallback = "#") => {
        try {
            // A protocol-relative URL ("//host") would inherit the page scheme and leave the site.
            if (/^[\s]*[\/\\]{2}/.test(String(url))) {
                return fallback;
            }
            const parsed = new URL(String(url), window.location.href);
            return ["http:", "https:", "mailto:"].includes(parsed.protocol) ? String(url) : fallback;
        } catch (e) {
            return fallback;
        }
    };

    window.SilverAssistSecurityUtils = Object.freeze({ escapeHtml, safeUrl });
}))(window);
