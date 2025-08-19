/**
 * Silver Assist Security Essentials - Password Strength Validation
 *
 * Real-time password validation for WordPress user profiles.
 * Validates password strength according to plugin security requirements.
 *
 * @file password-validation.js
 * @version 1.1.6
 * @author Silver Assist
 * @requires jQuery
 * @since 1.1.5
 */

(($ => {
    "use strict";

    /**
     * Initialize password validation on document ready
     *
     * Sets up real-time password validation for WordPress profile pages
     * when Silver Assist Security password enforcement is enabled.
     *
     * @since 1.1.5
     * @returns {void}
     */
    $(() => {
        initPasswordValidation();
        hideWeakPasswordConfirmation();
    });

    /**
     * Initialize password validation functionality
     *
     * Creates validation UI and binds events for real-time password checking.
     * Integrates with WordPress native password strength meter.
     *
     * @since 1.1.5
     * @returns {void}
     */
    const initPasswordValidation = () => {
        const passwordField = $("#pass1");
        const confirmField = $("#pass2");

        if (!passwordField.length) {
            return;
        }

        // Create validation UI
        createValidationUI(passwordField);

        // Bind validation events
        bindValidationEvents(passwordField, confirmField);
    };

    /**
     * Create validation message container
     *
     * Adds a validation message container below the password field
     * for displaying real-time validation feedback.
     *
     * @since 1.1.5
     * @param {jQuery} passwordField - The password input field
     * @returns {void}
     */
    const createValidationUI = passwordField => {
        const validationContainer = $('<div id="silver-assist-password-validation" class="password-validation-message"></div>');
        passwordField.closest("tr").after($('<tr><td colspan="2"></td></tr>').find("td").append(validationContainer).end());
    };

    /**
     * Bind validation events to password fields
     *
     * Sets up real-time validation on password input events
     * with debounced validation to improve performance.
     *
     * @since 1.1.5
     * @param {jQuery} passwordField - The password input field
     * @param {jQuery} confirmField - The password confirmation field
     * @returns {void}
     */
    const bindValidationEvents = (passwordField, confirmField) => {
        // Primary password field validation
        passwordField.on("input keyup paste", function() {
            // Debounce validation to avoid excessive calls
            clearTimeout(this.validationTimeout);
            this.validationTimeout = setTimeout(() => {
                validatePassword(passwordField.val());
            }, 300);
        });

        // Confirmation field validation
        confirmField.on("input keyup paste", () => {
            if (passwordField.val() && confirmField.val()) {
                // WordPress handles password match validation, we just trigger our validation
                validatePassword(passwordField.val());
            }
        });
    };

    /**
     * Validate password and display feedback
     *
     * Performs real-time password validation and displays
     * appropriate success or error messages.
     *
     * @since 1.1.5
     * @param {string} password - The password to validate
     * @returns {void}
     */
    const validatePassword = password => {
        const validationContainer = $("#silver-assist-password-validation");

        if (!password) {
            validationContainer.hide();
            return;
        }

        const validation = validatePasswordStrength(password);

        if (validation.valid) {
            showSuccessMessage(validationContainer);
        } else {
            showErrorMessage(validationContainer);
        }
    };

    /**
     * Validate password strength according to plugin rules
     *
     * Checks password against Silver Assist Security requirements:
     * - Minimum 8 characters
     * - Contains uppercase letters
     * - Contains lowercase letters
     * - Contains numbers
     * - Contains special characters
     *
     * @since 1.1.5
     * @param {string} password - The password to validate
     * @returns {Object} Validation result with valid flag and detailed checks
     */
    const validatePasswordStrength = password => {
        const checks = {
            length: password.length >= 8,
            uppercase: /[A-Z]/.test(password),
            lowercase: /[a-z]/.test(password),
            numbers: /[0-9]/.test(password),
            special: /[^A-Za-z0-9]/.test(password)
        };

        const valid = Object.values(checks).every(check => check);

        return {
            valid: valid,
            checks: checks
        };
    };

    /**
     * Display success validation message
     *
     * Shows a green success message when password meets all requirements.
     * Uses localized success message from PHP.
     *
     * @since 1.1.5
     * @param {jQuery} container - The validation message container
     * @returns {void}
     */
    const showSuccessMessage = container => {
        // Use localized message from silverAssistSecurity object
        const successMessage = window.silverAssistSecurity?.passwordSuccess || 
            "Password meets security requirements";

        container
            .removeClass("error warning")
            .addClass("success")
            .html(`✓ ${successMessage}`)
            .show();
    };

    /**
     * Display error validation message
     *
     * Shows a red error message when password doesn't meet requirements.
     * Uses localized error message from PHP.
     *
     * @since 1.1.5
     * @param {jQuery} container - The validation message container
     * @returns {void}
     */
    const showErrorMessage = container => {
        // Use localized message from silverAssistSecurity object
        const errorMessage = window.silverAssistSecurity?.passwordError || 
            "Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.";

        container
            .removeClass("success warning")
            .addClass("error")
            .html(`✗ ${errorMessage}`)
            .show();
    };

    /**
     * Hide weak password confirmation checkbox
     *
     * When password strength enforcement is enabled, hides the WordPress
     * "Confirm use of weak password" checkbox to prevent bypassing security.
     *
     * @since 1.1.5
     * @returns {void}
     */
    const hideWeakPasswordConfirmation = () => {
        // Add class to body to enable CSS hiding
        $("body").addClass("silver-assist-hide-weak-password");

        // Also hide any existing weak password rows
        $(".pw-weak").hide();

        // Monitor for dynamically added weak password elements
        const observer = new MutationObserver(mutations => {
            mutations.forEach(mutation => {
                mutation.addedNodes.forEach(node => {
                    if (node.nodeType === 1) { // Element node
                        const $node = $(node);
                        
                        // Check if the added node or its children have pw-weak class
                        if ($node.hasClass("pw-weak") || $node.find(".pw-weak").length) {
                            $node.filter(".pw-weak").hide();
                            $node.find(".pw-weak").hide();
                        }
                    }
                });
            });
        });

        // Start observing
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    };

}))(jQuery);
