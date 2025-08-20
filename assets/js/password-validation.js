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

    // ========================================
    // TIMING CONSTANTS
    // ========================================
    
    /**
     * Password validation timing constants
     * 
     * Centralized timeout values for consistent user experience
     * and easy maintenance of timing behavior.
     * 
     * @since 1.1.6
     */
    const TIMING = {
        VALIDATION_DEBOUNCE: 300,     // Debounce delay for input validation (ms)
        HIDE_ON_INACTIVITY: 8000,    // Hide message after inactivity period (ms)
        HIDE_ON_BLUR: 5000,          // Hide message when field loses focus (ms)
        FADE_OUT_DURATION: 400       // Smooth fade out animation duration (ms)
    };

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
        const $passwordField = $("#pass1");
        const $confirmField = $("#pass2");

        if (!$passwordField.length) {
            return;
        }

        // Create validation UI
        createValidationUI($passwordField);

        // Bind validation events
        bindValidationEvents($passwordField, $confirmField);
    };

    /**
     * Create validation message container
     *
     * Adds a validation message container below the password field
     * for displaying real-time validation feedback.
     *
     * @since 1.1.5
     * @param {jQuery} $passwordField - The password input field
     * @returns {void}
     */
    const createValidationUI = $passwordField => {
        const $validationContainer = $('<div id="silver-assist-password-validation" class="password-validation-message"></div>');
        $passwordField.closest("tr").after($('<tr><td colspan="2"></td></tr>').find("td").append($validationContainer).end());
    };

    /**
     * Bind validation events to password fields
     *
     * Sets up real-time validation on password input events
     * with debounced validation to improve performance.
     *
     * @since 1.1.5
     * @param {jQuery} $passwordField - The password input field
     * @param {jQuery} $confirmField - The password confirmation field
     * @returns {void}
     */
    const bindValidationEvents = ($passwordField, $confirmField) => {
        // Destructure timing constants for cleaner code
        const { VALIDATION_DEBOUNCE, HIDE_ON_INACTIVITY, HIDE_ON_BLUR } = TIMING;
        
        // Primary password field validation
        $passwordField.on("input keyup paste", function () {
            // Clear existing timeouts
            clearTimeout(this.validationTimeout);
            clearTimeout(this.hideTimeout);

            this.validationTimeout = setTimeout(() => {
                validatePassword($passwordField.val());

                // Set timeout to hide message after period of inactivity using destructured constant
                this.hideTimeout = setTimeout(() => {
                    hideValidationMessage();
                }, HIDE_ON_INACTIVITY);
            }, VALIDATION_DEBOUNCE);
        });

        // Confirmation field validation
        $confirmField.on("input keyup paste", () => {
            if ($passwordField.val() && $confirmField.val()) {
                // Clear any hide timeout when user is actively typing
                clearTimeout($passwordField[0].hideTimeout);

                // WordPress handles password match validation, we just trigger our validation
                validatePassword($passwordField.val());

                // Set timeout to hide message after period of inactivity using destructured constant
                $passwordField[0].hideTimeout = setTimeout(() => {
                    hideValidationMessage();
                }, HIDE_ON_INACTIVITY);
            }
        });

        // Clear timeouts when user focuses on password fields (actively editing)
        $passwordField.add($confirmField).on("focus", function () {
            clearTimeout($passwordField[0].hideTimeout);
        });

        // Start hide timer when user leaves password fields using destructured constant
        $passwordField.add($confirmField).on("blur", function () {
            const $container = $("#silver-assist-password-validation");
            if ($container.is(":visible")) {
                $passwordField[0].hideTimeout = setTimeout(() => {
                    hideValidationMessage();
                }, HIDE_ON_BLUR);
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
        const $validationContainer = $("#silver-assist-password-validation");

        if (!password) {
            $validationContainer.hide();
            return;
        }

        const validation = validatePasswordStrength(password);

        if (validation.valid) {
            showSuccessMessage($validationContainer);
        } else {
            showErrorMessage($validationContainer);
        }
    };

    /**
     * Hide validation message with smooth transition
     *
     * Smoothly hides the password validation message after a period of inactivity.
     * Uses fadeOut for better user experience.
     *
     * @since 1.1.6
     * @returns {void}
     */
    const hideValidationMessage = () => {
        // Destructure timing constants for cleaner code
        const { FADE_OUT_DURATION } = TIMING;
        
        const $validationContainer = $("#silver-assist-password-validation");

        if ($validationContainer.is(":visible")) {
            $validationContainer.fadeOut(FADE_OUT_DURATION, function () {
                // Clear any remaining classes after hiding
                $(this).removeClass("success error warning");
            });
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
     * @param {jQuery} $container - The validation message container
     * @returns {void}
     */
    const showSuccessMessage = $container => {
        // Use destructuring for cleaner object access
        const { passwordSuccess } = window.silverAssistSecurity || {};
        const successMessage = passwordSuccess || "Password meets security requirements";

        // Stop any ongoing fade animations and show immediately
        $container.stop(true, false);

        $container
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
     * @param {jQuery} $container - The validation message container
     * @returns {void}
     */
    const showErrorMessage = $container => {
        // Use destructuring for cleaner object access
        const { passwordError } = window.silverAssistSecurity || {};
        const errorMessage = passwordError || 
            "Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.";

        // Stop any ongoing fade animations and show immediately
        $container.stop(true, false);

        $container
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
