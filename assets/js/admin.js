/**
 * Silver Assist Security Suite - Admin Panel Scripts
 *
 * JavaScript functionality for the admin configuration panel including
 * form validation, AJAX security settings updates, and interactive
 * security status management.
 *
 * @file admin.js
 * @version 1.0.0
 * @author Silver Assist
 * @requires jQuery
 * @since 1.0.0
 */

(function ($) {
    'use strict';

    $(document).ready(function () {
        // Add security admin class to wrap
        $('.wrap').addClass('silver-assist-security-admin');

        // Initialize form validation
        initFormValidation();

        // Initialize toggle switches
        initToggleSwitches();

        // Initialize tooltips
        initTooltips();

        // Auto-save feature
        initAutoSave();
    });

    /**
     * Initialize form validation
     */
    function initFormValidation() {
        $('form').on('submit', function (e) {
            var isValid = true;
            var errors = [];

            // Validate login attempts
            var loginAttempts = $('#silver_assist_login_attempts').val();
            if (loginAttempts < 1 || loginAttempts > 20) {
                errors.push('Login attempts must be between 1 and 20');
                isValid = false;
            }

            // Validate lockout duration
            var lockoutDuration = $('#silver_assist_lockout_duration').val();
            if (lockoutDuration < 60 || lockoutDuration > 3600) {
                errors.push('Lockout duration must be between 60 and 3600 seconds');
                isValid = false;
            }

            // Validate session timeout
            var sessionTimeout = $('#silver_assist_session_timeout').val();
            if (sessionTimeout < 5 || sessionTimeout > 120) {
                errors.push('Session timeout must be between 5 and 120 minutes');
                isValid = false;
            }

            // Validate GraphQL settings if they exist
            var graphqlDepth = $('#silver_assist_graphql_query_depth').val();
            if (graphqlDepth && (graphqlDepth < 1 || graphqlDepth > 20)) {
                errors.push('GraphQL query depth must be between 1 and 20');
                isValid = false;
            }

            var graphqlComplexity = $('#silver_assist_graphql_query_complexity').val();
            if (graphqlComplexity && (graphqlComplexity < 10 || graphqlComplexity > 1000)) {
                errors.push('GraphQL query complexity must be between 10 and 1000');
                isValid = false;
            }

            var graphqlTimeout = $('#silver_assist_graphql_query_timeout').val();
            if (graphqlTimeout && (graphqlTimeout < 1 || graphqlTimeout > 30)) {
                errors.push('GraphQL query timeout must be between 1 and 30 seconds');
                isValid = false;
            }

            if (!isValid) {
                e.preventDefault();
                showValidationErrors(errors);
            }
        });
    }

    /**
     * Show validation errors
     */
    function showValidationErrors(errors) {
        var errorHtml = '<div class="notice notice-error is-dismissible"><ul>';
        errors.forEach(function (error) {
            errorHtml += '<li>' + error + '</li>';
        });
        errorHtml += '</ul></div>';

        $('.wrap h1').after(errorHtml);

        // Auto-dismiss after 5 seconds
        setTimeout(function () {
            $('.notice-error').fadeOut();
        }, 5000);
    }

    /**
     * Initialize toggle switches
     */
    function initToggleSwitches() {
        // Convert checkboxes to toggle switches
        $('input[type="checkbox"]').each(function () {
            var $checkbox = $(this);
            var $label = $checkbox.closest('label');

            if (!$label.hasClass('silver-assist-toggle')) {
                $label.addClass('silver-assist-toggle');
                $checkbox.after('<span class="silver-assist-slider"></span>');
            }
        });
    }

    /**
     * Initialize tooltips
     */
    function initTooltips() {
        // Add tooltips to description texts
        $('.description').each(function () {
            var $desc = $(this);
            var $input = $desc.closest('td').find('input');

            if ($input.length) {
                $input.attr('title', $desc.text());
            }
        });
    }

    /**
     * Initialize auto-save feature
     */
    function initAutoSave() {
        var saveTimeout;
        var $form = $('form');

        $form.find('input, select, textarea').on('change', function () {
            clearTimeout(saveTimeout);

            // Show saving indicator
            showSavingIndicator();

            // Auto-save after 2 seconds of inactivity
            saveTimeout = setTimeout(function () {
                autoSaveSettings();
            }, 2000);
        });
    }

    /**
     * Show saving indicator
     */
    function showSavingIndicator() {
        if (!$('.saving-indicator').length) {
            $('form').append('<div class="saving-indicator" style="position: fixed; top: 32px; right: 20px; background: #fff; border: 1px solid #ccc; padding: 10px; border-radius: 3px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); z-index: 9999;">Saving...</div>');
        }
    }

    /**
     * Auto-save settings via AJAX
     */
    function autoSaveSettings() {
        var $form = $('form');
        var formData = $form.serialize();

        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'silver_assist_auto_save',
                nonce: $('#_wpnonce').val(),
                form_data: formData
            },
            success: function (response) {
                $('.saving-indicator').html('Saved!').delay(2000).fadeOut();
            },
            error: function () {
                $('.saving-indicator').html('Save failed').addClass('error').delay(3000).fadeOut();
            }
        });
    }

    /**
     * Real-time validation feedback
     */
    function initRealTimeValidation() {
        $('input[type="number"]').on('input', function () {
            var $input = $(this);
            var value = parseInt($input.val());
            var min = parseInt($input.attr('min'));
            var max = parseInt($input.attr('max'));

            // Remove previous validation classes
            $input.removeClass('valid invalid');

            if (value >= min && value <= max) {
                $input.addClass('valid');
            } else {
                $input.addClass('invalid');
            }
        });
    }

    // Initialize real-time validation
    initRealTimeValidation();

})(jQuery);
