/**
 * WordPress Security Queries Library
 * Custom CodeQL queries for WordPress security best practices
 */

import php

/**
 * Detects WordPress functions that require nonce verification
 */
class WordPressNonceRequiredFunction extends FunctionCall {
  WordPressNonceRequiredFunction() {
    this.getTarget().getName() in [
      "wp_ajax_", "admin_post_", "wp_handle_upload",
      "update_option", "add_option", "delete_option"
    ]
  }
}

/**
 * Detects missing capability checks in admin functions
 */
class WordPressCapabilityCheck extends FunctionCall {
  WordPressCapabilityCheck() {
    this.getTarget().getName() in [
      "current_user_can", "user_can", "wp_verify_nonce"
    ]
  }
}

/**
 * Detects unescaped output in WordPress
 */
class WordPressUnescapedOutput extends FunctionCall {
  WordPressUnescapedOutput() {
    this.getTarget().getName() in [
      "echo", "print", "printf"
    ] and
    not exists(FunctionCall esc |
      esc.getTarget().getName() in ["esc_html", "esc_attr", "esc_url", "wp_kses"]
    )
  }
}

/**
 * Detects direct database queries without preparation
 */
class WordPressUnsafeDatabaseQuery extends MethodCall {
  WordPressUnsafeDatabaseQuery() {
    this.getTarget().getName() in ["query", "get_results", "get_var", "get_row"] and
    this.getReceiver().toString() = "$wpdb" and
    not exists(MethodCall prepare |
      prepare.getTarget().getName() = "prepare"
    )
  }
}
