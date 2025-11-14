/**
 * @name Unescaped output in WordPress
 * @description Detects output that should be escaped but isn't
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision medium
 * @id php/wordpress/unescaped-output
 * @tags security
 *       wordpress
 *       xss
 */

import php

from Expr output
where
  (
    output instanceof Echo or
    output instanceof Print
  ) and
  not exists(FunctionCall esc |
    esc.getTarget().getName() in [
      "esc_html", "esc_attr", "esc_url", "esc_js",
      "esc_html__", "esc_html_e", "esc_attr__", "esc_attr_e",
      "wp_kses", "wp_kses_post"
    ]
  )
select output, "Output should be escaped to prevent XSS"
