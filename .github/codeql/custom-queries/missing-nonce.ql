/**
 * @name Missing nonce verification in WordPress AJAX handler
 * @description Detects AJAX handlers that don't verify nonces
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @id php/wordpress/missing-nonce-ajax
 * @tags security
 *       wordpress
 *       csrf
 */

import php
import semmle.code.php.security.dataflow.TaintTracking

from FunctionCall ajax
where
  ajax.getTarget().getName().matches("wp_ajax_%") and
  not exists(FunctionCall nonce |
    nonce.getTarget().getName() = "wp_verify_nonce" and
    nonce.getLocation().getFile() = ajax.getLocation().getFile()
  )
select ajax, "WordPress AJAX handler missing nonce verification"
