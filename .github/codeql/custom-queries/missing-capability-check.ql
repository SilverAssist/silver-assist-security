/**
 * @name Missing capability check in admin page
 * @description Admin pages should verify user capabilities
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @precision high
 * @id php/wordpress/missing-capability-check
 * @tags security
 *       wordpress
 *       authorization
 */

import php

from FunctionCall adminPage
where
  adminPage.getTarget().getName() in [
    "add_menu_page", "add_submenu_page", "add_options_page",
    "add_theme_page", "add_plugins_page", "add_users_page",
    "add_management_page", "add_dashboard_page"
  ] and
  not exists(FunctionCall capCheck |
    capCheck.getTarget().getName() in ["current_user_can", "user_can"] and
    capCheck.getLocation().getFile() = adminPage.getLocation().getFile()
  )
select adminPage, "Admin page function should check user capabilities"
