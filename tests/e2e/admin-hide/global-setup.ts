import { ensureUser, resetLoginState, wp } from "../utils/wp-cli";
import { HIDDEN_PATH, MEMBER_PASS, MEMBER_USER } from "./support";

/**
 * Turn admin hiding on for this run and arrange the defaults the specs document.
 * global-teardown.ts turns it off again so the default E2E suite is not affected.
 */
export default async function globalSetup(): Promise<void> {
  wp("option", "update", "silver_assist_admin_hide_enabled", "1");
  wp("option", "update", "silver_assist_admin_hide_path", HIDDEN_PATH);
  wp("option", "update", "silver_assist_login_attempts", "5");
  wp("option", "update", "silver_assist_lockout_duration", "900");
  wp("option", "update", "silver_assist_session_timeout", "30");
  wp("option", "update", "silver_assist_password_strength_enforcement", "1");
  wp("option", "update", "silver_assist_bot_protection", "1");

  ensureUser(MEMBER_USER, "editor", MEMBER_PASS);
  resetLoginState();
}
