import { resetLoginState, wp } from "../utils/wp-cli";

/** Restore the state the default E2E suite expects: admin hiding off, no leftover lockouts. */
export default async function globalTeardown(): Promise<void> {
  wp("option", "update", "silver_assist_admin_hide_enabled", "0");
  wp("option", "update", "silver_assist_lockout_duration", "900");
  resetLoginState();
}
