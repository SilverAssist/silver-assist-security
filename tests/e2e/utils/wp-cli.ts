import { execFileSync } from "node:child_process";

/**
 * Run a WP-CLI command in the wp-env `cli` container of the current checkout and return its
 * trimmed stdout. Used to arrange state (options, users, transients) and to read what the
 * browser cannot see (the last captured email, transients).
 */
export function wp(...args: string[]): string {
  // `wp-env run` occasionally fails to attach to the container right after another call; one retry is enough.
  for (let tries = 1; ; tries++) {
    try {
      return execFileSync("npx", ["wp-env", "run", "cli", "wp", ...args], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"],
      }).trim();
    } catch (error) {
      if (tries >= 2) throw error;
    }
  }
}

/** Delete the plugin's per-IP login state (failed attempts, lockout, login page counter). */
export function resetLoginState(): void {
  wp(
    "db",
    "query",
    "DELETE FROM wp_options WHERE option_name LIKE '%login_attempts_%' OR option_name LIKE '%lockout_%' OR option_name LIKE '%login_access_%' OR option_name LIKE '%login_window_%' OR option_name LIKE '%bot_activity_%' OR option_name LIKE '%extended_bot_block_%'",
  );
}

/** Create a user (idempotent) and return its ID. */
export function ensureUser(login: string, role: string, password: string): string {
  const existing = wp("user", "list", `--search=${login}`, "--field=ID", "--search-columns=user_login");
  if (existing) {
    wp("user", "update", existing.split("\n")[0], `--user_pass=${password}`);
    return existing.split("\n")[0];
  }
  return wp("user", "create", login, `${login}@example.test`, `--role=${role}`, `--user_pass=${password}`, "--porcelain");
}

/** The latest email captured by tests/e2e/mu-plugins/e2e-mail-and-forms.php. */
export function lastMail(): { to: string; subject: string; message: string } {
  return JSON.parse(wp("option", "get", "e2e_last_mail"));
}

export function clearMail(): void {
  wp("option", "delete", "e2e_last_mail");
}

/** Move every session of a user back in time, as if they had been idle or logged in a while ago. */
export function ageUserSession(userId: string, seconds: number): void {
  const now = Math.floor(Date.now() / 1000);
  wp("user", "meta", "update", userId, "last_activity", String(now - seconds));

  const tokens = JSON.parse(wp("user", "meta", "get", userId, "session_tokens", "--format=json"));
  for (const hash of Object.keys(tokens)) tokens[hash].login = now - seconds;
  wp("user", "meta", "update", userId, "session_tokens", JSON.stringify(tokens), "--format=json");
}
