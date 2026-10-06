import { expect, test, type Page } from "@playwright/test";
import { clearMail, ensureUser, lastMail, resetLoginState, wp } from "../utils/wp-cli";
import { BROWSER_UA, TOKEN_QUERY, loginThroughHiddenPath, visitor } from "./support";

/** The first link in an email body that points at the given script. */
function linkTo(message: string, script: string): string {
  const match = message.match(new RegExp(`https?://[^\\s<>"]*${script.replace(".", "\\.")}[^\\s<>"]*`));
  if (!match) throw new Error(`No ${script} link in the email:\n${message}`);
  // Used as it appears in the plain-text email: a person clicks exactly this text.
  return match[0];
}

/**
 * Submit a form straight to the server. The browser-side strength meter asks for a "confirm
 * weak password" tick and can disable the button; what is checked here is the server-side rule,
 * which is the one that cannot be skipped.
 */
async function submitWithoutScripts(page: Page, form: string): Promise<void> {
  await Promise.all([
    page.waitForLoadState("domcontentloaded"),
    page.locator(form).evaluate((f) => HTMLFormElement.prototype.submit.call(f)),
  ]);
}

/** Type a new password the way the screens expect: reveal the field (profile) and keep pass2 in step. */
async function typePassword(page: Page, value: string): Promise<void> {
  const generate = page.locator(".wp-generate-pw");
  if (await generate.isVisible()) await generate.click();
  await page.evaluate((v) => {
    for (const id of ["pass1", "pass2"]) {
      const field = document.querySelector<HTMLInputElement>(`#${id}`);
      if (field) {
        field.disabled = false;
        field.value = v;
      }
    }
  }, value);
}

const STRONG = "Fresh-Pass-4567!";
const WEAK = "weakpass";

test.describe("Password reset by email", () => {
  test.use(visitor(41));

  const login = "e2e_reset_user";
  const original = "Original-Pass-123!";

  test.beforeEach(() => {
    resetLoginState();
    ensureUser(login, "subscriber", original);
    clearMail();
  });

  test("the emailed link opens for a visitor with no admin access cookie, refuses weak passwords with the rules, and accepts a strong one @smoke", async ({ page, browser }) => {
    // 1. Ask for the reset (the form is reachable without the secret path).
    await page.goto(`/wp-login.php?action=lostpassword&${TOKEN_QUERY}`);
    await page.fill("#user_login", login);
    await page.click("#wp-submit");
    await expect(page).toHaveURL(/checkemail=confirm/);

    // 2. Follow the link from the email in a clean browser: no cookies, no token.
    const link = linkTo(lastMail().message, "wp-login.php");
    const visitorContext = await browser.newContext({ userAgent: BROWSER_UA, extraHTTPHeaders: { "X-Forwarded-For": "203.0.113.41" } });
    const reset = await visitorContext.newPage();
    const response = await reset.goto(link);
    expect(response?.status(), "the emailed link must not be a 404").toBe(200);
    await expect(reset.locator("#resetpassform")).toBeVisible();

    // 3. A weak password is refused, and the person is told the rules (not "Invalid login credentials").
    await typePassword(reset, WEAK);
    await submitWithoutScripts(reset, "#resetpassform");
    const error = reset.locator("#login_error");
    await expect(error).toBeVisible();
    await expect(error).toContainText(/at least 8 characters/i);
    await expect(error).not.toContainText(/invalid login credentials/i);

    // 4. A strong password goes through and works for the next login.
    await typePassword(reset, STRONG);
    await submitWithoutScripts(reset, "#resetpassform");
    await expect(reset.locator(".message, #login .message")).toContainText(/password has been reset/i);
    await visitorContext.close();

    resetLoginState();
    await loginThroughHiddenPath(page, login, STRONG);
  });
});

test.describe("Profile changes", () => {
  test.use(visitor(42));

  const login = "e2e_profile_user";
  const password = "Profile-Pass-123!";

  test.beforeEach(() => {
    resetLoginState();
    ensureUser(login, "editor", password);
    wp("user", "update", login, `--user_email=${login}@example.test`);
    clearMail();
  });

  test("the profile form enforces the password rules @smoke", async ({ page }) => {
    await loginThroughHiddenPath(page, login, password);
    await page.goto("/wp-admin/profile.php");

    await typePassword(page, WEAK);
    await submitWithoutScripts(page, "#your-profile");

    await expect(page.locator("#wpbody-content")).toContainText(/at least 8 characters/i);

    await typePassword(page, STRONG);
    await submitWithoutScripts(page, "#your-profile");
    await expect(page.locator("#wpbody-content")).toContainText(/profile updated/i);
  });

  test("the email change confirmation link works for someone who has to log in first", async ({ page, browser }) => {
    await loginThroughHiddenPath(page, login, password);
    await page.goto("/wp-admin/profile.php");
    await page.fill("#email", `new-${login}@example.test`);
    await page.click("#submit");
    await expect(page.locator(".notice-success, #message.updated").first()).toBeVisible();

    const link = linkTo(lastMail().message, "profile.php");
    expect(link).toContain("newuseremail=");

    // Open it in a browser with no session and no admin access cookie, as from a phone.
    resetLoginState();
    const other = await browser.newContext({ userAgent: BROWSER_UA, extraHTTPHeaders: { "X-Forwarded-For": "203.0.113.43" } });
    const phone = await other.newPage();
    const response = await phone.goto(link);
    expect(response?.status(), "the confirmation link must lead to a login screen, not a 404").toBe(200);
    await expect(phone.locator("#loginform")).toBeVisible();

    await phone.fill("#user_login", login);
    await phone.fill("#user_pass", password);
    await phone.click("#wp-submit");
    await expect(phone).toHaveURL(/profile\.php/);
    await expect(phone.locator("#email")).toHaveValue(`new-${login}@example.test`);
    await other.close();
  });
});
