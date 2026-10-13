<!-- agents-toolkit:planning-doc issue=190 -->
# Plan: scheduled E2E fails on the lockout test (#190)

## Problem statement

The daily `E2E Tests` run (full suite) has failed since 2026-10-08. The test
`the lockout ends on time even when the locked-out person keeps trying` expects a 12 s lockout to be
over after 13 s, but the lockout lasts 60 s.

## Current architecture

- `SettingsRegistry` declares `silver_assist_lockout_duration` with a 60 to 3600 range.
- `SettingsSanitizer::register()` (1.5.4) attaches a `sanitize_callback` to every registry option, so
  `wp option update` clamps 12 to 60.
- PR runs execute the smoke subset only, which does not include this test.

## Proposed changes

- `tests/e2e/admin-hide/login-protection.spec.ts`: write the 12 s straight to `wp_options`
  (`wp db query`), bypassing the sanitizer, with a comment saying why.
- No plugin change: the 60 s minimum is intended behavior.

## Phases

1. Change the test setup (done locally, passes in 17 s).
2. Run `core-review`, open the PR.
3. Trigger `E2E Tests` with `workflow_dispatch` after merge and confirm it is green.

## Testing strategy

`npx playwright test -c playwright.admin-hide.config.ts -g "lockout ends on time"` against wp-env, then the
full `npm run test:e2e:admin-hide` suite.
