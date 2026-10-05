<!-- agents-toolkit:planning-doc -->

# WEB-1222: Core Compatibility Fixes and Behavioral Test Strategy

## Problem Statement

On Oasis Senior Advisors (STG and PRD), creating an event in the backoffice block editor
throws `TypeError: _ is not a function` (stack: `editor.min.js` calling
`data.min.js` `__unstableMarkListeningStores`). Deactivating Silver Assist Security
Essentials makes the editor work again.

Two behaviors of this plugin are suspects (both **unverified**, see Phase 1):

1. `GeneralSecurity::remove_version_query_string()` strips `ver=` from every
   `script_loader_src` / `style_loader_src` URL, including wp-admin and
   `wp-includes/js/dist/*`. Without the cache-buster, a browser or CDN can serve a stale
   `data.min.js` next to a fresh `editor.min.js` after a core update. The Gutenberg
   packages call each other through `__unstable*` APIs, so a version skew produces exactly
   this class of error.
2. `GeneralSecurity::disable_user_enumeration()` removes `/wp/v2/users` and
   `/wp/v2/users/(?P<id>)` for **everyone**, including logged-in editors. The block
   editor uses that route (author selector, mentions). Expected symptom is a 404, not this
   TypeError, so it is a secondary bug.

Beyond the immediate fix, the plugin touches many core behaviors (headers, cookies, REST,
login, admin UI, assets, GraphQL) and its current tests did not catch this. The existing
`GeneralSecurityTest::test_version_query_string_removed` even **asserts the buggy
behavior** (`?ver=` must be absent for `wp-includes/js/jquery`). We need tests that assert
what a real user experiences.

## Current Architecture

- Plugin: `silver-assist-security` v1.5.2, PHP 8.2+, PSR-4 `SilverAssist\Security\`,
  components implement `LoadableInterface` via `silverassist/wp-plugin-kernel`.
- Relevant code: `src/Security/GeneralSecurity.php` (lines ~112-113 hooks, ~207-226 ver
  stripping, ~285-296 users endpoint removal), `src/Security/RestAPISecurity.php`,
  `src/Security/LoginSecurity.php`, `src/Security/AdminHideSecurity.php`.
- Tests today (PHPUnit 9.6 + WP test suite, `phpunit.xml.dist`): `tests/Unit`,
  `tests/Security`, `tests/Integration`, `tests/Functional`, `tests/Core`. CI matrix is
  PHP 8.2 x WP 6.5 / 6.6 / latest (`.github/workflows/quality-checks.yml`).
- Gaps: all tests run server-side. Nothing loads a real admin page in a browser, so JS
  runtime errors, asset URLs as rendered, and logged-in REST calls from the editor are
  never exercised. No Playwright or wp-env setup exists.
- `src` unit tests mostly assert hook registration or filter output on synthetic URLs
  (`example.com`), not behavior in admin context.

## Proposed Changes

### Overview

Fix both behaviors so they only apply where they are safe, then build a layered test
suite (unit, integration, e2e) organized around user-visible behaviors rather than around
classes. E2E runs the real plugin inside `@wordpress/env` with Playwright.

### Technical Approach

**A. `ver=` stripping (priority 1)**

- Only strip on the public front end: bail out when `is_admin()`, `wp_doing_ajax()`, the
  login page, or when the request is a REST/editor request.
- Never strip for core dist assets: skip any `src` containing `/wp-includes/` or
  `/wp-admin/`. Core already versions these and they are exactly what breaks on skew.
- Keep stripping for theme/plugin assets on the front end only if Phase 1 shows it is not
  itself a cache hazard. If it is, prefer replacing `ver=<wp version>` with a
  content-hash or file mtime rather than removing the buster entirely.
- Expose a filter (`silver_assist_security_strip_asset_version`, bool, receives `$src` and
  `$handle`) so sites can opt out per asset without patching.
- Make the existing settings toggle (if any) honor this; otherwise add an option, default
  on for front end only.

**B. `/wp/v2/users` endpoint (priority 1)**

- Remove the two routes only when `! is_user_logged_in()` (or, stricter, when the current
  user lacks `list_users`). Evaluate inside the `rest_endpoints` callback, never at
  registration time, since the user is resolved after `init`.
- Keep author archive redirect and `author_link` rewrite as is; verify they do not fire in
  admin/REST contexts used by the editor (`template_redirect` is front-end only, so low
  risk, but add a test).

**C. Test architecture (priority 2)**

Layer | Tool | Scope
---|---|---
Unit | PHPUnit, no WP DB | Pure logic: `remove_version_query_string` branching, URL cleaning, IP/helper functions
Integration | PHPUnit + WP test suite | Hooks in real WP: filters applied in admin vs front context, `rest_endpoints` per user role, REST rate limit via `rest_do_request`, login lockout, headers
E2E | Playwright + `@wordpress/env` | Real browser: editor loads and saves, no console errors, asset URLs, anonymous enumeration blocked, login flow

Conventions:
- Name tests after behavior (`test_logged_in_editor_can_list_users_via_rest`).
- Replace the buggy assertion in `GeneralSecurityTest::test_version_query_string_removed`
  with context-aware tests (front end strips, admin and core dist keep `ver=`).
- Tag e2e specs so a smoke subset can run on every PR and the full suite nightly.

### Proposed new files

- `.wp-env.json` (plugin mapped, WP version configurable, `SCRIPT_DEBUG` on)
- `playwright.config.ts`, `tests/e2e/*.spec.ts`, `tests/e2e/utils/` (login, console
  collector, REST helper)
- `tests/Integration/AssetVersioningTest.php`, `tests/Integration/RestUsersEndpointTest.php`
- `package.json` scripts: `test:e2e`, `test:e2e:smoke`, `wp-env:start`
- `.github/workflows/e2e.yml`

### API Changes

- New filter `silver_assist_security_strip_asset_version` (additive).
- Behavior change: `ver=` is no longer stripped in admin or for `wp-includes` /
  `wp-admin` assets; `/wp/v2/users` is available to authenticated users. Both belong in
  the CHANGELOG as a fix, with a note that anonymous behavior is unchanged.

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Root cause is not `ver=` stripping or users route | Medium | High | Phase 1 reproduces with a cache-warm then core-update scenario and bisects plugin features before any fix is written |
| Restoring `ver=` on the front end reduces "version hiding" value | Low | Low | Only core dist and admin are changed; front-end theme/plugin assets keep current behavior unless Phase 1 says otherwise |
| Exposing `/wp/v2/users` to logged-in users widens enumeration surface | Low | Medium | Limit to `list_users` capability; anonymous behavior unchanged and covered by tests |
| E2E suite is flaky or slow in CI | Medium | Medium | Smoke subset on PRs, full suite nightly, retries=1, traces on failure, pinned WP versions |
| Plugin is deployed across many sites, regression elsewhere | Medium | High | Release behind a patch version, run the full matrix, verify on OSA STG before PRD |
| Private GitHub dependencies (composer repos) break CI for e2e | Medium | Medium | Reuse the `COMPOSER_AUTH` pattern from `quality-checks.yml`; build the plugin zip once and mount it in wp-env |
| Separate bug: manual update from the plugins screen fails | Medium | Medium | Out of scope for this fix; open a follow-up ticket after checking the updater (WEB-1194, v1.5.2) |

## Phase Breakdown

### Phase 1: Reproduce and confirm root cause
**Objective**: Prove which behavior causes the TypeError before changing code.

- [ ] Record WP core versions and active plugins for OSA STG and PRD; note the last core update date
- [ ] Reproduce with a cache-warm browser, then load the editor with hard refresh and with incognito
- [ ] Inspect Network: do `data.min.js` / `editor.min.js` load without `?ver=`? Any CDN or CloudFront caching on `wp-includes/js/dist`?
- [ ] Bisect: disable only the `script_loader_src` filter (mu-plugin snippet), then only the `/wp/v2/users` filter, and retest the editor
- [ ] Check browser console for 404 on `/wp-json/wp/v2/users`
- [ ] Write findings into the Jira ticket and update this plan if the cause differs

**Validation**: A single feature toggle reproduces and removes the error, documented with evidence.

### Phase 2: Fix the affected behaviors (TDD)
**Objective**: Ship the minimal, correct fix.

- [ ] Write failing integration tests first (admin keeps `ver=`, core dist keeps `ver=`, logged-in user can reach `/wp/v2/users`, anonymous cannot)
- [ ] Update `GeneralSecurityTest::test_version_query_string_removed` to the new contract
- [ ] Implement context checks in `remove_version_query_string` and the `rest_endpoints` callback
- [ ] Add the `silver_assist_security_strip_asset_version` filter
- [ ] Run `composer phpcs`, `composer phpstan`, PHPUnit

**Validation**: All new tests pass; PHPCS and PHPStan level 8 clean.

### Phase 3: Integration test coverage for core-touching features
**Objective**: Cover each core behavior the plugin modifies, in real WP context.

- [ ] Asset URLs per context (front, admin, login, REST, ajax)
- [ ] REST: users endpoint per role, batch endpoint for anonymous, rate limit via `rest_do_request`
- [ ] Headers: security headers on front and admin responses, HSTS only on SSL non-dev
- [ ] Login: lockout, generic error message, cookie flags
- [ ] User enumeration: `?author=1` redirect, `author_link`, oEmbed route removal does not break embeds in editor
- [ ] XML-RPC disabled, file editing disabled, admin footer/branding
- [ ] Map each plugin feature to at least one behavior test; list any gap in `tests/README.md`

**Validation**: Coverage report shows every `src/Security/*` public hook exercised by at least one behavior test.

### Phase 4: E2E with Playwright and wp-env
**Objective**: Validate real user behaviors in a browser.

- [ ] Add `.wp-env.json`, `playwright.config.ts`, auth setup (storage state for admin and editor)
- [ ] Console collector helper that fails a test on `pageerror` or console errors
- [ ] Specs (smoke tagged `@smoke`):
  - [ ] Admin opens block editor for a post and a custom post type, types, saves draft, publishes, no console errors `@smoke`
  - [ ] Editor author selector loads users for a logged-in editor `@smoke`
  - [ ] Admin pages load core scripts with `ver=` and no 404 on `wp-includes/js/dist`
  - [ ] Anonymous: `/wp-json/wp/v2/users` returns 401/404, `?author=1` redirects home `@smoke`
  - [ ] Front end: version hiding holds (no generator meta, no WP version in HTML)
  - [ ] Login: bad credentials show generic message, lockout after N attempts
  - [ ] Plugin settings page loads and saves
- [ ] Run against WP 6.5 and latest in the matrix; add a "simulate core update with warm cache" spec if Phase 1 confirms the skew theory
- [ ] Add `.github/workflows/e2e.yml` (smoke on PR, full nightly), upload traces on failure

**Validation**: `npm run test:e2e:smoke` green locally and in CI; reverting the Phase 2 fix makes the editor and users specs fail (proves the tests catch the bug).

### Phase 5: Release and rollout
**Objective**: Deliver safely to OSA and the rest of the fleet.

- [ ] Run `core-review` skill at `--budget medium` before pushing; apply all critical/warning findings and re-run until clean
- [ ] Update CHANGELOG, bump version (patch), follow `release-management` skill
- [ ] Update plugin on OSA STG, verify event creation, then PRD
- [ ] Open follow-up ticket for the failing manual update (updater/WEB-1194)

**Validation**: Event create/save/publish works on OSA STG and PRD with the plugin active.

## Testing Strategy

### Unit Tests
- `remove_version_query_string`: no `ver`, `ver` only, `ver` plus other params, multiple `ver`, fragment, malformed URL, empty string
- Context predicate (is this asset safe to strip?) for core, theme, plugin, admin URLs
- Filter override returns control to the site

### Integration Tests
- Front-end context strips theme/plugin `ver=`; admin context keeps all; core dist always keeps `ver=`
- `rest_endpoints` as anonymous, subscriber, editor, administrator
- Rate limiting and batch restriction via `rest_do_request`
- Headers, cookies, login lockout, author redirect

### E2E Tests
- Block editor create/save/publish (post and CPT) without console errors
- Editor author selector, anonymous enumeration blocked, login lockout, settings page

### Manual Testing
- OSA STG: reproduce before the fix, confirm after, with cache warm and with CDN in front
- Check the plugins screen manual update separately (out of scope for the fix)

## Rollback Plan

Revert the patch release (immutable tags: publish a new patch, never retag) and reinstall
the previous version. As an emergency mitigation on a site, add a mu-plugin that
`remove_filter`s the two hooks, or deactivate the plugin as Mauricio did.

## Dependencies

- Node 22 and Docker for `@wordpress/env` and Playwright locally and in CI
- `COMPOSER_AUTH` secret for private SilverAssist GitHub packages in CI
- Access to OSA STG/PRD (via `aws-ecs` tools) for Phase 1 data and final verification
- Coordination with Mauricio Gomez (ticket assignee) so findings land in WEB-1222
