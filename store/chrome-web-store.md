# Chrome Web Store submission

Everything the CWS dashboard asks for, ready to paste. Upload
`dist/whisper-guard-chromium-<version>.zip` (built by `npm run package`).

## Listing

- **Name:** Whisper Guard
- **Summary (132 max):** Phishing protection that works the instant it installs. On-device look-alike alerts; a live safety signal when you sign in.
- **Category:** Privacy & Security
- **Language:** English

**Description:**

Whisper Guard warns you before you type a password into a fake login page.

The moment you install it, an on-device detector starts checking every site
you visit against 800+ heavily phished brands: homoglyph tricks (paypa1.com,
Cyrillic lookalikes), swapped endings (paypal.tk), hyphen squats
(face-book.com), fake subdomains (paypal.com.evil.example) and combo squats
(paypal-secure-login.com). One tap takes you to the real site. Right-click
any link to vet it before you open it. All of this runs in your browser, with
no account and nothing sent anywhere.

Sign in free and the toolbar mark answers "is THIS site safe?" on every page,
from the Whisper security graph: green for no known threat, amber for
suspicious, a red stop plate reserved for evidenced-malicious sites, and an
honest UNKNOWN for the internet's long tail. Click the mark for the why (the
threat feeds a site is listed in), who runs it, confirmed look-alikes, and a
session log of risky sites.

Privacy is the product:
- Only a site's NAME is ever checked. Never the page, the path, what you
  type, or your history.
- The keyless protection sends nothing at all. Signed in, the hostname goes
  to exactly one endpoint to answer the safety check, and is not retained to
  build a browsing profile.
- No telemetry, no analytics, no sync. Open source (MIT).

Optional Active Shield adds a full-page stop before known credential-phishing
pages and a caution when a password field gains focus on a flagged site. It
asks for the browser's own on-page permission only when you turn it on, and
declining it keeps everything else working.

If Whisper is unreachable the extension fails open: browsing is never blocked
and the on-device protection keeps running.

- **Homepage URL:** https://whisper.online/docs/whisper-guard
- **Support URL:** https://github.com/whisper-sec/whisper-guard/issues
- **Privacy policy URL:** https://whisper.online/docs/whisper-guard (the
  privacy model section; a dedicated policy URL can replace this at review
  time if CWS requires a standalone page)

## Screenshots (1280x800 or 640x400)

Use the gallery in `shots/` (regenerate with
`npx playwright test e2e/screenshots.spec.ts`):

1. `toolbar-states.png` (the six states)
2. `popup-keyless-lookalike.png` (the keyless hero)
3. `popup-keyed-malicious.png` (evidenced verdict)
4. `warning.png` (the full-page stop)
5. `firstrun.png` (the privacy promise)

## Privacy practices tab (the exact answers)

- **Single purpose:** Warns the user before phishing and look-alike websites,
  using an on-device brand-impersonation detector and, when the user signs
  in, a per-site safety verdict from the Whisper security graph.
- **Permission justifications:**
  - `webNavigation`: to learn the hostname of the page being visited so it
    can be checked. The URL's path, query, and content are discarded at
    parse time.
  - `storage`: local settings, the local verdict cache, and the sign-in
    credential. Nothing is synced.
  - `scripting`: used only after the optional Active Shield opt-in, to draw
    the warning banner and password-field caution on flagged sites.
  - `declarativeNetRequest`: to block navigation to known credential-phishing
    sites before the request leaves the browser (Active Shield).
  - `contextMenus`: the "Check this link with Whisper" right-click action.
  - `alarms`: the daily signed brand-corpus update check.
  - `activeTab`: to act on the current tab when the user clicks the toolbar
    action.
  - Host permissions (`graph.whisper.security`, `console.whisper.security`,
    `get.whisper.online`): the safety check (hostname only), the sign-in
    flow, and corpus updates, respectively. No other host is ever contacted.
  - `<all_urls>` (optional): requested at runtime only when the user enables
    Active Shield, used only to draw warnings, never to read page content.
- **Data usage:** Website content: NOT collected. Web history: NOT collected
  (the hostname of the current site is transmitted to answer the user's
  safety check when signed in; it is not retained to build a profile).
  Personally identifiable information, financial, health, authentication,
  communications, location, user activity: NOT collected.
- **Remote code:** none (MV3, all code in the package).

## After upload

Verify the listing renders, the version matches `package.json`, and the
screenshots are current. First review typically takes a few days.
