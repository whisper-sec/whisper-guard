# Chrome Web Store submission

Everything the CWS dashboard asks for, ready to paste. Upload
`dist/whisper-guard-chromium-<version>.zip` (built by `npm run package`).

## Listing

- **Name:** Whisper Guard
- **Summary (132 max):** The Whisper security graph in your browser: a live safety verdict on every site, plus a dashboard of where your devices go.
- **Category:** Privacy & Security
- **Language:** English

**Description:**

Whisper Guard brings the Whisper security graph into your browser: a live
verdict on every site, and a dashboard of where your devices actually go.

The moment you install it, the toolbar mark answers "is THIS site safe?" on
every page you visit, with no account needed: green for no known threat, amber
for suspicious, a red stop plate reserved for evidenced-malicious sites, and an
honest UNKNOWN for the internet's long tail. Click the mark for who runs the
site and where it lives, how old the domain is, the threat feeds it is listed
in, and a look-alike neighborhood confirmed against the graph.

An on-device detector also checks every site against 800+ heavily phished
brands: homoglyph tricks (paypa1.com, Cyrillic lookalikes), swapped endings
(paypal.tk), hyphen squats (face-book.com), fake subdomains
(paypal.com.evil.example) and combo squats (paypal-secure-login.com). One tap
takes you to the real site. Right-click any link to vet it before you open it.

The "This browser" dashboard shows where this browser goes, enriched through the
graph: which companies answer, in which countries, on which networks, and what
is flagged. No account needed.

Sign in free (one tap, no API key to handle) to unlock your whole fleet: every
device and agent on your Whisper account in one view, per-endpoint drill-downs
with an explainable identity-health score, and the option to route this browser
itself through Whisper egress so it becomes a first-class endpoint with its own
routable identity.

Privacy is the product:
- Only a site's NAME is ever checked. Never the page, the path, what you type,
  or your history. Your on-device destination list never leaves the device.
- The bare hostname goes to exactly one endpoint to answer the safety check and
  is not retained to build a browsing profile. One switch turns the live check
  off, after which only the on-device detector runs and nothing leaves at all.
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

1. `dashboard-this-browser.png` (where this browser goes, keyless)
2. `dashboard-endpoint.png` (per-endpoint drill-down, identity health + receipts)
3. `popup-keyed-malicious.png` (evidenced verdict + composed picture)
4. `toolbar-states.png` (the six states)
5. `warning.png` (the full-page stop)

## Privacy practices tab (the exact answers)

- **Single purpose:** Warns the user before phishing and look-alike websites
  and shows where their devices connect, using an on-device
  brand-impersonation detector plus per-site safety verdicts and destination
  enrichment from the Whisper security graph.
- **Permission justifications:**
  - `webNavigation`: to learn the hostname of the page being visited so it
    can be checked and shown in the "This browser" dashboard. The URL's path,
    query, and content are discarded at parse time.
  - `storage`: local settings, the local verdict cache, the on-device
    destination log, and the sign-in credential. Nothing is synced.
  - `scripting`: used only after the optional Active Shield opt-in, to draw
    the warning banner and password-field caution on flagged sites.
  - `declarativeNetRequest`: to block navigation to known credential-phishing
    sites before the request leaves the browser (Active Shield).
  - `contextMenus`: the "Check this link with Whisper" right-click action.
  - `alarms`: the daily signed brand-corpus update check and the fleet
    activity poll (signed-in dashboard).
  - `activeTab`: to act on the current tab when the user clicks the toolbar
    action.
  - Host permissions (`graph.whisper.security`, `console.whisper.security`,
    `get.whisper.online`, `rdap.whisper.online`): the safety check +
    destination enrichment (hostname only), the sign-in flow, corpus updates,
    and public identity verification of the user's own endpoints (IP literals
    only), respectively. No other host is ever contacted.
  - `proxy`, `webRequest`, `webRequestAuthProvider`, `privacy` (all OPTIONAL):
    requested at runtime only when the user turns on "Protect this browser",
    which routes this browser through Whisper egress so it becomes an endpoint
    on the user's account. `proxy` sets the route, `webRequest` +
    `webRequestAuthProvider` supply the egress credential, and `privacy`
    hardens WebRTC to proxied-only so the source address cannot leak. Off by
    default; keyless users never grant them.
  - `<all_urls>` (optional): requested at runtime only when the user enables
    Active Shield (warnings) or the browser-egress route. The default install
    has no broad host access.
- **Data usage:** Website content: NOT collected. Web history: NOT collected
  (the hostname of the current site is transmitted to answer the user's
  safety check and enrich the dashboard; it is not retained to build a
  profile, and the on-device destination list never leaves the device).
  Personally identifiable information, financial, health, authentication,
  communications, location, user activity: NOT collected.
- **Remote code:** none (MV3, all code in the package).

## After upload

Verify the listing renders, the version matches `package.json`, and the
screenshots are current. First review typically takes a few days.
