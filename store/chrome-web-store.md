# Chrome Web Store submission

Everything the CWS dashboard asks for, ready to paste. Upload
`dist/whisper-guard-chromium-<version>.zip` (built by `npm run package`).

## Listing

- **Name:** Whisper Guard
- **Summary (132 max):** The chain behind every site: address, prefix, network, operator, building - and what its neighbours are listed for.
- **Category:** Privacy & Security
- **Language:** English

**Description:**

Whisper Guard shows you the CHAIN behind a site, not just a verdict on it. Click
the toolbar mark and Guard walks the graph: the name and how long ago it was
registered, what runs on it, the address it answers on and the city that address
is in, the prefix that address is announced in, the network that announces the
prefix, the operator that holds the network, and the buildings and internet
exchanges that operator is physically present in. Seven rungs, seven joins, no
account needed.

That walk answers what a verdict cannot. A name can be clean while the block it
sits in is not: neighbouring addresses in the same prefix listed as threats, an
operator present in over a thousand facilities, a domain observed for years.
Guard shows which of those it found and what it concludes from them.
Expand any rung for what is behind it: how much of that network's announced space
is actually listed, how many other names answer on that address, every facility
by name.

Each rung says one of three things and never confuses them: it has a value, the
graph answered and holds nothing there, or the read did not come back. The third
is drawn in amber and says so, because an outage that renders as an empty row is
an outage that reads as safety.

Guard also does what every extension in this category does, and does it with no
account: the toolbar mark answers "is THIS site safe?" on every page you visit -
green for no known threat, amber for suspicious, a red stop plate reserved for
evidenced-malicious sites, and an honest UNKNOWN for the internet's long tail.

The panel also shows the graph's own score and the named, weighted feed listings
behind the verdict, plus a look-alike neighborhood confirmed against the graph.

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
with an explainable identity-health score, and one control that gives this
browser its own routable Whisper IPv6 identity and routes its traffic out
through it, so it becomes a first-class endpoint anyone can verify by public
RDAP. The same one control is in the toolbar panel and on the dashboard.

Cookie banners are answered for you, in their own language. English, German,
French, Spanish, Italian, Dutch, Portuguese, Polish, Swedish, Danish,
Norwegian, Finnish, Czech, Turkish and Romanian, using the banner's own reject
control so the page starts in its most private configuration. A wall whose
only refusal costs money is left strictly alone: "Reject all and subscribe" is
a paywall, and pressing it on your behalf would be a purchase.

On a flagged site, Guard speaks up when a credential-shaped field takes focus,
and names what it caught: a password, a one-time code, card details, or a
wallet recovery phrase, which gets the strongest wording there is because that
loss is the one with no chargeback. It warns once per kind and stays quiet on
a search box or an email field.

Signed out, the panel shows your real remaining budget on the public graph
tier, read from the graph itself, so "sign in" is a fact about a ceiling you
can see rather than an advertisement. The size of the graph behind every
verdict is read live too, along with the resolvers' own pulse over the last 24
hours. No figure about our coverage is ever written into the build.

Every surface follows your system's light or dark setting, and all of them use
the same design system as the Whisper console, so moving between the two is
moving inside one product.

Privacy is the product:
- Only a site's NAME is ever checked. Never the page, the path, what you type,
  or your history. Your on-device destination list never leaves the device.
- The bare hostname goes to exactly one endpoint to answer the safety check and
  is not retained to build a browsing profile. One switch turns the live check
  off, after which only the on-device detector runs and nothing leaves at all.
- No telemetry, no analytics, no sync. Open source (MIT).

Whisper also holds a click before it lands: following a link to another site,
or submitting a form off-origin, pauses just long enough to check that
destination's name, and an evidenced-malicious destination gets an inline
panel with the verdict, the receipts, and both exits. The destination is never
contacted and nothing you typed leaves the page. If Whisper is slow or
unreachable the click simply proceeds. A calm line in the panel counts what
was handled for you today, by category only, never which sites, and there is
no toast or notification anywhere.

Optional Active Shield adds a full-page stop before known credential-phishing
pages, a caution when a password field gains focus on a flagged site, and an
amber banner on look-alikes. It asks for the browser's own on-page permission
only when you turn it on, and declining it keeps everything else working.

If Whisper is unreachable the extension fails open: browsing is never blocked
and the on-device protection keeps running.

- **Homepage URL:** https://whisper.online/docs/whisper-guard
- **Support URL:** https://github.com/whisper-sec/whisper-guard/issues
- **Privacy policy URL:** https://whisper.online/privacy

## Screenshots (1280x800 or 640x400)

Use the gallery in `shots/` (regenerate with
`npx playwright test e2e/screenshots.spec.ts`):

Upload them in the order `scripts/frame-store-shots.mjs` numbers them, so the
listing order and the filenames agree:

1. `01-toolbar-states.png` (the six states) <- `toolbar-states.png`
2. `02-popup-keyed-malicious.png` (evidenced verdict + composed picture) <- `popup-keyed-malicious.png`
3. `03-dashboard-this-browser.png` (where this browser goes, keyless) <- `dashboard-this-browser-store.png`
4. `04-warning.png` (the full-page stop) <- `warning-store.png`
5. `05-dashboard-endpoint.png` (per-endpoint drill-down, identity health + receipts) <- `dashboard-endpoint-store.png`

The three `-store` captures are the page-scale surfaces taken at the store's
own 1280x800 aspect. Their tall full-page twins (`dashboard-this-browser.png`
and friends) are gallery figures: framing one of those for the store shrinks it
to a 531px-wide strip with black either side and nothing legible in it, which
is what shipped before 2.4.0. `scripts/frame-store-shots.mjs` composes exactly
the five named above; run it rather than framing by hand.

The gallery also captures `preempt-interstitial.png` (a click held before it
lands) and `popup-today.png` (the session block ledger plus what Guard handled
quietly today). The listing submits the five above; those two carry the
pre-emptive story on the docs page instead.

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
  - `scripting`: injects Whisper's own on-page code (never remote code) for
    three things: the capture-phase click/form-submit hold that checks a
    destination HOSTNAME before the action lands and draws the inline warning
    panel; the optional cookie-consent decline, which inspects the page locally
    for a consent banner and clicks that banner's own reject control at most
    once per document, and which runs in a page's sub-frames as well as its
    top document because that is where most large publishers render the wall,
    under the same rules everywhere (so a page carrying both a top-level
    banner and a framed consent wall may see one click in each); and, after
    the Shield opt-in, the amber banner and password-field caution on flagged
    sites. It also reads, on the user's click, only the `<a href>` HOSTNAMES
    of the current page for the pre-click link sweep. Page text, paths,
    queries and form values are never read and never transmitted; every panel
    renders in a closed shadow root.
  - `declarativeNetRequest`: to block navigation to evidenced-malicious sites
    before the request leaves the browser: the full-page stop under Active
    Shield, and a session-scoped rule for a single host whose click was just
    held, so the same destination cannot slip through in another tab. Every
    session block is listed in the popup with a one-click clear.
  - `contextMenus`: the "Check this link with Whisper" right-click action.
  - `alarms`: the daily signed brand-corpus update check and the fleet
    activity poll (signed-in dashboard).
  - `activeTab`: to act on the current tab when the user clicks the toolbar
    action.
  - Host permissions (`graph.whisper.online`, `console.whisper.security`,
    `get.whisper.online`, `rdap.whisper.online`): the graph, carrying both the
    safety check + destination enrichment (hostname only) and the signed-in
    control plane (the user's own fleet, always keyed, never a browsing
    hostname); then the sign-in flow (two unauthenticated RFC 8628 endpoints
    only), corpus updates, and public identity verification of the user's own
    endpoints (IP literals only). No other host is ever contacted. The
    extension also OPENS console.whisper.online in a tab when the user asks
    for the console; it is never fetched from, so it needs no host permission.
  - `proxy` (REQUIRED), `webRequest`, `webRequestAuthProvider`, `privacy`
    (OPTIONAL): power "Protect this browser", which routes this browser through
    Whisper egress so it becomes an endpoint on the user's account. `proxy`
    sets the route; Chrome does not permit `proxy` to be an optional permission,
    so it is declared required, but it is only ACTIVATED when the user turns
    routing on, never before. `webRequest` + `webRequestAuthProvider` supply the
    egress credential and `privacy` hardens WebRTC to proxied-only; these three
    are requested at runtime on that same click. Routing is off by default; the
    proxy setting is never touched until the user opts in.
  - `<all_urls>` (optional): requested at runtime only when the user enables
    Active Shield (warnings), the pre-click link sweep (this-site access,
    requested per site), or the browser-egress route. The default install has
    no broad host access.
- **Data usage:** Web history: COLLECTED, and it is the only category ticked.
  Google counts transmitting the current site's hostname off the device as
  collection even though we do not retain it to build a profile, so the
  honest answer is yes. Nothing else is collected: not website content, not
  personally identifiable information, financial, health, authentication,
  communications, location, or user activity. The on-device destination log
  never leaves the device and page content is never read. The exact wording
  for the form is in `cws-submission-fields.md`, which is the source of
  truth for the answers typed into the console.
- **Remote code:** none (MV3, all code in the package).

## After upload

Verify the listing renders, the version matches `package.json`, and the
screenshots are current. First review typically takes a few days.
