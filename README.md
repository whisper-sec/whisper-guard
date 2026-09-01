# Whisper Guard

The Whisper security graph, native in your browser. On-device look-alike
detection starts the instant you install it, and a live graph verdict answers
"is THIS site safe?" on every site you visit, with no account needed. A
dashboard shows where this browser (and, signed in, every device on your
account) actually goes: who answers, in which country, on which network, and
whether anything is flagged. Sign in free to unlock your whole fleet and, if
you want, put this browser itself on the Whisper network with its own routable
identity.

Only a site's name is ever checked. Never the page, never the path, never your
history.

## Two tiers, both a full product

**No account (fully keyless, works the instant it installs):**

- **Live graph verdict on every site.** The toolbar mark answers "is THIS site
  safe?" from the Whisper security graph: green for no known threat, amber for
  suspicious, a filled red octagon plate reserved for evidenced-malicious, and
  an honest dashed-slate UNKNOWN for the internet's long tail. Never a fake
  green. Popularity feeds (Tranco and friends) are treated as good, never as a
  threat.
- **The composed picture, WHY included.** Click the mark for who runs the site
  and where it lives, how old the domain is, and the WHY behind the verdict
  shown by default: the graph's score and its named, weighted factors (each
  threat-feed listing with its weight; popularity listings shown as good
  standing), plus a look-alike neighborhood confirmed against the graph.
- **Page-link pre-verdicts.** One click reads every link on the current page
  and verdicts each destination BEFORE you visit any of them: malicious,
  suspicious, unknown, or clean, riskiest first. The links are reduced to bare
  hostnames inside the page itself; only those names are checked, never the
  page, its text, or your history. No new permissions.
- **On-device look-alike detection.** Homoglyph tricks (`paypa1.com`, Cyrillic
  `pаypal.com`), TLD swaps (`paypal.tk`), hyphenation squats (`face-book.com`),
  brand-subdomain abuse (`paypal.com.evil.example`) and combosquats
  (`paypal-secure-login.com`), across a bundled corpus of 800+ heavily phished
  brands. One tap goes to the real site. This runs entirely on-device and is the
  zero-network fallback if you switch the live check off.
- **The "This browser" dashboard.** A full-tab, console-style view of where this
  browser goes, built from your on-device navigation log and enriched through
  the graph: destination / company / country / network tiles, a category donut,
  company and country breakdowns, a concentration callout, and an activity
  ledger that updates live per navigation. Zero extra permissions.
- **Pre-click check.** Right-click any link and pick "Check this link with
  Whisper" to vet the destination before anything loads.
- **Pre-emptive interruption.** A click on a link leaving for a different
  registrable domain, or a form posting off-origin, is caught in the capture
  phase and held while the destination's hostname is checked. On evidenced
  malice an inline panel shows the verdict, the label, the coverage and the two
  exits (go back, or proceed anyway); the target is never contacted and nothing
  you typed leaves the page. Everything else resumes untouched, and so does
  every click if the graph is slow or unreachable: the check has a hard budget
  and fails open. Cached verdicts answer with no network at all. It needs no
  broad host permission and no account: it arms wherever the browser already
  lets Guard run, which is every page once Active Shield is on and otherwise
  the one tab you open Guard on.
- **Cookie prompts declined for you.** Where the on-page layer runs (the same
  places as the pre-emptive guard above), a consent banner is answered with its
  own reject control so the page starts in its most private configuration. It
  is deliberately timid: it acts only on a known consent platform's own reject
  control, or on a decline-labelled button inside a banner that says
  cookie/consent/GDPR outright and offers an accept next to it. Anything less
  certain is left alone and the whole thing runs on-device: nothing about the
  page is sent anywhere. It reads each frame's own DOM, including the iframes
  where most large publishers keep their wall, under exactly the same rules
  everywhere: a frame is a smaller document, not a laxer one. A consent wall
  inside a shadow root is still out of reach and is left untouched rather than
  guessed at. However many walls a page turns out to have, the tally counts
  the page once, because that is what was handled for you. Off with one
  switch.
- **A calm tally of what it handled.** One line in the panel counts today's
  quiet wins by category (clicks held, identities verified, cookie prompts
  declined) and nothing else: the record is a category, a count and today's
  date, so it resets on its own and can never learn a site you visited. There
  is no toast, no badge nag and no notification anywhere, because the extension
  holds no notifications permission at all.

**Signed in (free, one tap, no API key to handle):**

- **Your whole fleet, one view.** Every device and agent on your Whisper account,
  their last-24h destinations merged and graph-enriched into the same panels.
- **Per-endpoint drill-down.** Live counters, an explainable identity-health
  score (each factor shown met / unmet / unknown, never a black box), a
  connection constellation from the endpoint to where it went, and destination
  receipts with co-hosting fan-in and announcing-prefix threat neighbours. Every
  identity is anchored by an RDAP provenance link.
- **Protect this browser (opt-in, off by default).** One control in the panel
  does the whole thing: it reserves this browser's own routable Whisper
  identity (a real IPv6 address with reverse-DNS, verifiable by anyone via
  public RDAP) and routes the browser's traffic out through that identity, so
  it joins your fleet as a device whose activity you can audit. WebRTC is
  hardened to proxied-only so nothing leaks around the route.

  The two halves are separate underneath, which is what lets the failures stay
  honest. The identity is pure control plane: no browser permission, reserved
  first, and it stands whatever happens next. Routing needs the optional proxy
  permissions, asked for on that click. Refuse them, or let a VPN or proxy
  manager keep the browser's single-owner proxy setting, and you still have the
  identity and the verdicts; the panel names what is in the way and offers the
  way out. Routing is never a dead end, and the same button turns it off.
- Sign-in is the RFC 8628 device flow: you approve in the Whisper console and
  the extension receives its credential. You never see or paste a key.

**Active Shield (optional, off by default):**

- A single toggle that asks the browser for on-page permission, used only to
  draw warnings: a full-page stop before known credential-phishing pages (with
  the feed-cited receipts), a slim amber banner on look-alikes, and a caution
  when a password field gains focus on a flagged site. Decline it and everything
  else still works, pre-emptive interruption included: that layer is arranged so
  the browser's own permission model decides where it runs, so it reaches every
  page under this grant and, without it, the tab you invoked Guard on.

## How loud Guard is allowed to get

One table decides, for every surface: silent, ambient (the toolbar mark and a
single badge pulse), pre-emptive (hold the action you are taking and show the
receipts first), conversational (a dismissible word on the page), blocking (the
full-page stop). Most of the table is silent, and the whole no-evidence row is
silent, which is where the overwhelming majority of browsing lands. Guard
escalates only when the finding is urgent, actionable, and you are the right
person to act on it. De-noising is never hiding: the raw verdict is always one
popup click away, whatever the table decided.

The table has a column per moment, and the moments are genuinely different.
Answering the page verdict answers the page: click through a known-threat
warning and Guard does not re-block it, re-banner it, or ask again. Typing a
password into that site is a different moment with a different stake, so the
caution at the password field still appears, once, dismissible, never a block.
A softer verdict you waved through stays fully silent.

## Honest scope

The graph verdict reports UNKNOWN for most of the web, because that is the
truth: absence of evidence is shown as absence of evidence. Coverage is shown as
a category (known-clean, partial, no-data), never dressed up as a percentage or
a safety score. The on-device tier catches look-alikes of major brands you
navigate to; it does not catch compromised legitimate sites or brand-new
domains on its own. The fleet, per-endpoint and browser-egress features need an
account; the verdict, the composed picture, the this-browser dashboard and
public identity verification all work with no key.

## Privacy model

- The only browsing datum that can ever leave the browser is a **hostname**,
  sent to exactly one endpoint, `graph.whisper.online`, whether or not you are
  signed in. Extraction happens at parse time; path, query, fragment, page
  content, and form data are discarded before any network code runs. Your
  on-device navigation list and session allow-list never leave the device.
- The same host also carries the keyed control plane: your fleet roster,
  enrollment and egress, always with your key and never with a browsing
  hostname. Signed out, that half is never called at all. The two are separate
  calls with separate rules, and the rules are properties of the request, not
  of the hostname: a read is keyless-capable and carries a bare hostname, a
  control call is always keyed and carries no browsing datum.
- `console.whisper.security` is contacted only during sign-in (no browsing
  data). `get.whisper.online` is contacted only for signed brand-corpus
  updates (no browsing data). `rdap.whisper.online` is contacted only to verify
  the identity of your own endpoints, and only receives IP literals of those
  endpoints, never a browsing hostname.
- Verdicts are cached locally and navigations debounced, so revisits paint
  from cache with zero network.
- Hostnames are used to answer the live safety check, not retained to build a
  browsing profile.
- No telemetry, no analytics, no sync. The credential lives in local extension
  storage only. Internal pages (`chrome://`), localhost, private addresses,
  IP literals, and `.local`/`.internal` names are never checked at all.
- Every panel view states exactly what was sent for the current site.

Docs: [whisper.online/docs/whisper-guard](https://whisper.online/docs/whisper-guard) ·
Screenshots: [`shots/`](shots/index.html)

## Install

Chrome Web Store and Firefox AMO listings are in submission. Until they land,
load the built extension directly:

```bash
npm ci
npm run build
```

Then in Chrome / Edge / Brave / Opera / Vivaldi:

1. Open `chrome://extensions`
2. Enable "Developer mode"
3. "Load unpacked" and pick `dist/chromium`

In Firefox: open `about:debugging#/runtime/this-firefox`, choose "Load
Temporary Add-on", and pick `dist/firefox/manifest.json`.

## Build and development

```bash
npm run typecheck        # strict TypeScript, no emit
npm run build            # typecheck + build dist/chromium and dist/firefox
npm run build:chromium   # one target
npm run package          # zip both targets for store upload
npm run icons            # regenerate icon PNGs from the brand mark in assets/logo.png (ImageMagick)
npm run psl              # refresh the vendored Public Suffix List snapshot
```

The build is esbuild + a manifest transform per target, and it self-checks:
a dist missing any file the manifest references fails the build.

## End-to-end tests

The e2e suite loads the real built extension into Chromium with Playwright.
The hermetic suites point the whole browser at a local capture proxy, so the
request log is a complete record of everything that left the browser; the
hostname-only privacy invariant is asserted against that full capture, not a
sample.

```bash
npm run e2e              # hermetic: protection, dashboard, egress, Active Shield
npm run e2e:firefox      # web-ext lint (zero findings) + headless load gate
WHISPER_GUARD_E2E_KEY=... npm run e2e:live   # against the real production graph
npx playwright test e2e/screenshots.spec.ts  # regenerate shots/
```

The browser-as-endpoint feature has its own hard dual-engine e2e
(`e2e/egress.spec.ts`): it flips the toggle, then proves the browser is actually
routed through the Whisper egress endpoint (its own registered identity), that
the identity appears in the account roster, and that keyless RDAP
verify-identity of the routed address returns `is_whisper_agent: true`. It is
never a structural pass. `e2e/enroll.spec.ts` proves the split: enrollment
succeeds with zero proxy permissions granted (and no traffic routed), and a
REAL second proxy-holding extension cannot dead-end the flow: the browser
still enrolls, and the conflict renders as an explanation with a way forward.
`e2e/links.spec.ts` proves the page-link sweep against the full capture: only
registrable hostnames reach the graph; the links' paths, queries and the
page's text never leave the browser.

The live suite picks a currently-listed malicious hostname, pins its DNS to
a local harmless page, and verifies the real verdict end to end; the key is
read from the environment and never appears in any artifact. Fail-open
(graph unreachable means UNKNOWN, never a block) is a tested path.

## Store packaging

`npm run package` produces `dist/whisper-guard-chromium-<v>.zip` and
`dist/whisper-guard-firefox-<v>.zip`. Listing copy, permission
justifications, and reviewer notes live in [`store/`](store/).

## Architecture

```
src/
  shared/      config, types, messages, the offline Public Suffix List,
               the hostname chokepoint (the one place URLs are parsed), and
               the escalation ladder (the one place loudness is decided)
  detector/    the on-device engine: punycode decode, confusable skeleton,
               the bundled brand corpus, candidate generation
  background/  MV3 service worker: navigation pipeline, verdict cache,
               per-tab icon state, graph client (assess/explain/identify/
               submit), RFC 8628 device flow, context menu, corpus updater,
               Active Shield (DNR rules + injection), the pre-emptive target
               check, and the local daily-wins tally
  content/     the on-page layers, injected programmatically (there is no
               declared content script) and only where the browser's own
               permission model already allows it: the pre-emptive click and
               form-submit guard plus the cookie-consent decline on any
               eligible page, the amber banner and the password-field caution
               only on flagged hosts and only after the Active Shield opt-in.
               Everything is drawn inside closed shadow roots
  popup/       the click panel
  options/     settings, sign-in, privacy panel
  pages/       full-page warning + pre-click check result
manifests/     manifest.chromium.json, manifest.firefox.json
icons/         pre-rendered PNG state sets (built from the brand mark in assets/logo.png)
```

Default permissions are deliberately minimal: `activeTab`, `webNavigation`,
`storage`, `scripting`, `contextMenus`, `declarativeNetRequest`, `alarms`,
`proxy`, and host access to the four Whisper endpoints above. `proxy` is
declared but inert: Chrome does not allow it to be optional, and Guard never
touches the browser's proxy setting until you turn routing on (in Firefox it is
genuinely optional and requested on that click). There is no `<all_urls>` grant
and no standing content script; broad host access exists only as the optional,
revocable Active Shield permission, requested at runtime.

## Browser support

- **Chromium** (Chrome, Edge, Brave, Opera, Vivaldi): the primary target,
  MV3, `dist/chromium`.
- **Firefox** (142+): built from the same code via a manifest transform,
  `dist/firefox`; verified with web-ext (AMO lint, zero findings) and a
  headless temporary-install load test.
- **Safari**: planned; requires the Safari Web Extension converter and Xcode.

## Fail-open by design

If the graph is slow or unreachable, the icon shows UNKNOWN (never a false
green, never a false red), the on-device protection keeps running, and
browsing is never blocked. An expired sign-in says so plainly and offers to
sign in again.

## License

MIT (c) 2026 viaGraph B.V. (Whisper Security). See `LICENSE`.

The bundled Public Suffix List snapshot is maintained by Mozilla and the PSL
community under the Mozilla Public License 2.0; see `NOTICE`.
