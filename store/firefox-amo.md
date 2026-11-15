# Firefox AMO submission

Upload `dist/whisper-guard-firefox-<version>.zip` (built by
`npm run package`) at addons.mozilla.org. `web-ext lint` must be clean first
(`npm run e2e:firefox` runs it plus a headless load gate).

## Listing

- **Name:** Whisper Guard
- **Add-on ID:** `guard@whisper.security` (already in the manifest)
- **Summary:** The chain behind every site: address, prefix, network, operator, building - and what its neighbours are listed for.
- **Categories:** Privacy & Security
- **License:** MIT
- **Homepage:** https://whisper.online/docs/whisper-guard
- **Support site:** https://github.com/whisper-sec/whisper-guard/issues

**Description:** use the Chrome Web Store description from
`store/chrome-web-store.md` verbatim; it is engine-neutral.

## Data collection (the manifest declares this; keep the two in step)

- `websiteActivity`: the live safety check sends the hostname of the site you
  visit to `graph.whisper.online`, on by default, to answer "is this site
  safe?". Only the bare hostname leaves, never the page, path, or your history,
  and hostnames are not retained to build a browsing profile. One switch in
  settings turns the live check off, after which only the on-device look-alike
  detector runs and nothing leaves at all.

- `websiteContent`: the on-demand page scan reads the current page's visible
  text when the reader clicks Scan, extracts indicators from it, and sends only
  the hostnames among them. IP addresses, file hashes and CVE ids are shown as
  Not assessed and never sent. The page text itself never leaves the browser.

  It is declared because reading the page IS collecting website content, even
  though the text does not leave. This is the same answer we give Google, whose
  "Website content" box has been ticked since 2.6.0, and the symmetry is
  deliberate: two stores being told two different things about one feature is
  how a disclosure stops being trustworthy. It sits under `required` rather than
  `optional` because there is no separate grant for it; a click is not a
  permission, so the capability is present in every install and should be
  declared that way. Added in 2.6.1, which is the release that noticed the
  Chrome answer had been ticked for two releases while Firefox's was not.

## Review notes (paste into "Notes for reviewers")

- **What changed since 2.7.0.** Bug fixes only. The permission lists, the
  endpoints and the data categories are unchanged. The console link now opens
  `edr.whisper.security` in a tab (the console's new name; opened, never
  fetched). Each tab's verdict (a hostname, the verdict and the toolbar mark,
  never a URL) is kept in `storage.session` so it survives the background
  script being suspended; nothing is kept for a private-window tab. A check
  answer that arrives after the tab has moved on is discarded.
- `dns`: declared, not optional on Firefox. Used only for `*.ts.net` names; one
  connects directly only if it resolves to a Tailscale address.
- `proxy`: optional, requested on a click when the user turns on "Protect
  this browser". Off by default. Uses `proxy.onRequest` with a
  `proxyAuthorizationHeader`.
- `<all_urls>`: optional, runtime-requested. The default install has no broad
  host access.
- No remote code, no analytics, no external scripts. All assets are bundled.
- No declared content script. `content.js` is injected with
  `scripting.executeScript`, only where the browser's permission model allows
  it (the optional `<all_urls>` grant, or the one tab the user invoked the
  add-on on).
- Build from source: `npm ci && npm run build`; the Firefox package is
  `dist/firefox`. Node 22, esbuild; deterministic and self-checking.

Full notes: https://github.com/whisper-sec/whisper-guard/blob/main/store/firefox-amo.md

## Review notes, background (do not paste)

The full text behind the paste-ready notes above.

- **What changed since 2.7.0.** Five fixes, no new permission, endpoint or
  data category; both manifests differ from 2.7.0 in the version alone.
  "Open in console" and "Open the console" now open `edr.whisper.security`,
  the console's new name, instead of its old name, which only redirects
  there; it is opened in a tab and never fetched, so it needs no host
  permission. The toolbar mark is repainted after every main-frame
  navigation, because the browser resets it there. A check answer that
  arrives after the tab has navigated elsewhere is discarded before it can
  paint, store, block or inject anything. Each tab's settled state (a
  hostname, the verdict and the mark, never a URL) is mirrored to
  `storage.session` so the popup still has it after the background script is
  suspended; it is never written for a private-window tab, or when the window
  kind cannot be read. The dashboard's 30 second refresh alarm now exists only
  while a dashboard is open.
- **What changed in 2.7.0.** With the opt-in routing on, tailnet,
  private-network and intranet destinations connect directly. Firefox now
  declares `dns`, which is required because Firefox does not allow it as
  optional. `dns` is used only while routing is on, and only to look up
  `*.ts.net` names, to tell a tailnet node from a public Funnel host. The
  shared background code now generates a PAC script for Chromium. The Firefox
  build carries that generator (egressPacScript) but never runs it; on Firefox
  the same decision runs in `proxy.onRequest`. No endpoint or data-collection
  category changed.
- **What changed in 2.6.1, and why a new data category appears.** The code
  change is small: the proxy hooks that route this browser through Whisper
  egress are now registered in the background script's first turn instead of
  after a storage read, because registering them late meant Chromium asked the
  user for a proxy password on every restart and Firefox routed direct until
  the handler existed. No permission, endpoint or capability changed, and the
  permission lists are byte-identical to 2.6.0. The manifest does declare one
  additional data collection category, `websiteContent`, and that is a
  disclosure correction rather than a behaviour change: the on-demand page scan
  has read page text since 2.6.0 and the Chrome listing has declared the
  equivalent category since then, while this manifest declared only
  `websiteActivity`. Two stores were being told different things about one
  feature, so this release makes them agree. Nothing new is collected in 2.6.1;
  what was already collected is now declared here too.
- Build from source: `npm ci && npm run build`; the Firefox package is
  `dist/firefox`. Node 22, esbuild; the build is deterministic and
  self-checking.
- The network endpoints are: `graph.whisper.online` (both graph arms on one
  host: the safety check + destination enrichment, hostname only, the only
  thing a browsing hostname ever reaches; and the signed-in control plane,
  the user's own fleet roster, enrollment and egress, always keyed and never
  carrying a browsing hostname), `console.whisper.security` (RFC 8628
  device-flow sign-in only, two unauthenticated endpoints, no browsing data;
  it is a sign-in origin and never a destination), `get.whisper.online` (signed
  brand-corpus updates, no browsing data), `rdap.whisper.online` (public
  identity verification of the user's own endpoints, IP literals only, no
  browsing hostname), and `nic.whisper.online` (the public network statistics
  document: a plain GET of one public JSON file, no query string, no header,
  no body, no cookie, so nothing about the user can ride on it; it is how the
  live size of the graph and the resolvers' latency reach the UI instead of
  being written into the build as a constant that would be stale on release
  day. `e2e/graph-endpoints.spec.ts` asserts that shape from the outside). The add-on also OPENS `edr.whisper.security` in a tab
  when the user asks for the console; it is never fetched from, which is why
  it is not in the host permissions. The e2e suite (`e2e/mocked.spec.ts`)
  proves the hostname-only invariant with a full network capture, and
  `e2e/console-links.spec.ts` proves where each console link actually lands.
- No remote code, no analytics, no external scripts. All assets are bundled.
- There is NO declared content script. `content.js` is injected programmatically
  with `scripting.executeScript`, and only where the browser's own permission
  model already allows it: on every eligible page under the optional
  `<all_urls>` Active Shield grant, and otherwise on the one tab the user
  invoked the add-on on (activeTab, via opening the popup). It carries the
  capture-phase click and form-submit hold that checks a destination HOSTNAME
  before the action lands, the local cookie-consent decline (which clicks a
  consent banner's own reject control, at most once per document, and which
  runs in a page's sub-frames as well as its top document, because that is
  where most large publishers render the wall, under the same rules
  everywhere, so a page carrying both a top-level banner and a framed consent
  wall may see one click in each), and, under Active Shield, the amber banner
  and the password-field caution. Everything it draws lives in a closed
  shadow root. The only things it ever hands the background are a bare
  hostname and a win category. The on-demand page scan (2.6.0) reads the visible
  text of the current page when the reader clicks Scan, and transmits only the
  hostnames among the indicators it finds. Nothing else reads or transmits page
  text, paths,
  queries, or form values.
- `proxy` is an OPTIONAL permission, requested only on a user click when the
  user turns on "Protect this browser" (routes this browser through Whisper
  egress so it becomes a first-class endpoint on the user's account). It is off
  by default; keyless users never grant it. Firefox uses `proxy.onRequest` with
  a `proxyAuthorizationHeader`.
- `dns` is a declared permission (Firefox does not allow it as optional). It is
  used only while routing is on, to look up `*.ts.net` names and nothing else.
  The lookup tells a tailnet node from a public Tailscale Funnel host: a
  `*.ts.net` name connects directly only when it resolves to a Tailscale
  address, otherwise it stays on the route. While routing is on,
  private-network, intranet and tailnet destinations connect directly.
- `<all_urls>` is optional and runtime-requested (Active Shield on-page
  warnings, the pre-click link sweep with this-site access requested per site,
  and the egress route); the default install has no broad host access.
- The brand corpus is bundled and works offline from first install. The
  daily update channel to `get.whisper.online` activates only once the
  corpus signing key is published; until then no request is made to that
  host, and an unsigned corpus payload is always rejected. So the declared
  `get.whisper.online` host permission may show no traffic during review;
  that is expected.

## Screenshots

Same set as the Chrome listing, from `shots/`.
