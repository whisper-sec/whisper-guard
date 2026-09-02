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

## Data collection (the manifest already declares this)

- `data_collection_permissions.required = ["websiteActivity"]`: the live safety
  check sends the hostname of the site you visit to `graph.whisper.online`,
  on by default, to answer "is this site safe?". Only the bare hostname leaves,
  never the page, path, or your history, and hostnames are not retained to build
  a browsing profile. One switch in settings turns the live check off, after
  which only the on-device look-alike detector runs and nothing leaves at all.

## Review notes (paste into "Notes for reviewers")

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
  day. `e2e/graph-endpoints.spec.ts` asserts that shape from the outside). The add-on also OPENS `console.whisper.online` in a tab
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
  hostname and a win category; it never reads or transmits page text, paths,
  queries, or form values.
- `proxy` is an OPTIONAL permission, requested only on a user click when the
  user turns on "Protect this browser" (routes this browser through Whisper
  egress so it becomes a first-class endpoint on the user's account). It is off
  by default; keyless users never grant it. Firefox uses `proxy.onRequest` with
  a `proxyAuthorizationHeader`.
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
