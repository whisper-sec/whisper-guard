# Firefox AMO submission

Upload `dist/whisper-guard-firefox-<version>.zip` (built by
`npm run package`) at addons.mozilla.org. `web-ext lint` must be clean first
(`npm run e2e:firefox` runs it plus a headless load gate).

## Listing

- **Name:** Whisper Guard
- **Add-on ID:** `guard@whisper.security` (already in the manifest)
- **Summary:** The Whisper security graph in your browser: a live safety verdict on every site, plus a dashboard of where your devices go.
- **Categories:** Privacy & Security
- **License:** MIT
- **Homepage:** https://whisper.online/docs/whisper-guard
- **Support site:** https://github.com/whisper-sec/whisper-guard/issues

**Description:** use the Chrome Web Store description from
`store/chrome-web-store.md` verbatim; it is engine-neutral.

## Data collection (the manifest already declares this)

- `data_collection_permissions.required = ["websiteActivity"]`: the live safety
  check sends the hostname of the site you visit to `graph.whisper.security`,
  on by default, to answer "is this site safe?". Only the bare hostname leaves,
  never the page, path, or your history, and hostnames are not retained to build
  a browsing profile. One switch in settings turns the live check off, after
  which only the on-device look-alike detector runs and nothing leaves at all.

## Review notes (paste into "Notes for reviewers")

- Build from source: `npm ci && npm run build`; the Firefox package is
  `dist/firefox`. Node 22, esbuild; the build is deterministic and
  self-checking.
- The network endpoints are: `graph.whisper.security` (the safety check +
  destination enrichment, hostname only), `console.whisper.security` (RFC 8628
  device-flow sign-in, no browsing data), `get.whisper.online` (signed
  brand-corpus updates, no browsing data), and `rdap.whisper.online` (public
  identity verification of the user's own endpoints, IP literals only, no
  browsing hostname). The e2e suite (`e2e/mocked.spec.ts`) proves the
  hostname-only invariant with a full network capture.
- No remote code, no analytics, no external scripts. All assets are bundled.
- `proxy` is an OPTIONAL permission, requested only on a user click when the
  user turns on "Protect this browser" (routes this browser through Whisper
  egress so it becomes a first-class endpoint on the user's account). It is off
  by default; keyless users never grant it. Firefox uses `proxy.onRequest` with
  a `proxyAuthorizationHeader`.
- `<all_urls>` is optional and runtime-requested (Active Shield on-page
  warnings, and the egress route); the default install has no broad host access.
- The brand corpus is bundled and works offline from first install. The
  daily update channel to `get.whisper.online` activates only once the
  corpus signing key is published; until then no request is made to that
  host, and an unsigned corpus payload is always rejected. So the declared
  `get.whisper.online` host permission may show no traffic during review;
  that is expected.

## Screenshots

Same set as the Chrome listing, from `shots/`.
