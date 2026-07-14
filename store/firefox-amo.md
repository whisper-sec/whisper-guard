# Firefox AMO submission

Upload `dist/whisper-guard-firefox-<version>.zip` (built by
`npm run package`) at addons.mozilla.org. `web-ext lint` must be clean first
(`npm run e2e:firefox` runs it plus a headless load gate).

## Listing

- **Name:** Whisper Guard
- **Add-on ID:** `guard@whisper.security` (already in the manifest)
- **Summary:** Phishing protection that works the instant it installs. On-device look-alike alerts; a live safety signal when you sign in.
- **Categories:** Privacy & Security
- **License:** MIT
- **Homepage:** https://whisper.online/docs/whisper-guard
- **Support site:** https://github.com/whisper-sec/whisper-guard/issues

**Description:** use the Chrome Web Store description from
`store/chrome-web-store.md` verbatim; it is engine-neutral.

## Data collection (the manifest already declares this)

- `data_collection_permissions.required = ["none"]`: the extension collects
  nothing by default.
- `data_collection_permissions.optional = ["websiteActivity"]`: signing in
  opts into sending the hostname of visited sites to answer the live safety
  check. Hostnames are not retained to build a browsing profile.

## Review notes (paste into "Notes for reviewers")

- Build from source: `npm ci && npm run build`; the Firefox package is
  `dist/firefox`. Node 22, esbuild; the build is deterministic and
  self-checking.
- The only network endpoints are `graph.whisper.security` (safety check,
  hostname only, signed-in users only), `console.whisper.security` (RFC 8628
  device-flow sign-in), and `get.whisper.online` (signed brand-corpus
  updates). The e2e suite (`e2e/mocked.spec.ts`) proves the hostname-only
  invariant with a full network capture.
- No remote code, no analytics, no external scripts. All assets are bundled.
- `<all_urls>` is optional and runtime-requested (Active Shield); the
  default install has no broad host access.
- The brand corpus is bundled and works offline from first install. The
  daily update channel to `get.whisper.online` activates only once the
  corpus signing key is published; until then no request is made to that
  host, and an unsigned corpus payload is always rejected. So the declared
  `get.whisper.online` host permission may show no traffic during review;
  that is expected.

## Screenshots

Same set as the Chrome listing, from `shots/`.
