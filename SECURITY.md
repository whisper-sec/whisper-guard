# Security policy

Whisper Guard is a security product, and we treat reports about it seriously.

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.6.x   | yes       |

The latest published release is always the supported one.

## Reporting a vulnerability

Please do not open a public GitHub issue for a security vulnerability.

Report it privately, either way below:

- Email **security@whisper.security** with a description, the affected
  version, and reproduction steps.
- Or use GitHub's private vulnerability reporting on this repository
  (Security tab, "Report a vulnerability").

We aim to acknowledge a report within three business days and to keep you
updated as we investigate. If the issue is confirmed, we will work on a fix
and coordinate a disclosure timeline with you; we are happy to credit you
unless you prefer to stay anonymous.

## Scope

This policy covers the Whisper Guard extension in this repository. The
extension's only network endpoints are the public Whisper graph
(`graph.whisper.online`), the sign-in origin (`console.whisper.security`,
the two unauthenticated device-flow endpoints only), the brand-corpus host
(`get.whisper.online`), the public endpoint-identity lookup
(`rdap.whisper.online`), and the public stats endpoint
(`nic.whisper.online`, which is where the graph figures on our surfaces are
read from rather than typed); reports about those services are welcome here and we
will route them to the right team. The console the extension links to,
`console.whisper.online`, is opened in a tab and never fetched from.

## Known advisories in build tooling

`npm audit` on a fresh clone reports **five findings, three high and two
moderate, from three advisories**. None of them reaches a shipped byte, and we
would rather say so here than have you find the number and wonder.

| Advisory | Package | Reached through |
|----------|---------|-----------------|
| [GHSA-w3rx-r6r6-pgpr](https://github.com/advisories/GHSA-w3rx-r6r6-pgpr) | `image-size@2.0.2` | `web-ext` → `addons-linter` |
| [GHSA-5p2g-fcmc-qvqq](https://github.com/advisories/GHSA-5p2g-fcmc-qvqq) | `image-size@2.0.2` | `web-ext` → `addons-linter` |
| [GHSA-vwc7-r8mq-g2x9](https://github.com/advisories/GHSA-vwc7-r8mq-g2x9) | `adm-zip@0.6.0` | `web-ext` → `firefox-profile` |

The two `image-size` advisories are denial-of-service in image decoders
(ICNS, JXL, HEIF).

- **Not in the extension.** `package.json` declares no runtime dependencies
  at all. `npm audit --omit=dev` reports zero, and neither store package
  contains `node_modules`. The chain exists only in `web-ext`, the Mozilla
  tool that lints and signs the Firefox build.
- **Not exploitable by our use of it.** The vulnerable decoders parse ICNS,
  JXL and HEIF. This repository contains no image in any of those formats;
  every image here is PNG or SVG.
- **No upstream fix exists.** `image-size@2.0.2` is the current published
  release and the advisories cover `<= 2.0.2`. `addons-linter` pins it
  exactly, and `web-ext` pins `addons-linter` exactly, so no version bump
  resolves it. `npm audit fix --force` "resolves" it by downgrading `web-ext`
  five major versions, which would remove the AMO lint and signing gate: a
  worse security posture, not a better one, so we have not done it.

The moderate one is `adm-zip`, which follows symlinks in a destination path
while extracting, so a crafted archive can write outside the target
directory.

- **Not in the extension**, for the same reason: it is reached through
  `web-ext`, which builds the Firefox profile during a signing run.
- **Not exploitable by our use of it.** The finding needs an attacker to
  choose the archive being extracted. `web-ext` uses `adm-zip` to assemble a
  profile out of files this repository authors; we never extract an archive
  we did not just build.
- **No upstream fix exists.** `adm-zip@0.6.0` is the newest published release
  and the advisory covers `>= 0.5.9 <= 0.6.0`.
- **About the `overrides` entry.** `package.json` pins `adm-zip` to `^0.6.0`.
  That pin was written for an earlier advisory and does not resolve this one,
  so read it as a floor rather than a fix: it keeps the tree on the newest
  release instead of letting it resolve to an older version that is equally
  affected, and it will take a `0.6.x` patch the day one is published.

We re-check this whenever `image-size` publishes a fix or `addons-linter`
moves off it. `.github/workflows/dep-audit.yml` blocks CI on the shipped
dependency tree and reports the full tree without blocking.
