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

`npm audit` on a fresh clone reports **three findings, all low, from one
advisory**. None of them reaches a shipped byte, and we would rather say so
here than have you find the number and wonder.

| Advisory | Package | Reached through |
|----------|---------|-----------------|
| [GHSA-gcqx-w48m-w2h4](https://github.com/advisories/GHSA-gcqx-w48m-w2h4) | `deepmerge` | `web-ext` → `addons-linter` |

npm counts it three times because it reports `deepmerge`, `addons-linter` and
`web-ext` as one finding each. The advisory is prototype poisoning of the
object `deepmerge` returns.

- **Not in the extension.** `package.json` declares no runtime dependencies
  at all. `npm audit --omit=dev` reports zero, and neither store package
  contains `node_modules`. The chain exists only in `web-ext`, the Mozilla
  tool that lints and signs the Firefox build.
- **Not exploitable by our use of it.** `addons-linter` merges its own
  configuration with the manifest of the build we just produced. No input
  from outside this repository reaches it.
- **No upstream fix exists** in a `web-ext` we can use. `npm audit fix
  --force` "resolves" it by downgrading `web-ext` to 3.x, which would remove
  the AMO lint and signing gate: a worse security posture, not a better one,
  so we have not done it.

The `image-size` and `adm-zip` advisories this section used to list are gone:
`web-ext` 10.8 moved `addons-linter` onto a fixed `image-size`, and
`adm-zip@0.6.1` fixed the extraction finding. The `overrides` entry keeps
`adm-zip` on `^0.6.0`, so the tree cannot resolve to an older, affected
release.

We re-check this whenever `deepmerge` publishes a fix or `addons-linter`
moves off it. `.github/workflows/dep-audit.yml` blocks CI on the shipped
dependency tree and reports the full tree without blocking.
