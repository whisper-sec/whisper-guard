// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The on-device look-alike detector: the keyless hero. Runs entirely in the
// browser on every navigation; nothing leaves the device. Precision-ranked
// and FP-gated, per the product spec:
//
//   (a) confusable-skeleton collision on a different registrable domain  HIGH
//   (b) exact-SLD TLD swap                                               HIGH
//   (c) brand-subdomain / combosquat                                     MEDIUM (nudge only)
//   (d) Damerau-Levenshtein=1 near miss              MEDIUM, OFF by default
//
// Suppression comes first: the brand's own domains, the curated
// brand-adjacent allowlist, and the user's own allowlist always win.

import type { CorpusBrand, DetectorHit } from "../shared/types";
import { registrableDomain, splitRegistrable } from "../shared/psl";
import { damerauLevenshtein, skeletonLabel } from "./skeleton";
import { getIndex } from "./corpus";

const NEARMISS_MIN = 5;

function hit(
  kind: DetectorHit["kind"],
  severity: DetectorHit["severity"],
  brand: CorpusBrand,
  matched: string,
): DetectorHit {
  return {
    kind,
    severity,
    brand: brand.name,
    brandDomain: brand.domain,
    matched,
    goTo: `https://${brand.domain}/`,
  };
}

/** True when `token` occurs in `sld` delimited by a hyphen/digit/edge. */
function tokenInLabel(sld: string, token: string): boolean {
  let from = 0;
  for (;;) {
    const i = sld.indexOf(token, from);
    if (i < 0) return false;
    const before = i === 0 ? "-" : sld[i - 1]!;
    const afterIdx = i + token.length;
    const after = afterIdx >= sld.length ? "-" : sld[afterIdx]!;
    const boundary = (c: string) => c === "-" || (c >= "0" && c <= "9");
    if (boundary(before) && boundary(after)) return true;
    from = i + 1;
  }
}

/**
 * Analyze one hostname. Returns the single best hit (by precedence:
 * confusable > tldswap > brand-subdomain > combosquat > nearmiss) or null.
 * `nearMiss` enables the noisier distance-1 tier (settings toggle, default
 * off). `userAllow` is the user's own trusted-domain list.
 */
export async function detect(
  hostname: string,
  nearMiss: boolean,
  userAllow: readonly string[],
): Promise<DetectorHit | null> {
  const idx = await getIndex();
  const host = hostname.toLowerCase().replace(/\.$/, "");
  const reg = registrableDomain(host);
  if (!reg) return null;

  // Suppression first: the brand's own ground, curated allow, user allow.
  if (idx.legit.has(reg) || idx.allow.has(reg)) return null;
  for (const a of userAllow) {
    const al = a.toLowerCase();
    if (reg === al || host === al || host.endsWith("." + al)) return null;
  }

  const { sld, suffix } = splitRegistrable(reg);
  const skel = skeletonLabel(sld);
  const defensiveSuffix = idx.defensive.has(suffix);

  // (a) Confusable-skeleton collision: same skeleton, different registrable
  // domain. A raw-SLD match with only the suffix changed is the TLD-swap
  // axis and carries the anyTld gate; a differing label is a confusable.
  // The hyphen-stripped skeleton is checked too so hyphenation squats
  // (pay-pal, face-book) collapse onto the brand.
  const stripped = skel.replace(/-/g, "");
  const skelBrands = [
    ...(idx.bySkeleton.get(skel) ?? []),
    ...(stripped !== skel ? (idx.bySkeleton.get(stripped) ?? []) : []),
  ];
  for (const b of skelBrands) {
    const bReg = registrableDomain(b.domain.toLowerCase()) ?? b.domain.toLowerCase();
    if (reg === bReg) continue;
    const { sld: bSld } = splitRegistrable(bReg);
    if (sld !== bSld) return hit("confusable", "high", b, reg);
    if (!b.anyTld && !defensiveSuffix) return hit("tldswap", "high", b, reg);
  }

  // (b) Exact-SLD TLD swap (covers brands whose skeleton differs from raw).
  if (!defensiveSuffix) {
    const sldBrands = idx.bySld.get(sld);
    if (sldBrands) {
      for (const b of sldBrands) {
        if (b.anyTld) continue;
        const bReg = registrableDomain(b.domain.toLowerCase()) ?? b.domain.toLowerCase();
        if (reg !== bReg) return hit("tldswap", "high", b, reg);
      }
    }
  }

  // (c1) Brand-subdomain: the full brand domain used as a leading subdomain
  // chain of a different registrable domain (paypal.com.evil.example).
  for (const [bDomain, bReg, b] of idx.brandDomains) {
    if (host.startsWith(bDomain + ".") && reg !== bReg) {
      return hit("brand-subdomain", "medium", b, reg);
    }
  }

  // (c2) Combosquat: brand token inside the SLD with more around it.
  for (const t of idx.comboTokens) {
    if (t.token === sld) continue; // that case is the TLD-swap axis
    if (tokenInLabel(sld, t.token) || tokenInLabel(skel, t.skelToken)) {
      return hit("combosquat", "medium", t.brand, reg);
    }
  }

  // (d) Distance-1 near miss: opt-in, medium, nudge only.
  if (nearMiss && sld.length >= NEARMISS_MIN) {
    for (const [bSkel, brands] of idx.bySkeleton) {
      if (bSkel.length < NEARMISS_MIN) continue;
      if (damerauLevenshtein(skel, bSkel) === 1) {
        const b = brands[0]!;
        const bReg = registrableDomain(b.domain.toLowerCase()) ?? b.domain.toLowerCase();
        if (reg !== bReg) return hit("nearmiss", "medium", b, reg);
      }
    }
  }

  return null;
}
