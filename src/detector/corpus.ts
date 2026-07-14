// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Corpus loading + indexing. The bundled corpus works offline from the
// first install; a newer signed corpus from storage (fetched by the corpus
// updater) overrides it when its version is higher. Indexes are rebuilt
// lazily and are cheap (one pass over ~1000 brands).

import bundled from "./corpus-data.json";
import type { Corpus, CorpusBrand } from "../shared/types";
import { registrableDomain, splitRegistrable } from "../shared/psl";
import { skeletonLabel } from "./skeleton";

export interface ComboToken {
  token: string;
  skelToken: string;
  brand: CorpusBrand;
}

export interface CorpusIndex {
  corpus: Corpus;
  // skeleton(SLD) -> brands claiming that skeleton.
  bySkeleton: Map<string, CorpusBrand[]>;
  // exact SLD -> brands.
  bySld: Map<string, CorpusBrand[]>;
  // every registrable domain that is legitimately the brand's own.
  legit: Set<string>;
  // brand-adjacent registrable domains that must never be flagged.
  allow: Set<string>;
  // precomputed combosquat tokens (already gated by noCombo/comboOk/length).
  comboTokens: ComboToken[];
  // precomputed [brandDomain, brandRegistrable, brand] for subdomain abuse.
  brandDomains: [string, string, CorpusBrand][];
  // suffixes where the exact-SLD TLD-swap axis is suppressed (brand-defensive).
  defensive: Set<string>;
}

let index: CorpusIndex | null = null;

function addMulti<K, V>(m: Map<K, V[]>, k: K, v: V): void {
  const arr = m.get(k);
  if (arr) arr.push(v);
  else m.set(k, [v]);
}

const COMBO_MIN_TOKEN = 5;

export function buildIndex(corpus: Corpus): CorpusIndex {
  const bySkeleton = new Map<string, CorpusBrand[]>();
  const bySld = new Map<string, CorpusBrand[]>();
  const legit = new Set<string>();
  const allow = new Set<string>(corpus.allow.map((d) => d.toLowerCase()));
  const comboTokens: ComboToken[] = [];
  const brandDomains: [string, string, CorpusBrand][] = [];

  for (const brand of corpus.brands) {
    const domains = [brand.domain, ...(brand.legit ?? [])];
    for (const d of domains) legit.add(d.toLowerCase());
    const domain = brand.domain.toLowerCase();
    const reg = registrableDomain(domain) ?? domain;
    const { sld } = splitRegistrable(reg);
    addMulti(bySld, sld, brand);
    const skel = skeletonLabel(sld);
    addMulti(bySkeleton, skel, brand);
    // Hyphenation squats (wells-fargo for wellsfargo, face-book for
    // facebook) collapse onto the same key: index the stripped form too.
    const stripped = skel.replace(/-/g, "");
    if (stripped !== skel) addMulti(bySkeleton, stripped, brand);
    brandDomains.push([domain, reg, brand]);
    const comboAllowed = !brand.noCombo && (brand.comboOk === true || sld.length >= COMBO_MIN_TOKEN);
    if (comboAllowed) {
      comboTokens.push({ token: sld, skelToken: skeletonLabel(sld), brand });
    }
    // Explicitly curated extra tokens bypass the gates: curation is intent.
    for (const t of brand.tokens ?? []) {
      const token = t.toLowerCase();
      comboTokens.push({ token, skelToken: skeletonLabel(token), brand });
    }
  }
  const defensive = new Set<string>((corpus.defensiveSuffixes ?? []).map((s) => s.toLowerCase()));
  return { corpus, bySkeleton, bySld, legit, allow, comboTokens, brandDomains, defensive };
}

/** The active corpus index: stored override when newer, else bundled. */
export async function getIndex(): Promise<CorpusIndex> {
  if (index) return index;
  let corpus = bundled as Corpus;
  try {
    const stored = (await chrome.storage.local.get("corpus"))["corpus"] as Corpus | undefined;
    if (stored && typeof stored.version === "number" && stored.version > corpus.version) {
      corpus = stored;
    }
  } catch {
    // storage unavailable: the bundled corpus always works.
  }
  index = buildIndex(corpus);
  return index;
}

/** Drop the cached index (after a corpus update) so it rebuilds on next use. */
export function invalidateIndex(): void {
  index = null;
}
