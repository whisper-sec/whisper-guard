// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// THE CONSEQUENCE OF A PRESET, computed rather than promised.
//
// A protection preset used to be five words and a checkbox: "Blocks
// bulletproof-hosted destinations." True, unfalsifiable, and useless. A
// reader cannot tell whether turning it on changes nothing about their week
// or cuts off the site their payroll runs on, so the only thing the control
// can ask for is trust. This module turns each protection into a COUNT over
// destinations the endpoint actually reached: "2 of the 37 places this
// endpoint went, and here they are."
//
// THREE OUTCOMES PER DESTINATION, never two. A protection MATCHES a
// destination, or the graph answered and it does not match, or the graph
// holds nothing about that name and we do not know. The third is the one
// products get wrong: a name with no record is silently counted as clean,
// the total reads as complete, and a reader believes a survey that never
// happened. Here it is counted separately and shown, so "0 matched" is
// always accompanied by how many of the destinations that 0 was actually
// measured over.
//
// AND ONE PROTECTION CANNOT BE PREVIEWED AT ALL. Registration age comes from
// whisper.history, which answers for ONE name per call (a list argument is
// refused) and returns every WHOIS snapshot it holds - 37 rows and 252ms for
// a single ordinary domain, measured 2026-09-04. Previewing "brand-new
// domains" over a page of destinations would therefore cost one such call
// per destination, which is not a preview, it is a crawl. So that protection
// reports itself as NOT PREVIEWED and names the missing call, rather than
// reporting a zero it never measured. A fourth state is the honest answer
// when the first three would all be lies.

/**
 * The facts one destination carries, as the graph answered them.
 *
 * Every field here is the input to the SAME predicate the resolver uses, and
 * the comments in shared/config.ts say which trap each one avoids.
 */
export interface HostPolicyFacts {
  host: string;
  /** The reconciled band on the NAME. */
  band: string | null;
  /** The reconciled OFAC flag on the NAME. */
  sanctioned: boolean;
  /** The name, or an address it resolves to, is a listed Tor exit relay. */
  tor: boolean;
  /** Why the announcing prefix is RPKI-invalid, when its status says so. */
  rpkiReason: string | null;
  /**
   * The assess marker that names a bulletproof-hosting posture, verbatim,
   * or null. The resolver looks for that word in the verdict's band, label
   * and sub_labels, so this preview asks the same procedure the same way.
   */
  bulletproofMarker: string | null;
  /**
   * EVERY country this name resolves into, not one. A host lands in several
   * at once (google.com is US, DE and NL live), so a single-country answer
   * is an evasion: a deny on DE would pass whenever the arbitrary pick was
   * US. Enforcement fires when ANY of these is denied.
   */
  countries: string[];
}

/**
 * The answer to one batch read. `unread` is load-bearing: a host that the
 * graph returned no row for is UNKNOWN, and is never folded into the clean
 * count. `error` set means the read itself failed, so every host is unknown
 * and every count on this surface is a floor rather than a measurement.
 */
export interface PolicyFactSet {
  byHost: Record<string, HostPolicyFacts>;
  unread: string[];
  error: string | null;
}

/** What one protection would do to a list of destinations. */
export interface BundlePreview {
  id: string;
  /** Destinations it matches, in the order they were given (busiest first). */
  matched: string[];
  /** One short phrase per matched host: the fact that fired. */
  reasons: Record<string, string>;
  /** Destinations the graph could not answer for, so they could not match. */
  unknown: number;
  /** Destinations considered in total. */
  considered: number;
  /** Null when this protection was previewed; otherwise exactly why not. */
  unavailable: string | null;
  /**
   * Set when the READ failed, as opposed to the graph answering and holding
   * nothing. Both leave every destination unknown, and they are emphatically
   * not the same fact: one means "these names are not in the graph", the
   * other means "we could not find out". A surface that prints the first
   * sentence for the second case is the error that renders as an empty
   * state, so the two are carried separately all the way to the pixel.
   */
  error: string | null;
}

/**
 * The single protection whose evidence is a per-name call, and the exact
 * reason it stays out of the batch. Written once, shown verbatim in the UI:
 * a reader who wants to know why a number is missing deserves the real
 * answer, not "unavailable".
 */
export const NEWLY_REGISTERED_UNAVAILABLE =
  "Registration age is a per-name WHOIS read (whisper.history answers for one name per call), " +
  "so previewing it here would cost one graph call per destination. Everything else on this " +
  "list is read in a single call. The network's own check is best-effort for the same reason: " +
  "a name carries no creation date of its own, so where the age is not known this protection " +
  "lets the name through rather than blocking it.";

/** The bundle ids this module can evaluate from one batch read. */
const PREVIEWABLE = new Set([
  "block:sanctions",
  "block:bulletproof",
  "block:tor-exits",
  "block:rpki-invalid",
]);

/** The pseudo-bundle id under which the blocked-countries preview is keyed. */
export const GEO_PREVIEW_ID = "geo:deny";

function blank(
  id: string,
  considered: number,
  unknown: number,
  unavailable: string | null,
  error: string | null,
): BundlePreview {
  return { id, matched: [], reasons: {}, unknown, considered, unavailable, error };
}

/**
 * Evaluate every protection against a destination list.
 *
 * `countryOf` comes from the enrichment already on screen, which is why the
 * blocked-countries preview costs nothing at all: the ISO2 of every
 * destination is a column the surface has already drawn.
 */
export function previewBundles(
  hosts: string[],
  facts: PolicyFactSet,
  geoDeny: string[],
): Record<string, BundlePreview> {
  const considered = hosts.length;
  const unknownSet = new Set(facts.unread.map((h) => h.toLowerCase()));
  // A failed read makes EVERY host unknown, not zero hosts matched.
  const readFailed = facts.error !== null;
  const unknown = readFailed ? considered : hosts.filter((h) => unknownSet.has(h.toLowerCase())).length;

  const out: Record<string, BundlePreview> = {};
  for (const id of PREVIEWABLE) out[id] = blank(id, considered, unknown, null, facts.error);
  out["block:newly-registered"] = blank(
    "block:newly-registered",
    considered,
    considered,
    NEWLY_REGISTERED_UNAVAILABLE,
    null,
  );
  // The country blocker reads the SAME country set the resolver geolocates
  // against, so it shares the graph read and its error rather than answering
  // from a single enrichment column that disagrees with enforcement.
  const geo = blank(GEO_PREVIEW_ID, considered, unknown, null, facts.error);
  out[GEO_PREVIEW_ID] = geo;

  const denied = new Set(geoDeny.map((c) => c.trim().toUpperCase()).filter(Boolean));

  for (const raw of hosts) {
    const host = raw.toLowerCase();
    if (readFailed) continue;
    const f = facts.byHost[host];
    if (!f) continue;

    // ANY denied country fires, exactly as enforcement does. Naming every
    // match matters here: "blocked because it also lands in DE" is the whole
    // explanation for a destination a reader thinks of as American.
    const hit = f.countries.filter((cc) => denied.has(cc.trim().toUpperCase()));
    if (hit.length > 0) {
      geo.matched.push(raw);
      geo.reasons[raw] =
        f.countries.length > hit.length
          ? `resolves in ${hit.join(", ")} (also ${f.countries.filter((c) => !hit.includes(c)).join(", ")})`
          : `resolves in ${hit.join(", ")}`;
    }

    if (f.sanctioned) {
      const p = out["block:sanctions"];
      if (p) {
        p.matched.push(raw);
        p.reasons[raw] = "the name carries the reconciled OFAC sanctions flag";
      }
    }
    if (f.bulletproofMarker) {
      const p = out["block:bulletproof"];
      if (p) {
        p.matched.push(raw);
        p.reasons[raw] = `the graph's verdict names it: ${f.bulletproofMarker}`;
      }
    }
    if (f.tor) {
      const p = out["block:tor-exits"];
      if (p) {
        p.matched.push(raw);
        p.reasons[raw] = "resolves to a listed Tor exit relay";
      }
    }
    if (f.rpkiReason) {
      const p = out["block:rpki-invalid"];
      if (p) {
        p.matched.push(raw);
        p.reasons[raw] = `announcing prefix is RPKI-invalid (${f.rpkiReason})`;
      }
    }
  }
  return out;
}

/** What a whole preset (a set of protections) would do to the same list. */
export interface PresetPreview {
  /** Destinations at least one protection in the preset matches. */
  matched: string[];
  /** Destinations no protection could be evaluated against. */
  unknown: number;
  considered: number;
  /**
   * True when a protection in this preset could not be previewed, so the
   * matched count is a FLOOR and the UI must say "at least".
   */
  partial: boolean;
  /** Set when the read itself failed, so nothing here was measured at all. */
  error: string | null;
}

/** Roll a bundle set up into one preset-level consequence. */
export function previewPreset(
  bundleIds: string[],
  previews: Record<string, BundlePreview>,
  considered: number,
): PresetPreview {
  // How many destinations could not be read, and whether the read failed at
  // all, are properties of the READ and not of the bundle set. They are
  // therefore taken from the whole preview rather than from the selected
  // bundles: a preset with nothing turned on still cannot see the
  // destinations the graph had no row for, and reporting "none of the 4
  // checked" when only 3 were checkable is precisely the overcount this
  // module exists to refuse. (The country preview is excluded because its
  // unknown is a different measurement - a destination the graph could not
  // place - counted against the same list.)
  let unknown = 0;
  let error: string | null = null;
  for (const p of Object.values(previews)) {
    if (p.unavailable) continue;
    unknown = Math.max(unknown, p.unknown);
    if (p.error) error = p.error;
  }

  const seen = new Set<string>();
  const order: string[] = [];
  let partial = false;
  for (const id of bundleIds) {
    const p = previews[id];
    if (!p) continue;
    if (p.unavailable) {
      partial = true;
      continue;
    }
    for (const h of p.matched) {
      if (seen.has(h)) continue;
      seen.add(h);
      order.push(h);
    }
  }
  return { matched: order, unknown, considered, partial, error };
}

/**
 * The one-line consequence, in words, for a preset card.
 *
 * Deliberately never says "would have blocked N" when N was measured over
 * fewer destinations than there are: the sentence carries its own
 * denominator and its own floor marker so it cannot be quoted out of the
 * conditions it was measured under.
 */
export function presetSentence(p: PresetPreview): string {
  if (p.considered === 0) return "no destinations recorded yet";
  // A failed read is reported as a failed read. It must never borrow the
  // sentence for "the graph holds nothing about these names", which is a
  // claim about the world rather than about our connection to it.
  if (p.error) return `not checked: ${p.error}`;
  const n = p.matched.length;
  const measured = p.considered - p.unknown;
  if (measured === 0) {
    return `nothing checked yet: the graph holds no record of any of the ${p.considered} destinations`;
  }
  const of = `of the ${measured} checked`;
  const rest = p.unknown > 0 ? `, ${p.unknown} not in the graph` : "";
  // "None" is a strong word, and it is only earned when every protection in
  // the preset was actually evaluated. When one of them could not be, the
  // zero is a zero over the ones that could, and the sentence says so.
  if (n === 0) {
    return p.partial
      ? `blocks none ${of} (one protection not previewed)${rest}`
      : `blocks none ${of}${rest}`;
  }
  return `blocks ${p.partial ? "at least " : ""}${n} ${of}${rest}`;
}
