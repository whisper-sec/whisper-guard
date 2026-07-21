// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The device-policy model: a pure, testable mapping between the control
// plane's op:policy ["key","value"] entry rows and the governor surface
// (protection presets, an allow/block rules ledger, a blocked-countries
// list). Mirrors the console's /devices Rules model so both surfaces
// speak the same language over the same verb.
//
// HONESTY CONTRACT (why the serializer carries the whole value): the
// backend policy write is a WHOLE-VALUE replace of the rule set, so
// writeArgs always emits the complete block/allow/bundle set and carries
// bundle tokens this surface does not model (e.g. geo:allow:...)
// verbatim. A Guard save can never silently clear something the console
// or the CLI wrote. Resolution mode and retention are sticky settings on
// the engine side (absent means keep), so they are never sent from here.

export type RuleAction = "allow" | "block";

/** One allow/block rule on a device policy, as stored. */
export interface PolicyRule {
  action: RuleAction;
  value: string;
}

/** A device's DNS policy (op:policy with the device selector), modeled. */
export interface DevicePolicy {
  /** The /128 the engine keyed the policy by (its ["device", addr] row). */
  device: string | null;
  /** What happens when no rule matches: resolve, or block. */
  defaultAction: "allow" | "deny";
  rules: PolicyRule[];
  /** The named graph-evaluated protections currently on (block:*). */
  bundles: string[];
  /** Blocked countries (ISO2, uppercase) from the geo:deny bundle. */
  geoDeny: string[];
  /** Bundle tokens this surface does not model, preserved verbatim. */
  passthrough: string[];
}

/** The op:revoke outcome row, verbatim from the control plane. */
export interface RevokeResult {
  agent: string;
  status: string;
}

// ------------------------------------------------------------ bundles

export interface BundleInfo {
  id: string;
  label: string;
  /** One plain-language line: what turning this on actually does. */
  description: string;
}

/** The named graph-evaluated postures, with real one-line descriptions. */
export const BUNDLE_INFO: BundleInfo[] = [
  {
    id: "block:sanctions",
    label: "Threat & sanctions lists",
    description: "Blocks destinations on live threat-intel and sanctions feeds.",
  },
  {
    id: "block:bulletproof",
    label: "Bulletproof hosting",
    description: "Blocks networks that knowingly host malware and abuse.",
  },
  {
    id: "block:newly-registered",
    label: "Brand-new domains",
    description: "Blocks domains first seen in the last 24 hours, where phishing lives.",
  },
  {
    id: "block:tor-exits",
    label: "Tor exit relays",
    description: "Blocks connections that would terminate at a Tor exit.",
  },
  {
    id: "block:rpki-invalid",
    label: "Invalid routes",
    description: "Blocks destinations announced over RPKI-invalid (likely hijacked) routes.",
  },
];

const KNOWN_BUNDLE_IDS = new Set(BUNDLE_INFO.map((b) => b.id));

// ------------------------------------------------------------ presets

/** A protection preset: a plain-language promise over a bundle set. */
export type PolicyPreset = "standard" | "strict" | "open" | "custom";

export interface PresetInfo {
  id: PolicyPreset;
  label: string;
  /** The plain-language promise on the preset card. */
  promise: string;
}

export const PRESETS: PresetInfo[] = [
  {
    id: "standard",
    label: "Standard",
    promise: "Blocks known-bad: threat-listed and bulletproof-hosted destinations.",
  },
  {
    id: "strict",
    label: "Strict",
    promise: "Blocks threat lists, bulletproof hosts, brand-new domains, Tor exits and invalid routes.",
  },
  {
    id: "open",
    label: "Open",
    promise: "Everything resolves. Only your own rules below apply.",
  },
  {
    id: "custom",
    label: "Custom",
    promise: "Your own mix of protections, chosen below.",
  },
];

const STANDARD_BUNDLES = ["block:sanctions", "block:bulletproof"];
const STRICT_BUNDLES = BUNDLE_INFO.map((b) => b.id);

/** Which preset a bundle set corresponds to (order-independent). */
export function presetOf(bundles: string[]): PolicyPreset {
  const set = new Set(bundles);
  const same = (want: string[]) => set.size === want.length && want.every((b) => set.has(b));
  if (set.size === 0) return "open";
  if (same(STANDARD_BUNDLES)) return "standard";
  if (same(STRICT_BUNDLES)) return "strict";
  return "custom";
}

/** The bundle set a preset stands for (custom returns null: keep what's there). */
export function bundlesForPreset(preset: PolicyPreset): string[] | null {
  if (preset === "open") return [];
  if (preset === "standard") return [...STANDARD_BUNDLES];
  if (preset === "strict") return [...STRICT_BUNDLES];
  return null;
}

// ------------------------------------------------------------ geo:deny

/** The geo-deny bundle prefix (liberal-in: any case on read). */
const GEO_DENY_RE = /^geo:deny:(.*)$/i;

/** The engine's cap on country codes in one geo bundle. */
export const MAX_GEO_CODES = 250;

/**
 * Parse a geo:deny:<CC[,CC...]> bundle value into ISO2 codes: uppercased,
 * deduped, blank entries dropped (liberal-in; the engine may reorder or
 * re-case the list it echoes back).
 */
export function parseGeoDeny(value: string): string[] {
  const m = GEO_DENY_RE.exec(value);
  if (!m || m[1] === undefined) return [];
  const seen = new Set<string>();
  for (const part of m[1].split(",")) {
    const cc = part.trim().toUpperCase();
    if (cc) seen.add(cc);
  }
  return [...seen];
}

/** Serialize a geo-deny set back to the canonical bundle token (sorted). */
export function geoDenyBundle(codes: string[]): string | null {
  if (codes.length === 0) return null;
  return `geo:deny:${[...codes].sort().join(",")}`;
}

// ----------------------------------------------------- rows <-> model

/** The engine's published caps: entries per list, chars per entry. */
export const MAX_POLICY_ENTRIES = 1000;
export const MAX_ENTRY_LEN = 255;

const rowStr = (v: unknown): string => (typeof v === "string" ? v : v == null ? "" : String(v));

/**
 * Map op:policy read-back rows ({key, value} each) into the model.
 * Liberal-in: unknown keys are ignored, unmodeled bundle tokens are kept
 * verbatim so the whole-value write can re-emit them.
 */
export function policyFromRows(rows: Record<string, unknown>[]): DevicePolicy {
  const rules: PolicyRule[] = [];
  const bundles: string[] = [];
  const geoDeny = new Set<string>();
  const passthrough: string[] = [];
  let device: string | null = null;
  let defaultAction: "allow" | "deny" = "allow";

  for (const row of rows) {
    const key = rowStr(row["key"]);
    const value = rowStr(row["value"]);
    if (key === "device" && value) device = value;
    else if (key === "default") defaultAction = value === "deny" || value === "block" ? "deny" : "allow";
    else if (key === "block" && value) rules.push({ action: "block", value });
    else if (key === "allow" && value) rules.push({ action: "allow", value });
    else if (key === "bundle" && value) {
      if (KNOWN_BUNDLE_IDS.has(value)) {
        if (!bundles.includes(value)) bundles.push(value);
      } else if (GEO_DENY_RE.test(value)) {
        for (const cc of parseGeoDeny(value)) geoDeny.add(cc);
      } else {
        passthrough.push(value);
      }
    }
  }
  return { device, defaultAction, rules, bundles, geoDeny: [...geoDeny], passthrough };
}

/**
 * Build the WHOLE-VALUE op:policy write args from the model. Always
 * carries every list and every bundle (modeled + geo + passthrough); see
 * the honesty contract at the top.
 */
export function policyWriteArgs(p: DevicePolicy): {
  block: string[];
  allow: string[];
  default: "allow" | "deny";
  bundles: string[];
} {
  const geo = geoDenyBundle(p.geoDeny);
  return {
    block: p.rules.filter((r) => r.action === "block").map((r) => r.value),
    allow: p.rules.filter((r) => r.action === "allow").map((r) => r.value),
    default: p.defaultAction,
    bundles: [...p.bundles, ...(geo ? [geo] : []), ...p.passthrough],
  };
}

// ------------------------------------------------------------- domains

/**
 * Liberal-accept a domain the person typed (Postel): trims, lowercases,
 * strips a pasted scheme/path/port, a trailing dot and a wildcard prefix,
 * so "https://Ads.Example/x?y" and "ads.example." both land as
 * "ads.example". Returns null only when nothing usable remains.
 */
export function normalizeDomain(input: string): string | null {
  let s = (input ?? "").trim().toLowerCase();
  if (!s) return null;
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, ""); // scheme
  s = s.split(/[/?#]/, 1)[0] ?? ""; // path / query / fragment
  s = s.replace(/^\[|\]$/g, ""); // bracketed v6 literals pass through unbracketed
  // Strip a :port from host:port; a bare IPv6 literal keeps its colons
  // (the lazy head would itself contain one).
  const m = /^(.*?):(\d{1,5})$/.exec(s);
  if (m && m[1] && !m[1].includes(":")) s = m[1];
  s = s.replace(/\.$/, ""); // trailing dot
  s = s.replace(/^\*\./, ""); // wildcard prefix: policy matching is suffix-based
  if (!s || /\s/.test(s) || s.length > MAX_ENTRY_LEN) return null;
  return s;
}

// ----------------------------------------------------------- countries

export interface CountryOption {
  /** ISO2, uppercase: exactly the geo:deny token. */
  iso: string;
  name: string;
}

let countriesCache: CountryOption[] | null = null;

/**
 * Every region the browser itself can name, via Intl.DisplayNames: zero
 * shipped data, and the names match the user's own locale conventions.
 * Codes the browser cannot name are skipped here but still accepted when
 * typed directly (the engine validates alpha-2 for real).
 */
export function countryOptions(): CountryOption[] {
  if (countriesCache) return countriesCache;
  const out: CountryOption[] = [];
  try {
    const dn = new Intl.DisplayNames(["en"], { type: "region" });
    for (let a = 65; a <= 90; a++) {
      for (let b = 65; b <= 90; b++) {
        const iso = String.fromCharCode(a) + String.fromCharCode(b);
        if (iso === "ZZ") continue; // "Unknown Region"
        let name: string | undefined;
        try {
          name = dn.of(iso);
        } catch {
          continue;
        }
        if (name && name !== iso) out.push({ iso, name });
      }
    }
  } catch {
    // No Intl region names in this runtime: typed ISO codes still work.
  }
  out.sort((x, y) => x.name.localeCompare(y.name));
  countriesCache = out;
  return countriesCache;
}

/** The display name for one code, falling back to the code itself. */
export function countryName(iso: string): string {
  const cc = iso.trim().toUpperCase();
  const hit = countryOptions().find((c) => c.iso === cc);
  return hit ? hit.name : cc;
}

/**
 * Resolve what the person typed to an ISO2 code: "NL", "Netherlands", or
 * the datalist's "Netherlands (NL)" form all land on "NL". Liberal-in; a
 * bare two-letter token is accepted verbatim (the engine validates it).
 * Returns null when nothing resolvable was typed.
 */
export function resolveCountry(input: string): string | null {
  const s = (input ?? "").trim();
  if (!s) return null;
  const paren = /\(([A-Za-z]{2})\)\s*$/.exec(s);
  if (paren && paren[1]) return paren[1].toUpperCase();
  if (/^[A-Za-z]{2}$/.test(s)) return s.toUpperCase();
  const lower = s.toLowerCase();
  const hit = countryOptions().find((c) => c.name.toLowerCase() === lower);
  return hit ? hit.iso : null;
}
