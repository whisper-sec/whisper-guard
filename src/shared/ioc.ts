// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Indicator extraction: pull IPs, domains, URLs, file hashes and CVE ids out of
// a block of text.
//
// WHERE THIS RUNS MATTERS MORE THAN WHAT IT DOES. This module is pure - no
// browser APIs, no network - so the page scan can serialize it INTO the page and
// reduce a document to a short list of indicators before anything crosses back
// to the extension. The page's text never leaves the page, exactly as the link
// scan reduces links to bare hostnames in situ. A scanner that shipped the
// document out for server-side extraction would be a simpler build and a
// completely different privacy posture.
//
// DEFANGED FORMS ARE THE POINT, not a nicety. An analyst reads indicators in
// advisories, tickets and mail where they have been deliberately broken so
// nobody clicks them: 1.2.3[.]4, hxxps://evil[.]example, evil(dot)com. A
// scanner that only matches live syntax finds nothing on precisely the pages
// worth scanning.

/** One indicator lifted out of text, already refanged and normalised. */
export interface Ioc {
  kind: "ipv4" | "ipv6" | "domain" | "url" | "md5" | "sha1" | "sha256" | "cve";
  /** The canonical, refanged value: lowercase, no defang markers. */
  value: string;
  /** The host to assess for a url/domain/ip, else null (hashes and CVEs have none). */
  host: string | null;
}

/** Defang markers seen in the wild, longest first so [.] wins before [ or ]. */
const DEFANG: ReadonlyArray<readonly [RegExp, string]> = [
  [/\[\s*\.\s*\]/g, "."],
  [/\(\s*\.\s*\)/g, "."],
  [/\{\s*\.\s*\}/g, "."],
  [/\[\s*(?:dot|DOT|Dot)\s*\]/g, "."],
  [/\(\s*(?:dot|DOT|Dot)\s*\)/g, "."],
  [/\s+(?:dot|DOT)\s+/g, "."],
  [/\[\s*:\s*\]/g, ":"],
  [/\[\s*@\s*\]/g, "@"],
  [/\bhxxps\b/gi, "https"],
  [/\bhxxp\b/gi, "http"],
  [/\bfxp\b/gi, "ftp"],
  [/\[\s*\/\s*\]/g, "/"],
];

/**
 * Undo the conventional defang markers. Deliberately NOT reversible and
 * deliberately applied before any matching: `1.2.3[.]4` and `1.2.3.4` are the
 * same indicator and an analyst who pasted the first should get the second.
 */
export function refang(text: string): string {
  let out = text;
  for (const [re, to] of DEFANG) out = out.replace(re, to);
  return out;
}

// A dotted quad with each octet bounded 0-255, so 999.1.1.1 and a version
// string like 10.4.256.1 do not become indicators.
const OCTET = "(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const RE_IPV4 = new RegExp(`\\b${OCTET}(?:\\.${OCTET}){3}\\b`, "g");
// Conservative on purpose: the fully-expanded and one-::-elision forms only.
const RE_IPV6 = /\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4})?\b/gi;
const RE_URL = /\b(?:https?|ftp):\/\/[^\s<>"'`\]),]+/gi;
const RE_HASH = /\b[0-9a-f]{32}\b|\b[0-9a-f]{40}\b|\b[0-9a-f]{64}\b/gi;
const RE_CVE = /\bCVE-\d{4}-\d{4,7}\b/gi;
// A hostname with a plausible TLD. The PSL check happens later, in the
// background, where the real suffix list lives; this only has to be cheap and
// not obviously wrong inside the page.
const RE_DOMAIN = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi;

/** Hex length decides the algorithm; there is nothing else to go on. */
function hashKind(hex: string): Ioc["kind"] | null {
  if (hex.length === 32) return "md5";
  if (hex.length === 40) return "sha1";
  if (hex.length === 64) return "sha256";
  return null;
}

/**
 * A dotted string that is really a version, a decimal or a filename should not
 * be reported as a domain. The cheapest reliable discriminator is the last
 * label: a TLD is never all-digits, and `1.2` / `config.json` / `v1.20.3` all
 * fail on it.
 */
function looksLikeDomain(candidate: string): boolean {
  const labels = candidate.split(".");
  if (labels.length < 2) return false;
  const tld = labels[labels.length - 1] ?? "";
  if (!/^[a-z]{2,24}$/i.test(tld)) return false;
  // A bare two-label name whose TLD is a common file extension is a filename.
  const FILE_EXT = new Set([
    "js", "ts", "json", "html", "htm", "css", "png", "jpg", "jpeg", "gif", "svg",
    "md", "txt", "xml", "yml", "yaml", "sh", "py", "go", "rs", "java", "class",
    "exe", "dll", "so", "zip", "gz", "tar", "pdf", "doc", "docx", "log", "conf",
  ]);
  if (labels.length === 2 && FILE_EXT.has(tld.toLowerCase())) return false;
  return true;
}

/**
 * Extract every indicator in `text`, refanging first, deduplicated by
 * kind+value and capped so a pathological page cannot produce an unbounded
 * list. Order is stable: the order each distinct indicator first appears.
 *
 * `cap` bounds the RESULT, not the input, so the caller can scan a large
 * document and still get a bounded, renderable answer.
 */
export function extractIocs(text: string, cap = 500): Ioc[] {
  const refanged = refang(text ?? "");
  const out: Ioc[] = [];
  const seen = new Set<string>();

  const push = (kind: Ioc["kind"], raw: string, host: string | null) => {
    if (out.length >= cap) return;
    // CVE ids are written upper case everywhere they are published; lowercasing
    // them would make our output the only place they do not match.
    const value = kind === "cve" ? raw.toUpperCase() : raw.toLowerCase();
    const key = `${kind}:${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, value, host: host ? host.toLowerCase() : null });
  };

  // URLs first, and then their whole span is MASKED OUT of the text the other
  // scanners see. A url is one indicator, not a bag of them: without this the
  // path of https://evil.example/payload.bin yields a second "domain"
  // payload.bin, because a filename and a hostname are the same shape. Claiming
  // only the host was not enough - the bug that motivated this was in the PATH.
  const urlHosts = new Set<string>();
  let rest = refanged;
  for (const m of refanged.matchAll(RE_URL)) {
    let host: string | null = null;
    try {
      host = new URL(m[0]).hostname;
      urlHosts.add(host.toLowerCase());
    } catch {
      host = null; // unparseable after refang - still worth reporting verbatim
    }
    push("url", m[0], host);
    rest = rest.replace(m[0], " ".repeat(m[0].length));
  }
  for (const m of rest.matchAll(RE_CVE)) push("cve", m[0].toUpperCase(), null);
  for (const m of rest.matchAll(RE_HASH)) {
    const k = hashKind(m[0]);
    if (k) push(k, m[0], null);
  }
  for (const m of rest.matchAll(RE_IPV4)) {
    if (!urlHosts.has(m[0])) push("ipv4", m[0], m[0]);
  }
  for (const m of rest.matchAll(RE_IPV6)) {
    const v = m[0].toLowerCase();
    // A bare "::" fragment or a MAC-like run is not an address worth reporting.
    if (v.split(":").filter(Boolean).length >= 3 && !urlHosts.has(v)) push("ipv6", m[0], m[0]);
  }
  for (const m of rest.matchAll(RE_DOMAIN)) {
    const v = m[0].toLowerCase();
    if (urlHosts.has(v)) continue;
    if (!looksLikeDomain(v)) continue;
    push("domain", m[0], m[0]);
  }
  return out;
}

/**
 * Drop indicators the reader has told us to ignore. A term matches when it is
 * the whole value or one of its dot-separated labels, so `example` silences
 * `example.com` and `a.example.com` without also silencing `notexample.com`.
 */
export function applyIgnoreList(iocs: Ioc[], ignore: readonly string[]): Ioc[] {
  if (!ignore.length) return iocs;
  const terms = new Set(ignore.map((t) => t.trim().toLowerCase()).filter(Boolean));
  if (!terms.size) return iocs;
  return iocs.filter((i) => {
    if (terms.has(i.value)) return false;
    if (i.host && terms.has(i.host)) return false;
    const parts = (i.host ?? i.value).split(".");
    return !parts.some((p) => terms.has(p));
  });
}

/** The clipboard form: one indicator per line, grouped by kind, kind-labelled. */
export function iocsToText(iocs: readonly Ioc[]): string {
  const order: Ioc["kind"][] = ["url", "domain", "ipv4", "ipv6", "sha256", "sha1", "md5", "cve"];
  const lines: string[] = [];
  for (const kind of order) {
    const rows = iocs.filter((i) => i.kind === kind);
    if (!rows.length) continue;
    lines.push(`# ${kind} (${rows.length})`);
    for (const r of rows) lines.push(r.value);
    lines.push("");
  }
  return lines.join("\n").trimEnd();
}
