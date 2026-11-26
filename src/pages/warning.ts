// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The full-page warning (Active Shield, evidenced-malicious only). Reached
// two ways: a DNR session rule (cached-bad, pre-render) or tabs.update on
// verdict (novel-bad). Back always works, Escape works, and the page never
// traps: for a block Guard made, continue-anyway is one honest click.
//
// THE ARGUMENT IS SHOWN, NOT ASSERTED.
//
// This page is the one moment the whole product exists for, and the reader
// standing here is deciding whether to believe us and click through anyway.
// A blocklist entry is one hop and reads as an opinion. What we have that a
// blocklist does not is the JOIN, so the join is what this page shows: the
// walk from the name to the building as a spine of seven bars and as rows,
// and the facts that decide most of these cases as three figures a reader
// takes in at a glance: how new the name is, how many other hosts around it
// are already flagged, and how many reasons the graph cites.
//
// The words claim only what Guard knows. "Listed for credential phishing" is
// said only when the graph's own threat label says phishing, and "nothing on
// it has loaded" only when the page was reached through the block rule that
// redirects before any request leaves.
//
// Everything here is best-effort and says so. The block stands on its own
// if the graph is unreachable, and "we could not read this" never renders
// as "there is nothing here".

import { send, type BgResponse } from "../shared/messages";
import { renderChain } from "../shared/chain-view";
import type { Protection, SiteChain } from "../shared/types";

const params = new URLSearchParams(window.location.search);
const named = (params.get("host") ?? "").toLowerCase();
/** Only a value shaped like a hostname is treated as one, and shown. */
const host = /^[a-z0-9._:[\]-]{1,253}$/.test(named) ? named : "";

/** The age below which the product itself calls a name brand new. A name
 *  younger than this is drawn in the hot ink. */
const NEW_DOMAIN_DAYS = 32;

/** The value the block rule's redirect put in this address, if any. It is
 *  only sent to the background, which says whether it is the real one. */
const ruleValue = params.get("rule") ?? "";

const $ = (id: string): HTMLElement => document.getElementById(id) as HTMLElement;

// The page states a block, and offers to continue past one, only when the
// background says Guard stopped this host. The address names the host and
// nothing else: the brand shown comes from the background's answer.
type PageState = "stopped" | "no-block" | "unconfirmed" | "framed" | "no-host";

const SAYS_NOTHING_SENT = "Privacy: nothing was sent from this page.";

const NEUTRAL: Record<Exclude<PageState, "stopped">, { heading: string; detail: string; cont: string; privacy: string }> = {
  "no-block": {
    heading: "No block is in effect for this address.",
    detail: `Whisper Guard is not blocking ${host}, so there is nothing here to continue past. This says nothing about whether the address is safe.`,
    cont: "There is no block to continue past",
    privacy: SAYS_NOTHING_SENT,
  },
  unconfirmed: {
    heading: "Whisper Guard could not confirm a block for this address.",
    detail: `The extension did not answer, so this page cannot say whether ${host} is blocked. Reload the page to ask again.`,
    cont: "Continuing is not available until the block is confirmed",
    privacy: SAYS_NOTHING_SENT,
  },
  framed: {
    heading: "Whisper Guard does not show its warning inside a frame.",
    detail: "Open the address in its own tab to see whether Guard blocks it.",
    cont: "Continuing is not available inside a frame",
    privacy: SAYS_NOTHING_SENT,
  },
  "no-host": {
    heading: "No block is in effect.",
    detail: "This page was opened without an address, so there is nothing to block or continue to.",
    cont: "There is no destination to continue to",
    privacy: "Privacy: nothing was sent. This page carries no host to check.",
  },
};

const mainEl = document.querySelector("main") as HTMLElement;
const continueBtn = $("btn-continue") as HTMLButtonElement;
const backBtn = $("btn-back");
const realBtn = $("btn-real") as HTMLAnchorElement;
const bandEl = $("band");
const framed = window.top !== window.self;

function setHeading(lines: string[]): void {
  const h = $("heading");
  h.replaceChildren(...lines.flatMap((l, i) => (i === 0 ? [l] : [document.createElement("br"), l])));
}

const SVG_NS = "http://www.w3.org/2000/svg";

/** The stop sign: an octagon with a bar. Drawn here, not shipped as an
 *  image, so its colours are the theme's. */
function stopSign(): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("width", "96");
  svg.setAttribute("height", "96");
  svg.setAttribute("viewBox", "0 0 96 96");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Stop");
  const OCTAGON = "M30 4h36l26 26v36L66 92H30L4 66V30z";
  const fill = document.createElementNS(SVG_NS, "path");
  fill.setAttribute("d", OCTAGON);
  fill.setAttribute("class", "stop-fill");
  const edge = document.createElementNS(SVG_NS, "path");
  edge.setAttribute("d", OCTAGON);
  edge.setAttribute("class", "stop-edge");
  const bar = document.createElementNS(SVG_NS, "rect");
  bar.setAttribute("x", "26");
  bar.setAttribute("y", "44");
  bar.setAttribute("width", "44");
  bar.setAttribute("height", "8");
  bar.setAttribute("rx", "2");
  bar.setAttribute("class", "stop-bar");
  svg.append(fill, edge, bar);
  return svg;
}

/** Show a state with nothing of the block in it. No evidence, no way past. */
function showNeutral(state: Exclude<PageState, "stopped">): void {
  const t = NEUTRAL[state];
  $("glyph").textContent = "ⓘ";
  setHeading([t.heading]);
  $("detail").textContent = t.detail;
  $("privacy").textContent = t.privacy;
  continueBtn.textContent = t.cont;
  continueBtn.disabled = true;
  backBtn.textContent = "← Go back";
  realBtn.hidden = true;
  bandEl.hidden = true;
  $("evidence").hidden = true;
  mainEl.dataset["state"] = state;
}

/** What the background told us about the block, kept so the sentence can be
 *  worded again when the graph's own label arrives. */
let blockBrand: string | null = null;
let blockBrandDomain: string | null = null;
/** The graph's threat label, once read. Null until then, and when it has none. */
let threatLabel: string | null = null;

/** The first sentence says only what Guard knows. A brand the background
 *  found wins; "credential phishing" needs the graph's own label to say
 *  phishing. The category of the host's vendor says nothing about threats and
 *  is never used here. */
function claim(): string {
  if (blockBrandDomain) return ` is flagged as a known threat impersonating ${blockBrand ?? blockBrandDomain}.`;
  if (threatLabel !== null && /phish/i.test(threatLabel)) {
    return " is listed for credential phishing in the Whisper security graph.";
  }
  return " is flagged as a known threat in the Whisper security graph.";
}

/** The second sentence. "Nothing on it has loaded" is said only when the
 *  background confirmed the page arrived through the block rule's redirect,
 *  which fires before any request leaves. The address alone never decides it. */
let beforeLoad = false;
function reach(): string {
  return beforeLoad ? " Nothing on it has loaded." : " It was blocked before any credentials could be entered.";
}

function renderDetail(): void {
  const name = document.createElement("span");
  name.className = "host";
  name.textContent = host;
  $("detail").replaceChildren(name, claim() + reach());
}

/** The stop, as before. `brand` and `brandDomain` are the background's own. */
function showStopped(brand: string | null, brandDomain: string | null, confirmedBeforeLoad: boolean): void {
  beforeLoad = confirmedBeforeLoad;
  blockBrand = brand;
  blockBrandDomain = brandDomain;
  threatLabel = null;
  $("glyph").replaceChildren(stopSign());
  setHeading(["Whisper stopped a dangerous page", "before you could enter your password."]);
  renderDetail();
  $("privacy").textContent = `Privacy: only “${host}” was checked.`;
  backBtn.textContent = "← Back to safety";
  if (brandDomain) {
    realBtn.hidden = false;
    realBtn.textContent = `Go to the real ${brandDomain}`;
    realBtn.href = `https://${brandDomain}/`;
  }
  continueBtn.textContent = "I understand the risk, continue anyway";
  continueBtn.disabled = false;
  mainEl.dataset["state"] = "stopped";
  // Back to safety is the default action: Enter takes it. Focus moves only
  // once the actions are shown, which the state above does.
  backBtn.focus();
}

/** The band line: the graph's own label and band, nothing it did not say. */
function showBand(p: Protection): void {
  // A band of UNKNOWN or NONE is the graph saying it has nothing to rate, so
  // it is left out; the label, if the graph gave one, still shows alone.
  const label = p.label?.trim() ?? "";
  const rated = p.band !== "UNKNOWN" && p.band !== "NONE";
  const parts = [label.toUpperCase(), rated ? p.band : ""].filter((x) => x !== "");
  if (parts.length === 0) return;
  bandEl.textContent = parts.join(" · ");
  bandEl.hidden = false;
}

function backToSafety(): void {
  if (window.history.length > 1) window.history.back();
  else window.location.href = "about:blank";
}

backBtn.addEventListener("click", backToSafety);
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") backToSafety();
});

// "Continue anyway" is one honest click, and only while the background says
// the block is Guard's. Anything but an ok answer means there is no block to
// continue past, and the page says so instead of navigating.
continueBtn.addEventListener("click", async () => {
  if (mainEl.dataset["state"] !== "stopped") return;
  continueBtn.disabled = true;
  continueBtn.textContent = "Continuing...";
  const answer = await send({ kind: "allowHost", host, session: true }).catch(() => undefined);
  if (answer?.ok === true) {
    window.location.href = `https://${host}/`;
  } else {
    // No answer is not a "no": the page says which of the two it got.
    showNeutral(answer === undefined ? "unconfirmed" : "no-block");
  }
});

// ------------------------------------------------------------ the figures

/** One figure in a well: a large number over the words for it. A well with no
 *  figure carries only its words. */
function figure(box: HTMLElement, value: string | null, caption: string, hot: boolean): HTMLElement {
  const kids: HTMLElement[] = [];
  if (value !== null) {
    const fig = document.createElement("div");
    fig.className = hot ? "ev-figure hot" : "ev-figure";
    fig.textContent = value;
    kids.push(fig);
  }
  const cap = document.createElement("div");
  cap.className = "ev-caption";
  cap.textContent = caption;
  kids.push(cap);
  box.replaceChildren(...kids);
  box.hidden = false;
  return box;
}

const plural = (n: number, one: string, many: string): string => (n === 1 ? one : many);

/** How long since the name was registered, in the hot ink when it is younger
 *  than the product's own threshold for a new name. Shown only when read. */
function drawAge(ageDays: number | null): void {
  if (ageDays === null || !Number.isFinite(ageDays)) return;
  figure(
    $("ev-age"),
    `${ageDays} ${plural(ageDays, "day", "days")}`,
    "since the name was registered",
    ageDays < NEW_DOMAIN_DAYS,
  );
}

/** The other hosts in the same prefix that are already flagged: the fact that
 *  most often turns "probably a false positive" into "not a coincidence". It
 *  is a count of hosts, not of addresses. */
function drawNeighbours(count: number | null, prefix: string | null): void {
  if (count === null || !Number.isFinite(count) || count <= 0) return;
  figure(
    $("ev-neighbours"),
    String(count),
    `other flagged ${plural(count, "host", "hosts")}${prefix ? ` in ${prefix}` : " on this prefix"}`,
    true,
  );
}

/**
 * Why it is listed: the number of reasons the graph cited, with the reasons
 * under it.
 *
 * These are REASONS, not sources. Two of these strings can be two sentences
 * about the same feed, so counting them as feeds or as independent
 * confirmations would inflate the case in the one place the product must not.
 * The count is the count of reasons given, and the reasons are listed so a
 * reader can see for themselves what they are.
 */
function drawReasons(why: string[]): void {
  const reasons = why.map((w) => w.trim()).filter((w) => w.length > 0);
  if (reasons.length === 0) return;
  const box = figure(
    $("ev-feeds"),
    `${reasons.length} ${plural(reasons.length, "reason", "reasons")}`,
    "cited by the graph",
    true,
  );
  const list = document.createElement("ul");
  list.className = "ev-feedlist";
  for (const r of reasons) {
    const li = document.createElement("li");
    li.textContent = r;
    list.appendChild(li);
  }
  box.appendChild(list);
}

// ------------------------------------------------------------ the spine

/**
 * The joins as one glance: a bar for each, in the order of the chain, coloured
 * by what the join found. A join that could not be read is hollow and dashed,
 * which is not how a join that holds nothing looks, so an outage is never
 * drawn as a quiet result. The counter and the rows say the same in words, so
 * the bars are hidden from assistive technology.
 */
function drawSpine(chain: SiteChain): void {
  const cells = chain.rungs.map((r) => {
    const cell = document.createElement("div");
    cell.className = "ev-cell";
    const bar = document.createElement("div");
    bar.className = "ev-bar";
    bar.dataset["state"] = r.state;
    bar.dataset["tone"] = r.tone;
    const label = document.createElement("span");
    label.className = "ev-bar-label";
    label.textContent = r.label;
    cell.append(bar, label);
    return cell;
  });
  const grid = $("ev-spine");
  grid.style.setProperty("--ev-n", String(Math.max(1, cells.length)));
  grid.replaceChildren(...cells);

  // An answered join that holds nothing was still read; only a join that did
  // not come back is not.
  const total = chain.rungs.length;
  const done = $("ev-completeness");
  done.textContent =
    chain.unavailable > 0
      ? `${total - chain.unavailable} of ${total} joins read, ${chain.unavailable} unreadable`
      : `${total} of ${total} joins read`;
  if (chain.unavailable > 0) done.classList.add("lost");
}

// ------------------------------------------------------------ the load

async function loadEvidence(): Promise<void> {
  // Both reads at once. The chain is the case and the protection carries
  // the citations; neither is worth serialising behind the other on a page
  // that is already interrupting somebody.
  const [chainRes, protRes] = await Promise.all([
    send<{ ok: true; chain: SiteChain } | { ok: false; error: string }>({
      kind: "getChain",
      host,
    }).catch(() => ({ ok: false as const, error: "unreachable" })),
    send<{ ok: true; protection: Protection } | { ok: false; error: string }>({
      kind: "getProtection",
      host,
    }).catch(() => ({ ok: false as const, error: "unreachable" })),
  ]);

  // The page may have left the stopped state while the reads were out.
  if (mainEl.dataset["state"] !== "stopped") return;
  const box = $("evidence");
  box.hidden = false;

  if (chainRes.ok) {
    drawSpine(chainRes.chain);
    // Not expandable. Every expansion is a graph call, and this page is
    // shown to somebody mid-navigation who has already been interrupted;
    // the free detail the walk carried is on screen and the panel is where
    // a reader goes to dig.
    renderChain($("ev-chain"), chainRes.chain, {
      heading: "",
      completeness: false,
      expandable: false,
      emptyText: "the graph holds nothing here",
    });
    drawNeighbours(chainRes.chain.threatNeighbors, chainRes.chain.prefix);
    if (chainRes.chain.threatNeighbors === null) {
      // The chain answered but held no neighbourhood figure. Say which of
      // the two it was rather than leaving an empty column. It depends on
      // the chain alone, so it shows whether or not the protection read did.
      figure($("ev-neighbours"), null, "the graph holds no neighbourhood figure for this prefix", false);
    }
  } else {
    const lost = document.createElement("div");
    lost.className = "ev-lost";
    lost.textContent =
      "The join path behind this name could not be read just now. That is unknown, not clear: the block itself still stands.";
    $("ev-chain").replaceChildren(lost);
    $("ev-completeness").textContent = "join path unreadable";
    $("ev-completeness").classList.add("lost");
  }

  if (protRes.ok) {
    const p = protRes.protection;
    threatLabel = p.label;
    renderDetail();
    showBand(p);
    drawAge(p.ageDays);
    drawReasons(p.why);
    if (p.partial) {
      const note = $("ev-note");
      note.hidden = false;
      note.textContent = "Some of the supporting detail could not be fetched. What is shown was read; what is missing is unknown.";
    }
  } else {
    const note = $("ev-note");
    note.hidden = false;
    note.textContent =
      "The citations behind this block could not be loaded. The block itself still stands.";
  }

  // With no figure to show, the rows take the card's whole width.
  const anyWell = [...document.querySelectorAll<HTMLElement>(".ev-metric")].some((m) => !m.hidden);
  document.querySelector(".ev-grid")?.classList.toggle("solo", !anyWell);
}

async function start(): Promise<void> {
  if (host === "") return showNeutral("no-host");
  // Shown inside a frame, the page is only a notice: it asks nothing and sends nothing.
  if (framed) return showNeutral("framed");
  const res = await send<BgResponse>({ kind: "getBlock", host, ...(ruleValue ? { rule: ruleValue } : {}) }).catch(() => undefined);
  if (!res || res.ok !== true || !("block" in res)) return showNeutral("unconfirmed");
  if (!res.block.blocked) return showNeutral("no-block");
  showStopped(res.block.brand, res.block.brandDomain, res.block.beforeLoad === true);
  await loadEvidence();
}

void start();
