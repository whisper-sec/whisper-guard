// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The full-page warning (Active Shield, evidenced-malicious only). Reached
// two ways: a DNR session rule (cached-bad, pre-render) or tabs.update on
// verdict (novel-bad). Back-to-safety always works, Escape works, and the
// page never traps: continue-anyway is one click, honest and available.
//
// THE ARGUMENT IS NOW DRAWN.
//
// This page is the one moment the whole product exists for, and it used to
// make its entire case in a four-row label-and-value table. That is the
// weakest possible form for it, because the reader standing here is deciding
// whether to believe us and click through anyway, and a table of four
// strings is indistinguishable from any blocklist's opinion.
//
// What we have that a blocklist does not is the JOIN. So the join is what
// this page shows: the walk from the name to the building, drawn as a spine
// the reader can take in at a glance and read down for the values, with the
// two facts that decide most of these cases (how new the name is, how much
// of its neighbourhood is already flagged) drawn as quantities rather than
// written as numbers.
//
// Everything here is best-effort and says so. The block stands on its own
// if the graph is unreachable, and "we could not read this" never renders
// as "there is nothing here".

import { send } from "../shared/messages";
import { renderChain } from "../shared/chain-view";
import { countMarks, ratioBar } from "../shared/viz";
import { chainSpine, type SpineRung } from "../shared/viz";
import type { Protection, SiteChain } from "../shared/types";

const params = new URLSearchParams(window.location.search);
const host = (params.get("host") ?? "").toLowerCase();
const brand = params.get("brand");
const brandDomain = params.get("brandDomain");

/** The age below which the product itself calls a name brand new. Drawn as
 *  a marker on the age scale so the reader sees the threshold, not just the
 *  verdict it produced. */
const NEW_DOMAIN_DAYS = 32;

const $ = (id: string): HTMLElement => document.getElementById(id) as HTMLElement;

$("detail").textContent = host
  ? brandDomain
    ? `${host} is flagged as a known threat impersonating ${brand ?? brandDomain}. It was blocked before any credentials could be entered.`
    : `${host} is flagged as a known threat in the Whisper security graph. It was blocked before any credentials could be entered.`
  : "This page was flagged as a known threat.";

// Never an empty privacy line. When the page arrived without a host the
// honest sentence is that nothing was checked, not silence: silence on a
// privacy line is indistinguishable from a promise that was not kept.
$("privacy").textContent = host
  ? `Privacy: only "${host}" was checked. Your browsing stays yours.`
  : "Privacy: nothing was sent. This page carries no host to check.";

function backToSafety(): void {
  if (window.history.length > 1) window.history.back();
  else window.location.href = "about:blank";
}

$("btn-back").addEventListener("click", backToSafety);
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape") backToSafety();
});

if (brandDomain) {
  const real = $("btn-real") as HTMLAnchorElement;
  real.hidden = false;
  real.textContent = `Go to the real ${brandDomain}`;
  real.href = `https://${brandDomain}/`;
}

// "Continue anyway" without a host used to be a control that did nothing at
// all when pressed: no navigation, no message, no feedback. A button that
// silently ignores a click on a page whose whole purpose is to stop someone
// is worse than an absent one, because the reader concludes the product is
// broken and goes around it. Without a host there is nothing to continue TO,
// so the control says so and offers the way out that does work.
const continueBtn = $("btn-continue");
if (host === "") {
  continueBtn.textContent = "There is no destination to continue to";
  (continueBtn as HTMLButtonElement).disabled = true;
} else {
  continueBtn.addEventListener("click", async () => {
    continueBtn.textContent = "Continuing...";
    await send({ kind: "allowHost", host, session: true }).catch(() => undefined);
    window.location.href = `https://${host}/`;
  });
}

// ------------------------------------------------------------ drawn metrics

/** One drawn metric: an eyebrow, the mark, and the words for the mark. */
function metric(box: HTMLElement, label: string, mark: SVGElement | null, caption: string, tone?: string): void {
  const head = document.createElement("div");
  head.className = "ev-metric-label";
  head.textContent = label;
  const cap = document.createElement("div");
  cap.className = tone ? `ev-metric-cap ${tone}` : "ev-metric-cap";
  cap.textContent = caption;
  const kids: (HTMLElement | SVGElement)[] = [head];
  if (mark) {
    const wrap = document.createElement("div");
    wrap.className = "ev-metric-mark";
    wrap.appendChild(mark);
    kids.push(wrap);
  }
  kids.push(cap);
  box.replaceChildren(...kids);
  box.hidden = false;
}

/**
 * How new the name is, drawn against a year with the product's own
 * threshold marked.
 *
 * The scale is a year rather than a fitted distribution, because a
 * distribution of global domain ages is not something this extension has
 * measured and a chart shaped from a number we made up would be exactly the
 * defect this page exists to prevent. A year is a unit the reader already
 * owns, and sixteen days against it is a nub: the picture makes the case
 * without anyone having to trust a curve.
 */
function drawAge(ageDays: number | null): void {
  const box = $("ev-age");
  if (ageDays === null || !Number.isFinite(ageDays)) return;
  const fresh = ageDays < NEW_DOMAIN_DAYS;
  const bar = ratioBar(Math.min(ageDays, 365), 365, {
    width: 150,
    height: 7,
    tone: fresh ? "hot" : "neutral",
    marker: NEW_DOMAIN_DAYS / 365,
  });
  // The threshold the tick marks is explained in the visible caption rather
  // than in an accessible name, so everyone gets it and not only a screen
  // reader. The bar carries no name of its own: the words are right here.
  metric(
    box,
    "Age of the name",
    bar,
    ageDays >= 365
      ? "over a year old, against the year this bar spans"
      : `${ageDays} day${ageDays === 1 ? "" : "s"} old, against a year. The tick is ${NEW_DOMAIN_DAYS} days` +
        (fresh ? "; phishing lives on this side of it." : "."),
    fresh ? "hot" : undefined,
  );
}

/**
 * The flagged neighbourhood, drawn as one mark per flagged host.
 *
 * This is the fact that most often turns a reader's "it is probably a false
 * positive" into "that is not a coincidence", and it is the one a blocklist
 * structurally cannot produce: it needs the address, the prefix that routes
 * it, and the verdicts on everything else in that prefix.
 */
function drawNeighbours(count: number | null, prefix: string | null): void {
  const box = $("ev-neighbours");
  if (count === null || !Number.isFinite(count) || count <= 0) return;
  const marks = countMarks(count, { perRow: 12, size: 6, tone: "hot" });
  metric(
    box,
    "Its neighbourhood",
    marks,
    `${count} other flagged host${count === 1 ? "" : "s"}${prefix ? ` in ${prefix}` : " on this prefix"}`,
    "hot",
  );
}

/**
 * Why it is listed, drawn as one mark per reason the graph gave.
 *
 * These are REASONS, not sources. An earlier draft of this counted them and
 * called them "independent citations", which was an overclaim in the one
 * place the product must not make one: two of these strings can be two
 * sentences about the same feed, and calling that two independent
 * confirmations is exactly the kind of inflation a reader is right to stop
 * believing us over. The count is the count of reasons given, and the
 * reasons are listed so a reader can see for themselves what they are.
 */
function drawReasons(why: string[]): void {
  const box = $("ev-feeds");
  const reasons = why.map((w) => w.trim()).filter((w) => w.length > 0);
  if (reasons.length === 0) return;
  const marks = countMarks(reasons.length, { perRow: 12, size: 6, tone: "hot" });
  metric(
    box,
    "Why it is listed",
    marks,
    `${reasons.length} reason${reasons.length === 1 ? "" : "s"} cited by the graph`,
    "hot",
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

/** The seven rungs as one glance: how far the walk got and where it broke. */
function drawSpine(chain: SiteChain): void {
  const rungs: SpineRung[] = chain.rungs.map((r) => ({
    label: r.label,
    state: r.state,
    tone: r.tone === "hot" ? "hot" : r.tone === "warn" ? "warn" : "accent",
    pivotal: r.tone !== "neutral",
  }));
  // Decorative: the completeness readout beside it and the rungs below say
  // the same thing in words, and a graphic that repeats its own caption to
  // a screen reader is noise.
  const svg = chainSpine(rungs, { width: 460 });
  if (svg) $("ev-spine").replaceChildren(svg);

  const done = $("ev-completeness");
  done.textContent =
    chain.unavailable > 0
      ? `${chain.live} of ${chain.rungs.length} joins answered, ${chain.unavailable} unreadable`
      : `${chain.live} of ${chain.rungs.length} joins answered`;
  if (chain.unavailable > 0) done.classList.add("lost");
}

// ------------------------------------------------------------ the load

async function loadEvidence(): Promise<void> {
  if (host === "") return;

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

  const box = $("evidence");
  box.hidden = false;

  if (chainRes.ok) {
    drawSpine(chainRes.chain);
    // Not expandable. Every expansion is a graph call, and this page is
    // shown to somebody mid-navigation who has already been interrupted;
    // the free detail the walk carried is on screen and the panel is where
    // a reader goes to dig.
    renderChain($("ev-chain"), chainRes.chain, { heading: "", completeness: false, expandable: false });
    drawNeighbours(chainRes.chain.threatNeighbors, chainRes.chain.prefix);
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
    drawAge(p.ageDays);
    drawReasons(p.why);
    if (chainRes.ok && chainRes.chain.threatNeighbors === null) {
      // The chain answered but held no neighbourhood figure. Say which of
      // the two it was rather than leaving an empty column.
      const box2 = $("ev-neighbours");
      metric(box2, "Its neighbourhood", null, "the graph holds no neighbourhood figure for this prefix");
    }
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
}

void loadEvidence();
