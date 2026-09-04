// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The pre-click result window: vet a link's DESTINATION before navigating.
// The truly pre-autofill surface: nothing has loaded, no password manager
// has fired, no page has run. On-device detector always; the live band
// joins whenever the live check is on.
//
// IT NOW SHOWS THE JOIN.
//
// This window used to be a hostname, two rows and three buttons, which is
// the same thing a browser's own status bar offers. What makes it worth a
// window is that we can walk the destination's join path BEFORE it loads:
// the address it resolves to, the prefix that routes that address, how much
// of that prefix is already flagged, the network, the operator, the
// building. Nobody has to trust our word for the band, because the evidence
// for it is on the same screen.
//
// The walk is one round of graph calls on a window the reader deliberately
// opened, which is exactly the right place to spend from the keyless
// budget: it is never triggered by browsing, only by asking.

import { send, type CheckHostResult } from "../shared/messages";
import { GRAPH_HOST } from "../shared/config";
import { renderChain, renderChainPending } from "../shared/chain-view";
import { countMarks, ratioBar } from "../shared/viz";
import type { SiteChain } from "../shared/types";

const params = new URLSearchParams(window.location.search);
const host = (params.get("host") ?? "").toLowerCase();

/** The age below which the product calls a name brand new. Same constant as
 *  the interstitial, drawn as the marker on the age scale. */
const NEW_DOMAIN_DAYS = 32;

const $ = (id: string): HTMLElement => document.getElementById(id) as HTMLElement;

const BAND_TEXT: Record<string, { cls: string; text: string }> = {
  CRITICAL: { cls: "malicious", text: "Known threat, evidenced in the graph. Do not open." },
  HIGH: { cls: "suspicious", text: "Strong risk signals in the graph. Be careful." },
  MEDIUM: { cls: "suspicious", text: "Some risk signals in the graph. Be careful." },
  LOW: { cls: "benign", text: "No known threat (not a warranty)." },
  INFO: { cls: "benign", text: "No known threat (not a warranty)." },
  NONE: { cls: "benign", text: "No known threat (not a warranty)." },
  UNKNOWN: { cls: "unknown", text: "New or low-coverage host. Not confirmed either way." },
};

/** One drawn metric under the chain: eyebrow, mark, words for the mark. */
function metric(label: string, mark: SVGElement | null, caption: string, hot: boolean): HTMLElement {
  const box = document.createElement("div");
  box.className = "cl-metric";
  const head = document.createElement("div");
  head.className = "cl-metric-label";
  head.textContent = label;
  box.appendChild(head);
  if (mark) {
    const wrap = document.createElement("div");
    wrap.className = "cl-metric-mark";
    wrap.appendChild(mark);
    box.appendChild(wrap);
  }
  const cap = document.createElement("div");
  cap.className = hot ? "cl-metric-cap hot" : "cl-metric-cap";
  cap.textContent = caption;
  box.appendChild(cap);
  return box;
}

/**
 * The two quantities that decide a pre-click, drawn.
 *
 * Both are drawn only when the graph actually answered them. A metric box
 * that appears with a zero in it when the read failed is the error-renders-
 * as-empty defect, and on this surface it would read as reassurance.
 */
function drawMetrics(chain: SiteChain): void {
  const mount = $("cl-metrics");
  const boxes: HTMLElement[] = [];

  if (chain.ageDays !== null && Number.isFinite(chain.ageDays)) {
    const days = chain.ageDays;
    const fresh = days < NEW_DOMAIN_DAYS;
    boxes.push(
      metric(
        "Age of the name",
        ratioBar(Math.min(days, 365), 365, {
          width: 132, height: 6,
          tone: fresh ? "hot" : "neutral",
          marker: NEW_DOMAIN_DAYS / 365,
        }),
        days >= 365
          ? "over a year old"
          : `${days} day${days === 1 ? "" : "s"} old; the tick is ${NEW_DOMAIN_DAYS} days`,
        fresh,
      ),
    );
  }

  const nb = chain.threatNeighbors;
  if (nb !== null && Number.isFinite(nb) && nb > 0) {
    boxes.push(
      metric(
        "Flagged neighbours",
        countMarks(nb, { perRow: 14, size: 5, tone: "hot" }),
        `${nb} on ${chain.prefix ?? "this prefix"}`,
        true,
      ),
    );
  }

  if (boxes.length > 0) mount.replaceChildren(...boxes);
}

/**
 * Walk the destination. Separate from the verdict call and deliberately
 * not awaited with it: the band is the answer to the question the reader
 * asked and must never wait behind the evidence for it.
 */
async function loadChain(): Promise<void> {
  const card = $("chain-card");
  card.hidden = false;
  renderChainPending($("chain-mount"), 7, "THE JOIN PATH");

  const res = await send<{ ok: true; chain: SiteChain } | { ok: false; error: string }>({
    kind: "getChain",
    host,
  }).catch(() => ({ ok: false as const, error: "unreachable" }));

  if (!res.ok) {
    // Never silent. A window that shows a spine skeleton for ever, or drops
    // it without a word, tells the reader the destination is unremarkable.
    const lost = document.createElement("div");
    lost.className = "note lost";
    lost.textContent =
      "The join path behind this link could not be read. Unknown, not clear.";
    $("chain-mount").replaceChildren(lost);
    return;
  }
  renderChain($("chain-mount"), res.chain, { heading: "THE JOIN PATH", expandable: false });
  drawMetrics(res.chain);
}

async function init(): Promise<void> {
  if (host === "") {
    $("verdict").hidden = false;
    $("host").textContent = "No checkable link";
    $("band-text").textContent =
      "Only http and https destinations can be vetted. Nothing was checked.";
    ($("btn-open") as HTMLAnchorElement).hidden = true;
    $("privacy").textContent = "Privacy: nothing was sent.";
    return;
  }
  $("verdict").hidden = false;
  $("host").textContent = host;
  ($("btn-open") as HTMLAnchorElement).href = `https://${host}/`;

  // A failure HERE is the transport, not the graph: the background did not
  // answer at all. Returning quietly left the one window whose entire job is
  // to answer "is this link safe?" showing a hostname, no verdict, no
  // privacy line, and a live "Open anyway" button - which reads exactly like
  // a clean result. An error that renders as an empty state is the worst
  // shape this product has, and this was one.
  const res = await send<{ ok: true; check: CheckHostResult } | { ok: false; error: string }>({
    kind: "checkHost",
    host,
  }).catch((e: unknown) => ({ ok: false as const, error: String(e instanceof Error ? e.message : e) }));
  if (!res.ok) {
    $("error-note").hidden = false;
    $("error-note").textContent =
      "Whisper Guard could not run the check just now. That is not a clean result: this link is unchecked.";
    $("privacy").textContent = "Privacy: nothing was sent.";
    return;
  }
  const c = res.check;

  const copyLines = [`whisper guard check: ${host}`];

  if (c.detector) {
    $("detector-tag").hidden = false;
    $("detector-text").hidden = false;
    $("detector-text").textContent = `Looks like ${c.detector.brandDomain} (${c.detector.kind}, caught on-device).`;
    const real = $("btn-real") as HTMLAnchorElement;
    real.hidden = false;
    real.textContent = `Go to the real ${c.detector.brandDomain}`;
    real.href = c.detector.goTo;
    copyLines.push(`on-device: ${c.detector.kind} look-alike of ${c.detector.brandDomain}`);
  } else {
    copyLines.push("on-device: no look-alike match");
  }

  if (c.verdict) {
    const ui = BAND_TEXT[c.verdict.band] ?? BAND_TEXT["UNKNOWN"]!;
    const tag = $("band-tag");
    tag.hidden = false;
    tag.className = `tag ${ui.cls}`;
    tag.textContent = c.verdict.band;
    $("cl-rail").className = `cl-rail ${ui.cls}`;
    $("band-text").textContent = c.verdict.label ? `${ui.text} ${c.verdict.label}` : ui.text;
    copyLines.push(`graph band: ${c.verdict.band}${c.verdict.coverage ? ` (coverage: ${c.verdict.coverage}, categorical)` : ""}`);
  } else if (!c.graphError) {
    $("keyless-note").hidden = false;
    $("cl-rail").className = "cl-rail unknown";
    copyLines.push("graph band: (live check off)");
  }

  if (c.graphError) {
    $("error-note").hidden = false;
    $("error-note").textContent = c.graphError;
    $("cl-rail").className = "cl-rail unknown";
  }

  // The live check ran iff a verdict or a graph error came back; otherwise
  // the check was on-device only (live check switched off).
  const liveRan = Boolean(c.verdict || c.graphError);
  $("privacy").textContent = liveRan
    ? `Privacy: only "${host}" was sent, to ${GRAPH_HOST}.`
    : `Privacy: nothing left your browser. The check ran on-device.`;

  $("btn-copy").addEventListener("click", async () => {
    await navigator.clipboard.writeText(copyLines.join("\n"));
    $("btn-copy").textContent = "Copied";
  });

  // The join path is only walked when the live check is on. Walking it with
  // the live check switched OFF would send the very hostname the setting
  // exists to keep in the browser, which would make the privacy line above
  // a lie on the surface that prints it.
  if (liveRan) void loadChain();
}

void init();
