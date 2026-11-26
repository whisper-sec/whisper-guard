// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Reads Guard's on-page UI from outside its closed shadow root. Playwright
// locators cannot see into a closed root, but the DevTools protocol can: the
// DOM domain, with pierce, lists a closed root under its host, and a function
// can be called with that root as `this`.

import type { BrowserContext, CDPSession, Page } from "@playwright/test";

interface CdpNode {
  nodeId: number;
  nodeName?: string;
  attributes?: string[];
  backendNodeId: number;
  shadowRoots?: CdpNode[];
  children?: CdpNode[];
  contentDocument?: CdpNode;
}

/** The host element Guard mounts its UI under carries the maximum z-index. */
function findHost(node: CdpNode): CdpNode | null {
  const attrs = node.attributes ?? [];
  const at = attrs.indexOf("style");
  if (at >= 0 && (attrs[at + 1] ?? "").includes("2147483647") && node.shadowRoots?.length) {
    return node;
  }
  for (const c of node.children ?? []) {
    const f = findHost(c);
    if (f) return f;
  }
  return null;
}

export class ClosedShadow {
  private constructor(private readonly cdp: CDPSession) {}

  static async open(context: BrowserContext, page: Page): Promise<ClosedShadow> {
    const cdp = await context.newCDPSession(page);
    await cdp.send("DOM.enable");
    return new ClosedShadow(cdp);
  }

  async close(): Promise<void> {
    await this.cdp.detach();
  }

  /**
   * Call `fnSource` (a function declaration as text) with the closed root as
   * `this`, and return its JSON-serialisable result. `null` when no Guard
   * host with a root is present.
   */
  async call<T>(fnSource: string): Promise<T | null> {
    const doc = (await this.cdp.send("DOM.getDocument", { depth: -1, pierce: true })) as {
      root: CdpNode;
    };
    const host = findHost(doc.root);
    const root = host?.shadowRoots?.[0];
    if (!root) return null;
    const { object } = (await this.cdp.send("DOM.resolveNode", {
      backendNodeId: root.backendNodeId,
    })) as { object: { objectId: string } };
    const res = (await this.cdp.send("Runtime.callFunctionOn", {
      objectId: object.objectId,
      functionDeclaration: fnSource,
      returnByValue: true,
      awaitPromise: true,
    })) as { result: { value: T }; exceptionDetails?: { text: string } };
    if (res.exceptionDetails) throw new Error(`closed-root call failed: ${res.exceptionDetails.text}`);
    return res.result.value;
  }

  /**
   * Real (trusted) left clicks at a point, `times` press-and-release pairs,
   * all sent before any reply is awaited so they land back to back.
   */
  async mouseClicks(x: number, y: number, times: number): Promise<void> {
    const sends: Promise<unknown>[] = [];
    for (let i = 1; i <= times; i++) {
      for (const type of ["mousePressed", "mouseReleased"] as const) {
        sends.push(
          this.cdp.send("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: i }),
        );
      }
    }
    await Promise.all(sends);
  }

  /** Platform fonts used to draw the text of the element with this id inside the root. */
  async platformFonts(id: string): Promise<{ familyName: string; isCustomFont: boolean }[] | null> {
    await this.cdp.send("CSS.enable");
    const doc = (await this.cdp.send("DOM.getDocument", { depth: -1, pierce: true })) as {
      root: CdpNode;
    };
    const find = (n: CdpNode): CdpNode | null => {
      const a = n.attributes ?? [];
      if (a[a.indexOf("id") + 1] === id && a.indexOf("id") >= 0) return n;
      for (const c of [...(n.shadowRoots ?? []), ...(n.children ?? [])]) {
        const f = find(c);
        if (f) return f;
      }
      return null;
    };
    const host = findHost(doc.root);
    const node = host ? find(host) : null;
    if (!node) return null;
    const res = (await this.cdp.send("CSS.getPlatformFontsForNode", { nodeId: node.nodeId })) as {
      fonts: { familyName: string; isCustomFont: boolean }[];
    };
    return res.fonts;
  }
}

export interface Rect {
  l: number;
  r: number;
  t: number;
  b: number;
  w: number;
  h: number;
}

export interface TextRun {
  text: string;
  color: string;
  bg: string;
}

export interface ElSnap {
  text: string;
  rect: Rect;
  css: Record<
    | "backgroundColor" | "color" | "fontWeight" | "fontSize" | "fontFamily" | "borderTopWidth"
    | "borderTopColor" | "borderTopStyle" | "borderRadius" | "outlineStyle" | "outlineWidth"
    | "outlineColor" | "overflowY" | "display",
    string
  >;
  tag: string;
}

/** Hooks inside the closed root; the page cannot query a closed root. */
export interface CardSnapshot {
  role: string | null;
  modal: string | null;
  labelledby: string | null;
  describedby: string | null;
  focusedId: string | null;
  card: ElSnap | null;
  overlay: ElSnap | null;
  heading: ElSnap | null;
  sentence: ElSnap | null;
  host: ElSnap | null;
  tag: ElSnap | null;
  pill: ElSnap | null;
  privacy: ElSnap | null;
  wordmark: ElSnap | null;
  guardPill: ElSnap | null;
  mark: (ElSnap & { src: string; alt: string }) | null;
  back: ElSnap | null;
  proceed: ElSnap | null;
  runs: TextRun[];
}

/** Everything the card tests read, in one round trip. */
export const SNAPSHOT_FN = `function () {
  const r = this;
  const PROPS = ["backgroundColor","color","fontWeight","fontSize","fontFamily","borderTopWidth","borderTopColor","borderTopStyle","borderRadius","outlineStyle","outlineWidth","outlineColor","overflowY","display"];
  const snap = (el) => {
    if (!el) return null;
    const b = el.getBoundingClientRect();
    const cs = getComputedStyle(el);
    const css = {};
    for (const p of PROPS) css[p] = cs[p];
    return { text: (el.textContent || "").trim(), tag: el.tagName.toLowerCase(),
      rect: { l: b.left, r: b.right, t: b.top, b: b.bottom, w: b.width, h: b.height }, css };
  };
  const q = (id) => r.getElementById(id);
  const bgOf = (el) => {
    for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
      const c = getComputedStyle(n).backgroundColor;
      if (c && c !== "rgba(0, 0, 0, 0)" && c !== "transparent") return c;
    }
    return "rgba(0, 0, 0, 0)";
  };
  const runs = [];
  for (const el of r.querySelectorAll("*")) {
    const own = Array.from(el.childNodes).filter((n) => n.nodeType === 3 && n.textContent.trim()).map((n) => n.textContent.trim()).join(" ");
    if (own) runs.push({ text: own, color: getComputedStyle(el).color, bg: bgOf(el) });
  }
  const mark = q("w-mark");
  const markSnap = mark ? Object.assign(snap(mark), { src: mark.getAttribute("src") || "", alt: mark.getAttribute("alt") }) : null;
  const overlay = q("w-overlay");
  return {
    role: overlay ? overlay.getAttribute("role") : null,
    modal: overlay ? overlay.getAttribute("aria-modal") : null,
    labelledby: overlay ? overlay.getAttribute("aria-labelledby") : null,
    describedby: overlay ? overlay.getAttribute("aria-describedby") : null,
    focusedId: r.activeElement ? r.activeElement.id || null : null,
    card: snap(q("w-card")), overlay: snap(overlay), heading: snap(q("w-title")),
    sentence: snap(q("w-desc")), host: snap(q("w-host")), tag: snap(q("w-tag")),
    pill: snap(q("w-verdict")), privacy: snap(q("w-privacy")), wordmark: snap(q("w-word")),
    guardPill: snap(q("w-guard")), mark: markSnap,
    back: snap(q("w-back")), proceed: snap(q("w-proceed")), runs,
  };
}`;

/** Scroll a button into view in the overlay and return both buttons' rects. */
export const SCROLL_TO_BUTTONS_FN = `function () {
  const rect = (el) => { const b = el.getBoundingClientRect(); return { l: b.left, r: b.right, t: b.top, b: b.bottom, w: b.width, h: b.height }; };
  const back = this.getElementById("w-back");
  const proceed = this.getElementById("w-proceed");
  back.scrollIntoView({ block: "nearest" });
  proceed.scrollIntoView({ block: "nearest" });
  return { back: rect(back), proceed: rect(proceed), card: rect(this.getElementById("w-card")),
    overflowY: getComputedStyle(this.getElementById("w-overlay")).overflowY,
    vw: document.documentElement.clientWidth, vh: document.documentElement.clientHeight };
}`;

/** What the field caution tests read from inside the closed root. */
export interface CautionSnapshot {
  role: string | null;
  childTags: string[];
  card: {
    rect: Rect;
    backgroundColor: string;
    borderWidth: string;
    borderColor: string;
    borderStyle: string;
    borderRadius: string;
    position: string;
  };
  sentence: { text: string; fontSize: string; fontWeight: string; color: string; strongText: string | null; strongColor: string | null };
  caret: {
    rect: Rect;
    backgroundColor: string;
    borders: { top: string; right: string; bottom: string; left: string };
  } | null;
  dismiss: { label: string | null; type: string | null; rect: Rect } | null;
  markAlt: string | null;
}

/** The caution card, its caret, sentence and close button, in one round trip. */
export const CAUTION_FN = `function () {
  const rect = (el) => { const b = el.getBoundingClientRect(); return { l: b.left, r: b.right, t: b.top, b: b.bottom, w: b.width, h: b.height }; };
  const card = this.getElementById("w-caution");
  if (!card) return null;
  const cs = getComputedStyle(card);
  const sentence = this.getElementById("w-caution-text");
  const ss = sentence ? getComputedStyle(sentence) : null;
  const strong = sentence ? sentence.querySelector("strong") : null;
  const caretEl = this.getElementById("w-caution-caret");
  const cc = caretEl ? getComputedStyle(caretEl) : null;
  const close = this.getElementById("w-caution-close");
  const mark = card.querySelector("img");
  return {
    role: card.getAttribute("role"),
    childTags: Array.from(card.children).filter((c) => c.id !== "w-caution-caret").map((c) => c.tagName.toLowerCase()),
    card: { rect: rect(card), backgroundColor: cs.backgroundColor, borderWidth: cs.borderTopWidth, borderColor: cs.borderTopColor,
      borderStyle: cs.borderTopStyle, borderRadius: cs.borderTopLeftRadius, position: cs.position },
    sentence: sentence ? { text: (sentence.textContent || "").trim(), fontSize: ss.fontSize, fontWeight: ss.fontWeight, color: ss.color,
      strongText: strong ? strong.textContent : null, strongColor: strong ? getComputedStyle(strong).color : null } : null,
    caret: caretEl ? { rect: rect(caretEl), backgroundColor: cc.backgroundColor,
      borders: { top: cc.borderTopWidth, right: cc.borderRightWidth, bottom: cc.borderBottomWidth, left: cc.borderLeftWidth } } : null,
    dismiss: close ? { label: close.getAttribute("aria-label"), type: close.getAttribute("type"), rect: rect(close) } : null,
    markAlt: mark ? mark.getAttribute("alt") : null,
  };
}`;

/** Click the caution's close button with a real (trusted) click, at its centre. */
export const CLOSE_CENTRE_FN = `function () {
  const b = this.getElementById("w-caution-close").getBoundingClientRect();
  return { x: b.left + b.width / 2, y: b.top + b.height / 2 };
}`;
