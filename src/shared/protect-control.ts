// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// THE one control that puts this browser on the Whisper network, and the
// only implementation of it in the extension.
//
// It used to be two controls in two surfaces saying two different things:
// the panel offered "Protect this browser", the dashboard offered "Enroll
// this browser" plus a separate "Turn on" routing toggle, and the panel's
// wording promised something the dashboard's split contradicted. Two ways
// to do one thing is one way too many, so both surfaces now mount THIS
// module: same markup, same ids, same words, same ordering, same failure
// states. A change to the vocabulary lands on both at once because there
// is only one place it can be written.
//
// What it does, in one click:
//
//   1. RESERVE the browser's own routable Whisper IPv6 identity. Needs no
//      browser permission, works the moment you are signed in, and stands
//      whatever routing does afterwards.
//   2. ROUTE this browser's traffic out through that identity, asking for
//      the permission routing needs at the moment it is needed.
//
// Ordering is the whole design.
//
//   - The permission request is the FIRST thing on the gesture. An await
//     in front of it and the browser drops the request as un-gestured.
//   - The identity is reserved by the BACKGROUND, and nothing waits on the
//     permission first. That call outlives the surface, needs no
//     permission of any kind, and must not be downstream of a promise that
//     may never settle: a reader who refuses the prompt, or whose popup
//     the prompt closed, still ends up with the address they asked for.
//   - Reserving the identity is tried up to three times by the background,
//     and takes a few seconds when the address is slow to appear. While it
//     runs, the control shows its steps and names the try, read from the
//     status so a surface opened mid-way shows the same thing. Closing the
//     surface changes nothing: the background finishes the work.
//   - Routing comes last and is allowed to fail. When it does, the status
//     that comes back names what is in the way and the control shows it,
//     with a way to retry. Never a dead end.

import { send } from "./messages";
import { EGRESS_REQUEST } from "./config";
import { ext } from "./api";
import { IS_FIREFOX } from "./engine";
import type { EgressStatus, Enrollment, IdentityVerification } from "./types";

/** The one static sentence on the route line (popup and dashboard), verbatim. */
export const ROUTE_LINE_BASE =
  "Every window in this profile leaves from this address, except tailnet and private-network destinations, which connect directly.";

/**
 * The route line while routing is on. The WebRTC half is stated either way.
 * Chromium lets an extension pin the handling policy, so "everything sources
 * from the /128" is true there. Firefox has the control too (behind the
 * optional `privacy` permission) but Guard does not request it, so STUN goes
 * out over direct UDP and a page can learn the browser's real public address:
 * a limit we have not closed is one we say out loud. Private windows are
 * stated the same way: neither engine routes them unless the user allowed the
 * extension there (Chromium skips an extension-controlled proxy in incognito,
 * Firefox's request hook never sees private requests), so "every window"
 * would otherwise overstate.
 */
export function routeLineText(s: Pick<EgressStatus, "webrtcHardened" | "privateWindowsRouted">): string {
  return `${ROUTE_LINE_BASE}${routeLimitsText(s)}`;
}

/**
 * The limits half of the route line (the private-window clause, then the WebRTC
 * clause), each with its leading space. The surfaces draw it as a second,
 * smaller line under the sentence; building the whole line from this keeps the
 * two from drifting.
 */
export function routeLimitsText(s: Pick<EgressStatus, "webrtcHardened" | "privateWindowsRouted">): string {
  const priv =
    s.privateWindowsRouted === true ? "" : " Private windows are not routed unless Whisper Guard is allowed in them.";
  const webrtc =
    s.webrtcHardened === true
      ? " WebRTC is hardened to proxied-only."
      : " WebRTC is not pinned to this address, so a page can still learn your real address through a peer connection.";
  return `${priv}${webrtc}`;
}

/** What the route line says while this browser has no identity and nothing went wrong. */
const NO_IDENTITY_TEXT = "No Whisper identity yet.";

/** What the route line says while another extension holds the proxy setting. */
const HELD_TEXT = "Another extension controls the proxy setting. Your identity and verdicts still work.";

/** What the route line says once every try at reserving an address is used. */
export const RESERVE_FAILED_TEXT = "We couldn’t reserve an address yet. Your verdicts still work.";

/** How often a running reservation's status is re-read. Nothing polls otherwise. */
const RESERVE_POLL_MS = 500;

/** The empty status: what the surfaces show when the background cannot answer. */
const NO_EGRESS: EgressStatus = {
  on: false,
  enrolled: false,
  agent: null,
  address: null,
  label: null,
  fqdn: null,
  rdapUrl: null,
  controlledByOther: false,
  webrtcHardened: null,
  privateWindowsRouted: null,
  error: null,
  reserving: null,
  reserveFailed: false,
};

/**
 * How long to wait for the browser's answer to the permission prompt
 * before saying, honestly, that we do not have one.
 *
 * The request promise cannot be trusted to settle. On a real toolbar popup
 * the prompt takes the focus and closes the page while the dialog is still
 * up; in a headless browser the dialog never appears and the promise stays
 * pending forever (measured, not assumed). So the browser's own permission
 * STATE is polled alongside the promise, and whichever answers first wins.
 */
const ROUTING_PERMISSION_WAIT_MS = 12_000;
const ROUTING_PERMISSION_POLL_MS = 400;

/** The permissions ROUTING needs, per engine. On Chromium `proxy` is a
 *  REQUIRED manifest permission (Chrome forbids it as optional), so it is
 *  not in the runtime set there; config.ts owns both sets. */
export function routingPermissions(): chrome.permissions.Permissions {
  const set = IS_FIREFOX ? EGRESS_REQUEST.firefox : EGRESS_REQUEST.chromium;
  return { permissions: [...set.permissions], origins: [...set.origins] };
}

export async function currentEgress(): Promise<EgressStatus> {
  const res = await send<{ ok: true; egress: EgressStatus }>({ kind: "egressStatus" });
  return res.ok ? res.egress : NO_EGRESS;
}

/** The control-plane messages are written to follow a "⚠ " prefix, so
 *  they open in lower case. Here they follow a full stop instead. */
function asSentence(text: string): string {
  return text.length === 0 ? text : text[0]!.toUpperCase() + text.slice(1);
}

function el(tag: string, cls?: string, text?: string): HTMLElement {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

/**
 * A Whisper /128, drawn the way the console draws every one of them: the
 * /32 that every Whisper endpoint shares recedes, and the part that is
 * only this browser's stays in full ink.
 */
export function addressNode(address: string): HTMLElement {
  const wrap = el("span", "w-mono");
  const groups = address.split(":");
  if (groups.length < 4) {
    wrap.textContent = address;
    return wrap;
  }
  wrap.append(
    el("span", "w-addr-prefix", groups.slice(0, 2).join(":") + ":"),
    document.createTextNode(groups.slice(2).join(":")),
  );
  return wrap;
}

/**
 * The browser's public name, with a break allowed after each dot. None of the
 * breaks is text, so the name is still selected and copied as one exact
 * string. The popup keeps the name to one line: the start part is trimmed with
 * an ellipsis when it does not fit, and when the name has more than three
 * labels its zone (the last three, agents.whisper.online) is a part of its own
 * that stays in view. The dashboard draws both parts inline as one name. Both
 * parts are inline: a block or flex part would put a line break into a
 * selection between them.
 *
 * --pc-name-zone tells the style how much of the line the zone takes. It
 * starts as the zone's length in ch (each character of the monospace face is
 * 1ch wide) and is then set to the zone's drawn width, which also counts any
 * letter spacing the reader's own style adds. Where the zone is not drawn as a
 * box of its own (the dashboard) its width reads 0 and the value is left as it is.
 */
export function nameNode(fqdn: string): HTMLElement {
  const name = el("span", "w-mono pc-name");
  name.title = fqdn;
  const labels = fqdn.split(".");
  const appendLabels = (into: HTMLElement, from: number, to: number): void => {
    for (let i = from; i < to; i++) {
      const last = i === labels.length - 1;
      into.append(document.createTextNode(last ? labels[i]! : `${labels[i]}.`));
      if (!last) into.append(document.createElement("wbr"));
    }
  };
  const start = el("span", "pc-name-start");
  if (labels.length <= 3) {
    appendLabels(start, 0, labels.length);
    name.append(start);
    return name;
  }
  const cut = labels.length - 3;
  const zone = el("span", "pc-name-zone");
  appendLabels(start, 0, cut);
  appendLabels(zone, cut, labels.length);
  name.style.setProperty("--pc-name-zone", `${labels.slice(cut).join(".").length}ch`);
  name.append(start, zone);
  if (typeof ResizeObserver === "function") {
    const watch = new ResizeObserver((entries) => {
      if (!zone.isConnected) {
        watch.disconnect();
        return;
      }
      const width = entries[entries.length - 1]?.borderBoxSize?.[0]?.inlineSize ?? 0;
      if (width > 0) name.style.setProperty("--pc-name-zone", `${width}px`);
    });
    watch.observe(zone);
  }
  return name;
}

export interface ProtectControlOptions {
  /** The element the control renders itself into. Emptied on mount. */
  root: HTMLElement;
  /**
   * Extra actions the HOST surface adds beside the one control (the
   * dashboard puts "Govern this browser" here). Rebuilt on every render,
   * so it always sees the current status.
   */
  extraActions?: (s: EgressStatus) => HTMLElement[];
  /** Called after every status the control renders, for host chrome. */
  onStatus?: (s: EgressStatus, verified: boolean | null) => void;
}

export interface ProtectControl {
  /** Re-read the background's status and repaint. */
  refresh(): Promise<void>;
  /** The status last rendered. */
  status(): EgressStatus;
}

/**
 * Build the control's markup and wire it. The ids are deliberately the
 * same on both surfaces: one control, one set of names, one set of
 * selectors for the tests that prove it.
 */
export function mountProtectControl(opts: ProtectControlOptions): ProtectControl {
  const { root } = opts;

  const head = el("div", "pc-head");
  const title = el("span", "w-label", "This browser");
  const chip = el("span", "w-chip unknown", "NOT ENROLLED");
  chip.id = "identity-state";
  head.append(title, chip);

  const routeLine = el("div", "pc-route");
  routeLine.id = "route-line";
  // Made a live region by setRoute once it holds its first words, so opening
  // a surface never reads the first fill out: only later changes are announced.

  const detail = el("div", "pc-detail");
  detail.id = "identity-detail";
  detail.hidden = true;

  const actions = el("div", "pc-actions");
  const btn = el("button", "w-btn primary", "Protect this browser") as HTMLButtonElement;
  btn.id = "btn-protect";
  btn.type = "button";
  const fix = el("button", "w-btn small", "") as HTMLButtonElement;
  fix.id = "btn-route-fix";
  fix.type = "button";
  fix.hidden = true;
  actions.append(btn, fix);

  const note = el("div", "w-note pc-note");
  note.id = "identity-note";
  note.hidden = true;

  // The steps shown while the address is reserved and routing is turned on.
  const progress = el("div", "pc-progress");
  progress.id = "protect-progress";
  progress.setAttribute("aria-live", "polite");
  progress.tabIndex = -1;
  progress.hidden = true;
  const steps = el("ol", "pc-steps");
  steps.id = "protect-steps";
  const hint = el("div", "pc-progress-hint");
  progress.append(el("div", "pc-progress-title", "Protecting this browser…"), steps, hint);

  // Words for assistive technology only (no visible text): said when routing is
  // turned off, a state with no sentence of its own. Live from the start and
  // empty, so the first paint says nothing.
  const announce = el("div", "pc-sr");
  announce.id = "route-announce";
  announce.setAttribute("aria-live", "polite");

  root.replaceChildren(head, progress, routeLine, detail, actions, note, announce);

  /** RDAP verification of the enrolled address; null until it lands. */
  let verified: boolean | null = null;
  let last: EgressStatus = NO_EGRESS;
  /** This surface's own click is in flight: reserving the address, or turning routing on. */
  let pending: "reserving" | "routing" | null = null;
  /** Bumped whenever `pending` changes, so a slow status read never paints over a newer state. */
  let epoch = 0;
  let pollTimer: ReturnType<typeof setInterval> | null = null;
  let drawn = "";

  function setNote(text: string | null): void {
    note.hidden = text === null;
    note.textContent = text ?? "";
  }

  let routeKey = "";
  /**
   * Write the route line: the dot, an optional lead word, the sentence and an
   * optional second, smaller line. The whole line is always written with one
   * replaceChildren. The first words are written before the region is live (so
   * opening a surface never reads them out) and the region is made live right
   * after; every later change is announced.
   */
  function setRoute(dot: "on" | "blocked" | "off", lead: string, sentence: string, more?: string): void {
    // Same words, same dot: leave the line alone so it is not announced again.
    const key = `${dot}|${lead}|${sentence}|${more ?? ""}`;
    if (key === routeKey) return;
    routeKey = key;
    const d = el("span", `w-dot ${dot}`);
    const text = el("span", "pc-route-text");
    if (lead) text.append(el("span", "pc-route-lead", lead), document.createTextNode(" "));
    text.append(document.createTextNode(more ? `${sentence} ` : sentence));
    if (more) text.append(el("span", "pc-route-more", more));
    routeLine.replaceChildren(d, text);
    if (!routeLine.hasAttribute("aria-live")) routeLine.setAttribute("aria-live", "polite");
  }

  /**
   * A state with no sentence: the address row is its line, so the route line
   * holds nothing. It writes nothing worth announcing, but it still makes the
   * region live, so the outcome of the next press (routed, refused, held) is
   * announced like any later change.
   */
  function clearRoute(): void {
    if (routeKey === "none") return;
    routeKey = "none";
    routeLine.replaceChildren();
    if (!routeLine.hasAttribute("aria-live")) routeLine.setAttribute("aria-live", "polite");
  }

  /** Whether the status has a sentence for the route line (see paint, which writes it). */
  function hasLine(s: EgressStatus): boolean {
    return !(s.enrolled && s.address && !s.on && !s.controlledByOther && !s.error);
  }

  /** The state the control is in, for the surface that tints itself by it and for tests. */
  function setState(state: "busy" | "failed" | "none" | "routed" | "held" | "error" | "enrolled"): void {
    const before = root.dataset["state"];
    root.dataset["state"] = state;
    // Reaching "enrolled" from "routed" is the one change with no sentence to
    // announce it. Any other change of state clears the words, so a later
    // turn-off is said again; a repaint that keeps the state leaves them alone.
    if (state !== before) announce.textContent = state === "enrolled" && before === "routed" ? "Routing is off." : "";
  }

  function fact(label: string, value: Node): HTMLElement {
    const row = el("div", "w-kv");
    row.append(el("span", "k", label));
    const v = el("span", "v");
    v.append(value);
    row.append(v);
    return row;
  }

  function renderDetail(s: EgressStatus): void {
    if (!s.address) {
      detail.hidden = true;
      detail.replaceChildren();
      return;
    }
    detail.hidden = false;
    const rows: HTMLElement[] = [fact("Address", addressNode(s.address))];
    // The name and the proof are the public record's answer, so they show once
    // it has said yes. The address does not wait for it.
    if (verified === true && s.fqdn) rows.push(fact("Name", nameNode(s.fqdn)));
    if (verified === true && s.rdapUrl) {
      const a = el("a", undefined, "RDAP record, anyone can check ") as HTMLAnchorElement;
      a.href = s.rdapUrl;
      a.target = "_blank";
      a.rel = "noopener";
      const arrow = el("span", undefined, "↗");
      arrow.setAttribute("aria-hidden", "true");
      a.append(arrow);
      rows.push(fact("Proof", a));
    }
    detail.replaceChildren(...rows);
  }

  function step(state: "done" | "current" | "todo", label: string, tryNote?: string): HTMLElement {
    const li = el("li", `pc-step ${state}`);
    if (state === "current") li.setAttribute("aria-current", "step");
    const mark = el("span", "pc-mark", state === "done" ? "✓" : "");
    mark.setAttribute("aria-hidden", "true");
    const text = el("span", "pc-step-text", label);
    if (tryNote) text.append(" ", el("span", "pc-step-try", tryNote));
    // The state is words as well as a shape and a colour.
    const words = state === "done" ? "done" : state === "current" ? "in progress" : "not started";
    li.append(mark, text, el("span", "pc-sr", ` (${words})`));
    return li;
  }

  /** Draw the steps for what is running. Redrawn only when they change, so a
   *  screen reader is not told the same thing every poll. */
  function drawSteps(phase: "reserving" | "routing", attempt: number, of: number): void {
    const key = `${phase}:${attempt}/${of}`;
    if (key === drawn) return;
    drawn = key;
    hint.textContent =
      phase === "reserving"
        ? "A new address can take a few seconds to appear."
        : "Identity reserved. Waiting for the browser's permission before routing.";
    const reserve = "Reserving your Whisper address";
    steps.replaceChildren(
      step("done", "Signed in"),
      phase === "reserving" ? step("current", reserve, `(try ${attempt} of ${of})`) : step("done", reserve),
      step(phase === "reserving" ? "todo" : "current", "Turning routing on"),
    );
  }

  /** Show the steps in place of the route line and the buttons, or put those
   *  back. Done BEFORE painting: a change written into a hidden live region is
   *  never announced, so the route line must be visible when its words change. */
  function showRegions(s: EgressStatus): "reserving" | "routing" | null {
    const busy = s.reserving ? "reserving" : pending;
    progress.hidden = busy === null;
    routeLine.hidden = busy !== null || !hasLine(s);
    actions.hidden = busy !== null;
    return busy;
  }

  /** What follows the paint: the steps, the note (paint may have shown it) and the focus. */
  function finishRegions(
    s: EgressStatus,
    busy: "reserving" | "routing" | null,
    focused: HTMLElement | null,
    progressHadFocus: boolean,
  ): void {
    if (busy === null) {
      drawn = "";
      // The held state hides the retry button and offers the way out instead.
      const action = (): HTMLElement => (btn.hidden && !fix.hidden ? fix : btn);
      if (progressHadFocus) action().focus();
      else if (focused && (focused === btn || focused === fix) && document.activeElement !== focused) {
        // Repainting the actions drops the focus of the button that had it.
        (focused.hidden ? action() : focused).focus();
      }
      return;
    }
    setState("busy");
    note.hidden = true;
    drawSteps(busy, s.reserving?.attempt ?? 1, s.reserving?.of ?? 3);
    if (focused) progress.focus();
  }

  /** While a reservation runs, on this surface or any other, keep its status fresh. */
  function syncPolling(s: EgressStatus): void {
    const need = s.reserving !== null || pending === "reserving";
    if (need && pollTimer === null) {
      pollTimer = setInterval(() => void tick(), RESERVE_POLL_MS);
    } else if (!need && pollTimer !== null) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  let ticking = false;
  async function tick(): Promise<void> {
    if (ticking) return;
    ticking = true;
    const seen = epoch;
    try {
      const s = await currentEgress();
      if (seen !== epoch) return;
      if (pending !== null) render(s);
      else await apply(s);
    } catch {
      // The background cannot be reached: stop waiting on it (see settleAfterFailure).
      if (seen === epoch) await settleAfterFailure();
    } finally {
      ticking = false;
    }
  }

  /**
   * One status, one control, and never a dead end. The chip is what this
   * browser IS on the network (an identity fact, which survives every
   * routing failure); the sentence and the button are what it is DOING (a
   * routing fact). The chip is always shown. The sentence is shown whenever
   * there is something to say (a browser that holds its address and is not
   * routed has the address row for it), and the button is the one next thing
   * to press, never two competing ones.
   */
  function render(s: EgressStatus): void {
    // Focus follows the button that is replaced by the steps, and returns to
    // it. Read before painting: repainting the actions can drop the focus.
    const focused = actions.contains(document.activeElement) ? (document.activeElement as HTMLElement) : null;
    const progressHadFocus = document.activeElement === progress;
    const busy = showRegions(s);
    paint(s);
    finishRegions(s, busy, focused, progressHadFocus);
    syncPolling(s);
  }

  function paint(s: EgressStatus): void {
    last = s;
    btn.disabled = false;
    btn.hidden = false;
    fix.hidden = true;

    const extras = opts.extraActions?.(s) ?? [];
    actions.replaceChildren(btn, fix, ...extras);

    if (!s.enrolled || !s.address) {
      chip.className = "w-chip unknown";
      chip.textContent = "NOT ENROLLED";
      chip.title = "This browser has no Whisper identity yet.";
      renderDetail(s);
      if (s.reserveFailed) {
        // Every try is used. Said once, in the control's own words, and the
        // raw error is not shown; the verdicts do not depend on any of this.
        setRoute("blocked", "", RESERVE_FAILED_TEXT);
        btn.className = "w-btn primary";
        btn.textContent = "Try again";
        btn.onclick = protect;
        setNote(null);
        setState("failed");
        opts.onStatus?.(s, verified);
        return;
      }
      setRoute("off", "", NO_IDENTITY_TEXT);
      btn.className = "w-btn primary";
      btn.textContent = "Protect this browser";
      btn.onclick = protect;
      setNote(s.error);
      setState("none");
      opts.onStatus?.(s, verified);
      return;
    }

    // Enrolled. The identity stands whatever routing does.
    if (verified === true) {
      chip.className = "w-chip ok";
      chip.textContent = "VERIFIED";
      chip.title = "This address resolves as a Whisper endpoint via keyless RDAP verify-identity.";
    } else {
      chip.className = "w-chip accent";
      chip.textContent = "ENROLLED";
      chip.title = verified === false ? "Identity reserved; public verification pending." : "Identity reserved.";
    }
    renderDetail(s);

    if (s.on) {
      setRoute("on", "Protected.", ROUTE_LINE_BASE, routeLimitsText(s).trimStart());
      btn.className = "w-btn small";
      btn.textContent = "Turn routing off";
      btn.onclick = unprotect;
      setNote(s.error);
      setState("routed");
      opts.onStatus?.(s, verified);
      return;
    }

    btn.className = "w-btn primary";
    btn.onclick = protect;
    if (s.controlledByOther) {
      // Named, not a bare "cannot": the identity is real, the verdicts still
      // run, and the way out is the extensions page. The next status read
      // shows "Turn routing on" once the other extension lets go.
      setRoute("blocked", "", HELD_TEXT);
      if (IS_FIREFOX) {
        // Not reachable there (the status never reports another extension),
        // but the control is never left with no button.
        btn.textContent = "Turn routing on";
      } else {
        btn.hidden = true;
        fix.hidden = false;
        fix.textContent = "Open the extensions page";
        fix.onclick = () => {
          chrome.tabs.create({ url: "chrome://extensions" }).catch(() => undefined);
        };
      }
      setNote(null);
      setState("held");
      opts.onStatus?.(s, verified);
      return;
    }
    if (s.error) {
      setRoute("blocked", "Not routed.", asSentence(s.error));
      btn.textContent = "Turn routing on";
      setNote(null);
      setState("error");
      opts.onStatus?.(s, verified);
      return;
    }
    clearRoute();
    btn.textContent = "Turn routing on";
    setNote(null);
    setState("enrolled");
    opts.onStatus?.(s, verified);
  }

  /** Render a status, then upgrade the chip when keyless RDAP confirms it. */
  async function apply(s: EgressStatus): Promise<void> {
    render(s);
    if (!s.enrolled || !s.address) return;
    const v = await send<{ ok: true; verification: IdentityVerification | null }>({
      kind: "verifyIdentity",
      ip: s.address,
    });
    if (!v.ok || !v.verification) return;
    verified = v.verification.isWhisperAgent;
    render(s.fqdn ? s : { ...s, fqdn: v.verification.fqdn });
  }

  async function permissionAnswer(request: Promise<boolean>): Promise<boolean> {
    const want = routingPermissions();
    let settled: boolean | null = null;
    void request.then(
      (granted) => {
        settled = granted;
      },
      () => {
        settled = false;
      },
    );
    const deadline = Date.now() + ROUTING_PERMISSION_WAIT_MS;
    for (;;) {
      // Already held is the common case on every click after the first, and
      // it answers with no wait at all.
      if (await ext.permissions.contains(want).catch(() => false)) return true;
      if (settled !== null) return settled;
      if (Date.now() >= deadline) return false;
      await new Promise((r) => setTimeout(r, ROUTING_PERMISSION_POLL_MS));
    }
  }

  function protect(): void {
    if (pending !== null) return;
    let request: Promise<boolean>;
    try {
      request = Promise.resolve(chrome.permissions.request(routingPermissions()));
    } catch {
      // Some engines throw for a set they will not offer rather than
      // resolving false. Either way the identity half below still runs.
      request = Promise.resolve(false);
    }
    // A browser that already holds its address is only turning routing on.
    pending = last.enrolled && last.address ? "routing" : "reserving";
    epoch++;
    render(last);
    void run(request).catch(settleAfterFailure);
  }

  /** The background did not answer (stopped mid-way, reloaded under an open
   *  page): end the waiting, stop polling, and repaint from what can be read,
   *  so the buttons are never left hidden behind steps that will not move. */
  async function settleAfterFailure(): Promise<void> {
    finish();
    let s = NO_EGRESS;
    try {
      s = await currentEgress();
    } catch {
      // nothing to read either: the empty status stands
    }
    render(s);
  }

  function finish(): void {
    pending = null;
    epoch++;
  }

  async function run(request: Promise<boolean>): Promise<void> {
    const enrolled = await send<
      { ok: true; enrollment: Enrollment } | { ok: false; error: string; exhausted?: boolean }
    >({ kind: "enroll" });
    if (!enrolled.ok) {
      finish();
      render(await currentEgress());
      // Every try used: the status carries it and the line says it. Anything
      // else is shown as it always was.
      if (!enrolled.exhausted) setNote(enrolled.error);
      return;
    }
    // The identity is real from here on. Show it before routing is even
    // tried, so what the reader gets is never contingent on what happens
    // next.
    verified = enrolled.enrollment.verification?.isWhisperAgent ?? null;
    pending = "routing";
    epoch++;
    render(await currentEgress());

    // The answer is waited for, not read: enabling re-checks the permission
    // itself and reports the honest reason when it is missing, so there is
    // one place that decides whether routing may engage rather than two
    // that can disagree. All this wait buys is not asking before the reader
    // answered.
    await permissionAnswer(request);
    const res = await send<{ ok: true; egress: EgressStatus } | { ok: false; error: string }>({
      kind: "egressEnable",
    });
    finish();
    if (!res.ok) {
      render(await currentEgress());
      setNote(res.error);
      return;
    }
    await apply(res.egress);
  }

  function unprotect(): void {
    // Disabling the button takes its focus; remember it and give it back to the
    // visible action once the new state is drawn.
    const hadFocus = document.activeElement === btn;
    btn.disabled = true;
    btn.textContent = "Turning off...";
    void send<{ ok: true; egress: EgressStatus }>({ kind: "egressDisable" }).then(async (res) => {
      if (res.ok) await apply(res.egress);
      else render(await currentEgress());
      // Only when the focus is still where the press left it: nowhere, or the
      // button. A reader who moved on while the identity was re-verified keeps it.
      const now = document.activeElement;
      if (hadFocus && (now === null || now === document.body || now === btn)) (btn.hidden && !fix.hidden ? fix : btn).focus();
    });
  }

  return {
    async refresh(): Promise<void> {
      try {
        await apply(await currentEgress());
      } catch {
        // The background did not answer (stopped mid-request): keep what is
        // drawn rather than claim a state nothing has read.
      }
    },
    status(): EgressStatus {
      return last;
    },
  };
}
