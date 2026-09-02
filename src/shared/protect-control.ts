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
//   - Routing comes last and is allowed to fail. When it does, the status
//     that comes back names what is in the way and the control shows it,
//     with a way to retry. Never a dead end.

import { send } from "./messages";
import { EGRESS_REQUEST } from "./config";
import { ext } from "./api";
import { IS_FIREFOX } from "./engine";
import type { EgressStatus, Enrollment, IdentityVerification } from "./types";

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
  error: null,
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

  root.replaceChildren(head, routeLine, detail, actions, note);

  /** RDAP verification of the enrolled address; null until it lands. */
  let verified: boolean | null = null;
  let last: EgressStatus = NO_EGRESS;

  function setNote(text: string | null): void {
    note.hidden = text === null;
    note.textContent = text ?? "";
  }

  function setRoute(dot: "on" | "blocked" | "off", lead: string, rest: string): void {
    const d = el("span", `w-dot ${dot}`);
    const text = el("span", "pc-route-text");
    text.append(el("span", "pc-route-lead", lead), document.createTextNode(` ${rest}`));
    routeLine.replaceChildren(d, text);
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
    if (s.fqdn) {
      const name = el("span", "w-mono");
      name.textContent = s.fqdn;
      rows.push(fact("Name", name));
    }
    if (s.rdapUrl) {
      const a = el("a", undefined, "RDAP registration (anyone can check)") as HTMLAnchorElement;
      a.href = s.rdapUrl;
      a.target = "_blank";
      a.rel = "noopener";
      rows.push(fact("Proof", a));
    }
    detail.replaceChildren(...rows);
  }

  /**
   * One status, one control, and never a dead end. The chip is what this
   * browser IS on the network (an identity fact, which survives every
   * routing failure); the line and the button are what it is DOING (a
   * routing fact). Both are always shown, because collapsing them would
   * hide a real state.
   */
  function render(s: EgressStatus): void {
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
      setRoute(
        "off",
        "Not protected.",
        "One click gives this browser its own routable Whisper IPv6 address and sends its traffic out through it. Anyone can check that address by RDAP.",
      );
      btn.className = "w-btn primary";
      btn.textContent = "Protect this browser";
      btn.onclick = protect;
      setNote(s.error);
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
      // The WebRTC half is stated either way. Chromium lets an extension
      // pin the handling policy, so the claim "everything sources from the
      // /128" is true there; Firefox exposes no such control, and a limit
      // we cannot close is one we say out loud rather than leave the reader
      // to assume.
      const webrtc =
        s.webrtcHardened === true
          ? " WebRTC is hardened to proxied-only."
          : " WebRTC cannot be pinned on this browser, so a peer connection can still reveal a local address.";
      setRoute("on", "Protected.", `Every window in this profile leaves from this address.${webrtc}`);
      btn.className = "w-btn small";
      btn.textContent = "Turn routing off";
      btn.onclick = unprotect;
      setNote(s.error);
      opts.onStatus?.(s, verified);
      return;
    }

    btn.className = "w-btn primary";
    btn.onclick = protect;
    if (s.controlledByOther) {
      // Named, not a bare "cannot": the identity is real, the verdicts
      // still run, and the one thing that would let routing engage is
      // spelled out.
      setRoute(
        "blocked",
        "Not routed.",
        "Another extension (a VPN or proxy manager) holds this browser's proxy setting. Your identity and site verdicts keep working. Turn that extension's proxy control off, then try again.",
      );
      btn.textContent = "Try again";
      if (!IS_FIREFOX) {
        fix.hidden = false;
        fix.textContent = "Open the extensions page";
        fix.onclick = () => {
          chrome.tabs.create({ url: "chrome://extensions" }).catch(() => undefined);
        };
      }
      setNote(null);
      opts.onStatus?.(s, verified);
      return;
    }
    if (s.error) {
      setRoute("blocked", "Not routed.", asSentence(s.error));
      btn.textContent = "Turn routing on";
      setNote(null);
      opts.onStatus?.(s, verified);
      return;
    }
    setRoute("off", "Identity reserved.", "This browser holds its address but does not route through it yet.");
    btn.textContent = "Turn routing on";
    setNote(null);
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
    let request: Promise<boolean>;
    try {
      request = Promise.resolve(chrome.permissions.request(routingPermissions()));
    } catch {
      // Some engines throw for a set they will not offer rather than
      // resolving false. Either way the identity half below still runs.
      request = Promise.resolve(false);
    }
    btn.disabled = true;
    btn.textContent = "Working...";
    fix.hidden = true;
    setNote("Reserving this browser's identity. A few seconds.");
    void run(request);
  }

  async function run(request: Promise<boolean>): Promise<void> {
    const enrolled = await send<{ ok: true; enrollment: Enrollment } | { ok: false; error: string }>({
      kind: "enroll",
    });
    if (!enrolled.ok) {
      render(await currentEgress());
      setNote(enrolled.error);
      return;
    }
    // The identity is real from here on. Show it before routing is even
    // tried, so what the reader gets is never contingent on what happens
    // next.
    verified = enrolled.enrollment.verification?.isWhisperAgent ?? null;
    render(await currentEgress());
    btn.disabled = true;
    btn.textContent = "Working...";
    setNote("Identity reserved. Waiting for the browser's permission before routing.");

    // The answer is waited for, not read: enabling re-checks the permission
    // itself and reports the honest reason when it is missing, so there is
    // one place that decides whether routing may engage rather than two
    // that can disagree. All this wait buys is not asking before the reader
    // answered.
    await permissionAnswer(request);
    const res = await send<{ ok: true; egress: EgressStatus } | { ok: false; error: string }>({
      kind: "egressEnable",
    });
    if (!res.ok) {
      render(await currentEgress());
      setNote(res.error);
      return;
    }
    await apply(res.egress);
  }

  function unprotect(): void {
    btn.disabled = true;
    btn.textContent = "Turning off...";
    void send<{ ok: true; egress: EgressStatus }>({ kind: "egressDisable" }).then(async (res) => {
      if (res.ok) await apply(res.egress);
      else render(await currentEgress());
    });
  }

  return {
    async refresh(): Promise<void> {
      await apply(await currentEgress());
    },
    status(): EgressStatus {
      return last;
    },
  };
}
