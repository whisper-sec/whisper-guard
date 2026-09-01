// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The on-page guard. Injected only where the browser's permission model
// says the user allowed it: everywhere under the opt-in Active-Shield
// broad-host grant, or on the one tab the user invoked Guard on
// (activeTab via the popup) for the pre-emptive layer and never
// anywhere else, and never via a new permission. Renders inside closed
// shadow roots so page CSS cannot touch it and it cannot leak styles. It
// reads nothing from the page content, and the only thing vetting ever
// sends anywhere is the BARE HOSTNAME of a link/form target, to the
// extension's own background (never the network directly): no URLs,
// no paths, no query strings, no form-field values, ever. (Resuming a
// held middle/modifier click hands the destination URL to the background
// purely so the tab can open with the native disposition; that URL is
// consumed on this machine and never touches the wire.)
//
//   banner     a slim dismissible amber bar (never blocks the page)
//   fieldGuard a caution shown when a password field gains focus
//   preempt    capture-phase click/submit interruption: a link to a
//              different registrable domain, or a form posting off-origin,
//              is held while the target hostname is vetted; an evidenced
//              HIGH/CRITICAL target gets an inline interstitial, everything
//              else resumes untouched (fail open, cheap on the common path)

import { LOGO_DATAURI } from "../shared/brand";
import { PREEMPT_DECIDE_TIMEOUT_MS } from "../shared/config";
import { armConsent } from "./consent";
import {
  linkTarget,
  modifiedDisposition,
  submitTarget,
  type PreemptEvidence,
} from "../shared/preempt";

interface GuardConfig {
  kind: "whisper-guard-config";
  host: string;
  severity: "high" | "medium";
  brand: string | null;
  brandDomain: string | null;
  banner: boolean;
  fieldGuard: boolean;
  /** The live graph band/label, when one flagged this host (optional). */
  band?: string | null;
  graphLabel?: string | null;
  /** The credential moment on a host the user already clicked through. */
  afterAllow?: boolean;
}

interface PreemptConfig {
  kind: "whisper-preempt-config";
  host: string;
}

interface PreemptPing {
  kind: "whisper-preempt-ping";
}

interface ConsentConfig {
  kind: "whisper-consent-config";
}

type ContentMessage = GuardConfig | PreemptConfig | PreemptPing | ConsentConfig;

const FLAG = "__whisperGuardInjected";
const w = window as unknown as Record<string, unknown>;

if (!w[FLAG]) {
  w[FLAG] = true;

  let shown = false;
  let fieldGuardArmed = false;
  let preemptArmed = false;
  let consentArmed = false;

  chrome.runtime.onMessage.addListener(
    (msg: ContentMessage, _sender, sendResponse: (r: unknown) => void) => {
      if (!msg) return;
      if (msg.kind === "whisper-preempt-ping") {
        // Test/diagnostic affordance: which on-page layers are live here?
        sendResponse({ armed: preemptArmed, consent: consentArmed });
        return;
      }
      if (msg.kind === "whisper-preempt-config") {
        // TOP DOCUMENT ONLY, decided here rather than trusted from the
        // caller. Since the consent pass injects this same file into
        // every frame, a preempt config sent without an explicit frameId
        // reaches every frame that happens to have been injected by then,
        // and the click guard would silently acquire a new home as a side
        // effect of a change about cookie banners. armConsent's ordering
        // makes that unreachable today and the background pins frameId 0
        // besides, but neither is a property of THIS module, and this is the
        // module whose scope it is. Widening the guard into sub-frames is a
        // real decision with its own risks (a framed ad's click, a target
        // that navigates the top window); it is not something that should
        // ever happen by accident.
        if (window.top !== window) return;
        if (!preemptArmed) {
          preemptArmed = true;
          armPreempt(msg.host);
        }
        return;
      }
      if (msg.kind === "whisper-consent-config") {
        // Cookie-consent auto-decline: fully local, one click at
        // most, and never an accept. See content/consent.ts for the contract.
        if (!consentArmed) {
          consentArmed = true;
          armConsent();
        }
        return;
      }
      if (msg.kind !== "whisper-guard-config") return;
      // Dismissing the banner silences THE BANNER for this host, this tab,
      // this session. It is not a blanket "never speak again": the
      // password-field caution is the credential moment, a separate
      // cell of the ladder with a different actor and a different stake,
      // and reading a bar is not a decision about what to type.
      if (msg.banner && !shown && sessionStorage.getItem("whisper-guard-dismissed") !== msg.host) {
        shown = true;
        renderBanner(msg);
      }
      if (msg.fieldGuard && !fieldGuardArmed) {
        fieldGuardArmed = true;
        armFieldGuard(msg);
      }
    },
  );

  function mount(): ShadowRoot {
    const hostEl = document.createElement("div");
    hostEl.style.cssText = "all:initial; position:fixed; z-index:2147483647;";
    (document.documentElement ?? document.body).appendChild(hostEl);
    return hostEl.attachShadow({ mode: "closed" });
  }

  function renderBanner(cfg: GuardConfig): void {
    const root = mount();
    const bar = document.createElement("div");
    bar.setAttribute("role", "alert");
    bar.style.cssText = [
      "position:fixed", "top:0", "left:0", "right:0",
      "background:#78350F", "color:#FEF3C7",
      "font:14px/1.5 system-ui,sans-serif", "padding:10px 16px",
      "display:flex", "gap:12px", "align-items:center",
      "box-shadow:0 2px 8px rgba(0,0,0,.4)",
    ].join(";");

    // The wordmark rides as a data URI: nothing becomes web-accessible.
    const logo = document.createElement("img");
    logo.src = LOGO_DATAURI;
    logo.alt = "Whisper";
    logo.style.cssText = "height:16px;width:auto;flex:none;display:block";
    bar.appendChild(logo);

    const text = document.createElement("span");
    text.style.cssText = "flex:1;min-width:0";
    const graphNote =
      cfg.band && (cfg.band === "MEDIUM" || cfg.band === "HIGH" || cfg.band === "CRITICAL")
        ? ` The Whisper graph rates it ${cfg.band}${cfg.graphLabel ? ` (${cfg.graphLabel})` : ""}.`
        : "";
    text.textContent = cfg.brandDomain
      ? `Whisper Guard: this site looks like ${cfg.brandDomain} but is not it.${graphNote} Be careful with passwords and payment details.`
      : `Whisper Guard: this site is flagged as suspicious.${graphNote} Be careful with passwords and payment details.`;
    bar.appendChild(text);

    if (cfg.brandDomain) {
      const go = document.createElement("a");
      go.href = `https://${cfg.brandDomain}/`;
      go.textContent = `Go to the real ${cfg.brandDomain}`;
      go.style.cssText =
        "background:#F59E0B;color:#1C1917;text-decoration:none;padding:6px 12px;border-radius:6px;font-weight:600;white-space:nowrap";
      bar.appendChild(go);
    }

    const dismiss = document.createElement("button");
    dismiss.textContent = "Dismiss";
    dismiss.style.cssText =
      "background:transparent;color:#FDE68A;border:1px solid #A16207;border-radius:6px;padding:6px 12px;cursor:pointer;font:inherit";
    dismiss.addEventListener("click", () => {
      sessionStorage.setItem("whisper-guard-dismissed", cfg.host);
      bar.remove();
    });
    bar.appendChild(dismiss);
    root.appendChild(bar);
  }

  function armFieldGuard(cfg: GuardConfig): void {
    let warned = false;
    document.addEventListener(
      "focusin",
      (ev) => {
        if (warned) return;
        const t = ev.target;
        if (!(t instanceof HTMLInputElement) || t.type !== "password") return;
        warned = true;
        const root = mount();
        const tip = document.createElement("div");
        tip.setAttribute("role", "alert");
        const rect = t.getBoundingClientRect();
        tip.style.cssText = [
          "position:fixed",
          `top:${Math.max(8, rect.top - 56)}px`,
          `left:${Math.max(8, rect.left)}px`,
          "max-width:340px", "background:#7F1D1D", "color:#FEE2E2",
          "font:13px/1.5 system-ui,sans-serif", "padding:10px 12px",
          "border-radius:8px", "box-shadow:0 4px 16px rgba(0,0,0,.5)",
        ].join(";");
        tip.textContent = cfg.brandDomain
          ? `Careful: this is NOT ${cfg.brandDomain}. Do not enter the password you use there.`
          : cfg.afterAllow === true
            ? "You continued past a known-threat warning for this site. Do not enter a password here, and never one you use anywhere else."
            : "Careful: this site is flagged. Think twice before entering a password here.";
        root.appendChild(tip);
        setTimeout(() => tip.remove(), 8000);
      },
      true,
    );
  }

  // ------------------------------------------- pre-emptive interruption

  function armPreempt(pageHost: string): void {
    /** Hosts already vetted clean this page-load: zero work on re-click. */
    const cleanHosts = new Set<string>();
    /** True while WE re-dispatch the original action (resume): pass it. */
    let resuming = false;
    /** One interstitial at a time. */
    let interstitialOpen = false;

    document.addEventListener("click", onActivate, true);
    document.addEventListener("auxclick", onActivate, true);
    document.addEventListener("submit", onSubmit, true);

    function onActivate(ev: MouseEvent): void {
      if (resuming || interstitialOpen) return;
      // Script-synthesized clicks are page-initiated navigation; the nav
      // pipeline (and shield) covers wherever they land. Trusted only here.
      if (!ev.isTrusted || ev.defaultPrevented) return;
      // click carries the primary button (and keyboard activation, detail
      // 0); auxclick carries the middle button. Everything else is not a
      // navigation gesture.
      if (ev.type === "click" && ev.button !== 0) return;
      if (ev.type === "auxclick" && ev.button !== 1) return;

      // Find the activated anchor, crossing shadow boundaries.
      let a: HTMLAnchorElement | null = null;
      for (const n of ev.composedPath()) {
        if (n instanceof HTMLAnchorElement && n.hasAttribute("href")) {
          a = n;
          break;
        }
      }
      if (!a) return;

      const href = a.href; // absolute, resolved by the browser
      const target = linkTarget(pageHost, href);
      // Same registrable domain, out of scope, or already vetted clean:
      // not ours to hold; the handler cost stops at this cheap check.
      if (!target || cleanHosts.has(target)) return;

      // Modified activation? Capture the disposition NOW; the event is
      // gone by the time an async decision resumes.
      const disposition = modifiedDisposition({
        middle: ev.type === "auxclick" || ev.button === 1,
        ctrl: ev.ctrlKey,
        meta: ev.metaKey,
        shift: ev.shiftKey,
      });

      ev.preventDefault();
      ev.stopImmediatePropagation();

      const anchor = a;
      const resume = (): void => {
        if (disposition) {
          // Middle- or modifier-click: a synthetic click cannot carry the
          // user's modifiers (untrusted events never trigger modified
          // navigation), and window.open always FOREGROUNDS, which would
          // steal the user's place on a middle/Ctrl-click. The background
          // opens the real thing with the native disposition instead;
          // fail open to a plain new tab if it is unreachable.
          const fallback = (): void => {
            window.open(href, "_blank", "noopener");
          };
          try {
            chrome.runtime.sendMessage(
              { kind: "preemptOpen", url: href, disposition },
              (res: { ok?: boolean } | undefined) => {
                void chrome.runtime.lastError;
                if (!res || res.ok !== true) fallback();
              },
            );
          } catch {
            fallback();
          }
          return;
        }
        if (document.contains(anchor)) {
          // Plain activation (incl. target=_blank and keyboard Enter):
          // re-dispatch on the anchor itself so target=_blank/<frame>,
          // download, rel/opener semantics, and the page's own click
          // handlers (e.g. an onclick that finalizes the real href) all
          // behave exactly as they would have.
          resuming = true;
          try {
            anchor.click();
          } finally {
            resuming = false;
          }
          return;
        }
        // Anchor gone from the document: last resort, honor the target.
        if (anchor.getAttribute("target") === "_blank") {
          window.open(href, "_blank", "noopener");
          return;
        }
        window.location.assign(href);
      };

      decide(target, resume, (evd) => showInterstitial(evd, "link", resume));
    }

    function onSubmit(ev: Event): void {
      if (interstitialOpen) return;
      const form = ev.target;
      if (!(form instanceof HTMLFormElement)) return;
      if (resuming) return; // our own requestSubmit on resume
      if (!ev.isTrusted || ev.defaultPrevented) return;

      const submitter = ev instanceof SubmitEvent ? ev.submitter : null;
      // Attribute access, not property: an <input name="action"> shadows
      // form.action, and the submitter's formaction overrides the form's.
      const raw = submitter?.getAttribute("formaction") ?? form.getAttribute("action") ?? "";
      let resolved: URL;
      try {
        resolved = new URL(raw, window.location.href);
      } catch {
        return;
      }
      const target = submitTarget(window.location.origin, resolved.href);
      if (!target || cleanHosts.has(target)) return;

      ev.preventDefault();
      ev.stopImmediatePropagation();

      const resume = (): void => {
        if (!document.contains(form)) return;
        resuming = true;
        try {
          // requestSubmit replays validation + the submit event, so the
          // page's own handlers run exactly as they would have.
          if (submitter instanceof HTMLElement) form.requestSubmit(submitter);
          else form.requestSubmit();
        } catch {
          try {
            form.submit();
          } catch {
            // form gone or inert: nothing to resume
          }
        } finally {
          resuming = false;
        }
      };

      decide(target, resume, (evd) => showInterstitial(evd, "form", resume));
    }

    /**
     * Ask the background about the held action's target: BARE HOSTNAME
     * only, ever. Fail open on every fault: no answer, a dead worker, or
     * the belt-and-braces timer all resume the original action untouched.
     */
    function decide(
      host: string,
      resume: () => void,
      interrupt: (e: PreemptEvidence) => void,
    ): void {
      let settled = false;
      const settle = (fn: () => void): void => {
        if (!settled) {
          settled = true;
          fn();
        }
      };
      const timer = setTimeout(() => settle(resume), PREEMPT_DECIDE_TIMEOUT_MS);
      try {
        chrome.runtime.sendMessage(
          { kind: "preemptCheck", host },
          (res: { ok?: boolean; preempt?: { action: string } & Partial<PreemptEvidence> } | undefined) => {
            void chrome.runtime.lastError; // read it: no unchecked-error noise
            clearTimeout(timer);
            const d = res && res.ok === true ? res.preempt : undefined;
            if (d && d.action === "interrupt" && typeof d.host === "string" && typeof d.band === "string") {
              const e: PreemptEvidence = {
                host: d.host,
                band: d.band,
                label: d.label ?? null,
                coverage: d.coverage ?? null,
              };
              settle(() => interrupt(e));
            } else if (d) {
              cleanHosts.add(host);
              settle(resume);
            } else {
              settle(resume); // background unreachable: fail open, do not cache
            }
          },
        );
      } catch {
        clearTimeout(timer);
        settle(resume);
      }
    }

    function showInterstitial(evd: PreemptEvidence, kind: "link" | "form", resume: () => void): void {
      if (interstitialOpen) return;
      interstitialOpen = true;
      const root = mount();
      const hostEl = root.host as HTMLElement;

      const overlay = document.createElement("div");
      overlay.setAttribute("role", "alertdialog");
      overlay.setAttribute("aria-modal", "true");
      overlay.style.cssText = [
        "position:fixed", "inset:0", "background:rgba(12,10,9,.78)",
        "display:flex", "align-items:center", "justify-content:center",
        "font:15px/1.6 system-ui,sans-serif", "padding:16px",
      ].join(";");

      const card = document.createElement("div");
      card.style.cssText = [
        "max-width:480px", "width:100%", "background:#1C1917", "color:#F5F5F4",
        "border-radius:12px", "padding:24px", "box-shadow:0 12px 48px rgba(0,0,0,.6)",
        "border-top:4px solid #DC2626",
      ].join(";");

      const logo = document.createElement("img");
      logo.src = LOGO_DATAURI;
      logo.alt = "Whisper";
      logo.style.cssText = "height:18px;width:auto;display:block;margin-bottom:14px";
      card.appendChild(logo);

      const h = document.createElement("div");
      h.style.cssText = "font-size:18px;font-weight:700;margin-bottom:8px;color:#FECACA";
      h.textContent =
        kind === "form"
          ? "Whisper stopped a dangerous form submission"
          : "Whisper stopped a dangerous link";
      card.appendChild(h);

      const detail = document.createElement("p");
      detail.style.cssText = "margin:0 0 12px";
      detail.textContent =
        kind === "form"
          ? `${evd.host} is flagged ${evd.band} in the Whisper security graph. Nothing you typed was sent.`
          : `${evd.host} is flagged ${evd.band} in the Whisper security graph. The click was stopped before anything loaded.`;
      card.appendChild(detail);

      // The receipts: band, label, coverage, straight from the verdict.
      const receipts = document.createElement("div");
      receipts.style.cssText =
        "background:#292524;border-radius:8px;padding:10px 12px;margin:0 0 12px;font-size:13px;color:#D6D3D1";
      const rows: [string, string | null][] = [
        ["verdict", evd.band],
        ["label", evd.label],
        ["coverage", evd.coverage],
      ];
      for (const [k, v] of rows) {
        if (!v) continue;
        const row = document.createElement("div");
        const kEl = document.createElement("span");
        kEl.style.cssText = "display:inline-block;min-width:80px;color:#A8A29E";
        kEl.textContent = k;
        row.append(kEl, document.createTextNode(v));
        receipts.appendChild(row);
      }
      card.appendChild(receipts);

      const privacy = document.createElement("p");
      privacy.style.cssText = "margin:0 0 16px;font-size:12px;color:#A8A29E";
      privacy.textContent = `Privacy: only "${evd.host}" was checked. Your browsing stays yours.`;
      card.appendChild(privacy);

      const buttons = document.createElement("div");
      buttons.style.cssText = "display:flex;gap:10px;justify-content:flex-end";

      const back = document.createElement("button");
      back.textContent = "Go back";
      back.style.cssText =
        "background:#F5F5F4;color:#1C1917;border:0;border-radius:8px;padding:9px 16px;font:inherit;font-weight:600;cursor:pointer";

      const proceed = document.createElement("button");
      proceed.textContent = "Proceed anyway";
      proceed.style.cssText =
        "background:transparent;color:#D6D3D1;border:1px solid #57534E;border-radius:8px;padding:9px 16px;font:inherit;cursor:pointer";

      const close = (): void => {
        interstitialOpen = false;
        document.removeEventListener("keydown", onKey, true);
        hostEl.remove();
      };
      const onKey = (kev: KeyboardEvent): void => {
        if (kev.key === "Escape") {
          kev.preventDefault();
          kev.stopImmediatePropagation();
          close();
        }
      };

      back.addEventListener("click", close);
      proceed.addEventListener("click", () => {
        // Honest one-click-through, like the full-page warning: session-
        // allow in the background (which also lifts any DNR rule), THEN
        // resume, so the resumed navigation is not re-blocked. Fail open
        // if the background is unreachable.
        cleanHosts.add(evd.host);
        const go = (): void => {
          close();
          resume();
        };
        try {
          chrome.runtime.sendMessage({ kind: "preemptAllow", host: evd.host }, () => {
            void chrome.runtime.lastError;
            go();
          });
        } catch {
          go();
        }
      });

      document.addEventListener("keydown", onKey, true);
      buttons.append(back, proceed);
      card.appendChild(buttons);
      overlay.appendChild(card);
      root.appendChild(overlay);
      back.focus();
    }
  }
}
