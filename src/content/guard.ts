// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The Active Shield on-page guard. Injected ONLY on flagged hosts, ONLY
// after the user opted in to Active Shield (runtime broad-host grant).
// Renders inside a closed shadow root so page CSS cannot touch it and it
// cannot leak styles. It reads nothing from the page and sends nothing
// anywhere: pure warning UI.
//
//   banner     a slim dismissible amber bar (never blocks the page)
//   fieldGuard a caution shown when a password field gains focus

interface GuardConfig {
  kind: "whisper-guard-config";
  host: string;
  severity: "high" | "medium";
  brand: string | null;
  brandDomain: string | null;
  banner: boolean;
  fieldGuard: boolean;
}

const FLAG = "__whisperGuardInjected";
const w = window as unknown as Record<string, unknown>;

if (!w[FLAG]) {
  w[FLAG] = true;

  let shown = false;
  let fieldGuardArmed = false;

  chrome.runtime.onMessage.addListener((msg: GuardConfig) => {
    if (!msg || msg.kind !== "whisper-guard-config") return;
    if (sessionStorage.getItem("whisper-guard-dismissed") === msg.host) return;
    if (msg.banner && !shown) {
      shown = true;
      renderBanner(msg);
    }
    if (msg.fieldGuard && !fieldGuardArmed) {
      fieldGuardArmed = true;
      armFieldGuard(msg);
    }
  });

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

    const text = document.createElement("span");
    text.style.cssText = "flex:1;min-width:0";
    text.textContent = cfg.brandDomain
      ? `Whisper Guard: this site looks like ${cfg.brandDomain} but is not it. Be careful with passwords and payment details.`
      : "Whisper Guard: this site is flagged as suspicious. Be careful with passwords and payment details.";
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
          : "Careful: this site is flagged. Think twice before entering a password here.";
        root.appendChild(tip);
        setTimeout(() => tip.remove(), 8000);
      },
      true,
    );
  }
}
