// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Unit coverage for the target-risk decision core (pure functions,
// no browser): which link clicks and form submits are held for vetting,
// and which verdicts are allowed to interrupt. Same runner as the e2e
// suite so `npx playwright test` covers everything in one pass.

import { test, expect } from "@playwright/test";
import { linkTarget, modifiedDisposition, shouldInterrupt, submitTarget } from "../src/shared/preempt";

// ------------------------------------------------------------ link clicks

test("link to a DIFFERENT registrable domain is held (hostname only comes back)", () => {
  expect(linkTarget("shop.example.com", "https://evil-known.com/steal?token=hunter2#frag")).toBe(
    "evil-known.com",
  );
});

test("link within the SAME registrable domain is never held", () => {
  expect(linkTarget("www.example.com", "https://login.example.com/a?b=c")).toBeNull();
  expect(linkTarget("example.com", "https://example.com/deep/path")).toBeNull();
});

test("PSL semantics: co.uk siblings are the same registrable domain; strangers are not", () => {
  expect(linkTarget("a.example.co.uk", "https://b.example.co.uk/x")).toBeNull();
  expect(linkTarget("example.co.uk", "https://other.co.uk/x")).toBe("other.co.uk");
});

test("out-of-scope link targets are never held: non-http(s), IP literals, local names", () => {
  expect(linkTarget("example.com", "mailto:x@y.com")).toBeNull();
  expect(linkTarget("example.com", "javascript:void(0)")).toBeNull();
  expect(linkTarget("example.com", "https://192.168.1.1/router")).toBeNull();
  expect(linkTarget("example.com", "https://intranet/wiki")).toBeNull();
  expect(linkTarget("example.com", "https://printer.local/")).toBeNull();
  expect(linkTarget("example.com", "not a url at all")).toBeNull();
});

test("trailing dot and case never split a domain from itself", () => {
  expect(linkTarget("Example.COM", "https://www.example.com./x")).toBeNull();
});

// ------------------------------------------------------------ form submits

test("form action posting OFF-ORIGIN is held, and only the hostname comes back", () => {
  expect(submitTarget("https://checkout.example.com", "https://collector-evil.com/grab?sid=1")).toBe(
    "collector-evil.com",
  );
});

test("same-origin form action is never held", () => {
  expect(submitTarget("https://www.example.com", "https://www.example.com/login")).toBeNull();
});

test("off-origin is stricter than the link rule: a sibling subdomain IS vetted", () => {
  expect(submitTarget("https://www.example.com", "https://api.example.com/submit")).toBe(
    "api.example.com",
  );
});

test("scheme downgrade is off-origin even on the same host", () => {
  expect(submitTarget("https://www.example.com", "http://www.example.com/login")).toBe(
    "www.example.com",
  );
});

test("out-of-scope form targets are never held", () => {
  expect(submitTarget("https://example.com", "https://10.0.0.5/post")).toBeNull();
  expect(submitTarget("https://example.com", "not a url")).toBeNull();
});

// ------------------------------------------------------ the calm ladder

test("only evidenced HIGH/CRITICAL interrupts; everything else flows", () => {
  expect(shouldInterrupt({ band: "CRITICAL" })).toBe(true);
  expect(shouldInterrupt({ band: "HIGH" })).toBe(true);
  expect(shouldInterrupt({ band: "MEDIUM" })).toBe(false);
  expect(shouldInterrupt({ band: "LOW" })).toBe(false);
  expect(shouldInterrupt({ band: "INFO" })).toBe(false);
  expect(shouldInterrupt({ band: "NONE" })).toBe(false);
  expect(shouldInterrupt({ band: "UNKNOWN" })).toBe(false);
  expect(shouldInterrupt(null)).toBe(false);
  expect(shouldInterrupt(undefined)).toBe(false);
});

// ------------------------------------------- modified-click dispositions

test("middle- and Ctrl/Cmd-click resume as a BACKGROUND tab (the native disposition)", () => {
  expect(modifiedDisposition({ middle: true, ctrl: false, meta: false, shift: false })).toBe(
    "background-tab",
  );
  expect(modifiedDisposition({ middle: false, ctrl: true, meta: false, shift: false })).toBe(
    "background-tab",
  );
  expect(modifiedDisposition({ middle: false, ctrl: false, meta: true, shift: false })).toBe(
    "background-tab",
  );
});

test("adding Shift foregrounds the tab; Shift alone opens a window", () => {
  expect(modifiedDisposition({ middle: false, ctrl: true, meta: false, shift: true })).toBe(
    "foreground-tab",
  );
  expect(modifiedDisposition({ middle: true, ctrl: false, meta: false, shift: true })).toBe(
    "foreground-tab",
  );
  expect(modifiedDisposition({ middle: false, ctrl: false, meta: false, shift: true })).toBe(
    "window",
  );
});

test("a plain activation (primary button or keyboard, no modifiers) has no disposition: it re-dispatches the anchor", () => {
  expect(modifiedDisposition({ middle: false, ctrl: false, meta: false, shift: false })).toBeNull();
});
