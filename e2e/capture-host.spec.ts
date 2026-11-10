// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The capture proxy records hosts in ONE form. Splitting an authority on the
// first ":" turned "[fd00::1]" into "[fd00", so an assertion about that host
// could never fail; this pins the parser those assertions rest on.

import { test, expect } from "@playwright/test";
import { authorityHost, hostKey } from "./helpers/servers";

test("authorityHost keeps an IPv6 literal whole and strips only the port", () => {
  const table: Array<[string, string]> = [
    ["example.com:443", "example.com"],
    ["Example.COM", "example.com"],
    ["example.com:8080", "example.com"],
    ["192.168.1.1:80", "192.168.1.1"],
    ["[fd00::1]:443", "[fd00::1]"],
    ["[fd00::1]:3000", "[fd00::1]"],
    ["[FD00::1]", "[fd00::1]"],
    ["[::1]:80", "[::1]"],
    ["fd00::1", "[fd00::1]"],
  ];
  for (const [authority, host] of table) expect(authorityHost(authority), authority).toBe(host);
});

test("hostKey brackets a bare IPv6 literal and leaves everything else alone", () => {
  expect(hostKey("fd00::1")).toBe("[fd00::1]");
  expect(hostKey("[fd00::1]")).toBe("[fd00::1]");
  expect(hostKey("Example.com")).toBe("example.com");
  expect(hostKey("192.168.1.1")).toBe("192.168.1.1");
});
