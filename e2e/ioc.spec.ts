// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The indicator extractor, tested where it is riskiest: a scanner is judged by
// what it does NOT report. A parser that finds every indicator and also calls
// every version string a domain is worse than useless on the pages an analyst
// actually scans, because the noise is what makes people turn a feature off.
//
// So the negatives below are not filler. Each one is a shape that appears on
// ordinary pages - a semver, a decimal, a filename, a git sha - and each would
// be a false indicator without a specific rule to reject it.

import { test, expect } from "@playwright/test";
import { extractIocs, refang, applyIgnoreList, iocsToText } from "../src/shared/ioc";

const vals = (text: string) => extractIocs(text).map((i) => `${i.kind}:${i.value}`);

test("refangs the forms indicators are actually published in", () => {
  // Every one of these is how a real advisory writes it so nobody clicks it.
  expect(refang("1.2.3[.]4")).toBe("1.2.3.4");
  expect(refang("evil(dot)example")).toBe("evil.example");
  expect(refang("evil[dot]example")).toBe("evil.example");
  expect(refang("hxxps://bad[.]example/p")).toBe("https://bad.example/p");
  expect(refang("hxxp://bad[.]example")).toBe("http://bad.example");
  expect(refang("10.0.0.1[:]8080")).toBe("10.0.0.1:8080");
});

test("a defanged indicator and a live one are the same indicator", () => {
  const a = extractIocs("contact 203.0.113.9 now");
  const b = extractIocs("contact 203.0.113[.]9 now");
  expect(a.map((i) => i.value)).toEqual(b.map((i) => i.value));
  expect(a[0]?.kind).toBe("ipv4");
});

test("finds each kind, and gives a url its host to assess", () => {
  const got = vals(
    [
      "See hxxps://evil[.]example/payload.bin and 198.51.100.7",
      "hash d41d8cd98f00b204e9800998ecf8427e",
      "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "tracked as CVE-2026-1234 on cdn.example.org",
    ].join("\n"),
  );
  expect(got).toContain("url:https://evil.example/payload.bin");
  expect(got).toContain("ipv4:198.51.100.7");
  expect(got).toContain("md5:d41d8cd98f00b204e9800998ecf8427e");
  expect(got).toContain("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  expect(got).toContain("cve:CVE-2026-1234");
  expect(got).toContain("domain:cdn.example.org");

  const url = extractIocs("hxxps://evil[.]example/x").find((i) => i.kind === "url");
  expect(url?.host).toBe("evil.example");
});

test("a url's host is not ALSO reported as a bare domain", () => {
  // Otherwise every scan double-counts, and the copied list has duplicates in it.
  const got = vals("go to https://evil.example/a and https://evil.example/b");
  expect(got.filter((v) => v === "domain:evil.example")).toHaveLength(0);
  expect(got.filter((v) => v.startsWith("url:"))).toHaveLength(2);
});

test("a url's PATH is not mined for further indicators", () => {
  // The bug this pins: https://evil.example/payload.bin yielded a second
  // "domain" payload.bin, because a filename and a hostname are the same shape.
  // Claiming only the host was not enough - the leak was in the path. Extending
  // the file-extension deny-list would have been whack-a-mole; masking the whole
  // url span is the rule that actually holds.
  const got = vals("fetch https://evil.example/payload.bin and https://a.example/x/report.doc?q=1.2.3.4");
  expect(got.filter((v) => v.startsWith("domain:"))).toHaveLength(0);
  expect(got.filter((v) => v.startsWith("ipv4:"))).toHaveLength(0);
  expect(got.filter((v) => v.startsWith("url:"))).toHaveLength(2);
});

test("rejects the things that merely look like indicators", () => {
  const got = vals(
    [
      "version 1.2.3 and v10.20.30",     // semver
      "ratio 3.14 and 0.5",              // decimals
      "open config.json and main.js",    // filenames
      "commit 4f2a1b9c8d3e5f6a7b8c9d0e1f2a3b4c5d6e7f81", // 40 hex IS a sha1, see below
      "port 999.999.999.999",            // not a valid dotted quad
    ].join("\n"),
  );
  expect(got).not.toContain("domain:1.2.3");
  expect(got).not.toContain("domain:3.14");
  expect(got).not.toContain("domain:config.json");
  expect(got).not.toContain("domain:main.js");
  expect(got).not.toContain("ipv4:999.999.999.999");
  // A 40-hex git sha is indistinguishable from a sha1 file hash by inspection,
  // so it IS reported. Recording that on purpose: the alternative is dropping
  // real sha1 indicators, and a false positive an analyst can dismiss beats a
  // malware hash silently withheld.
  expect(got).toContain("sha1:4f2a1b9c8d3e5f6a7b8c9d0e1f2a3b4c5d6e7f81");
});

test("octet bounds are enforced, so a version-like quad is not an address", () => {
  expect(vals("build 10.4.256.1")).not.toContain("ipv4:10.4.256.1");
  expect(vals("host 10.4.255.1")).toContain("ipv4:10.4.255.1");
});

test("deduplicates and preserves first-appearance order", () => {
  const got = extractIocs("a.example then b.example then a.example again");
  expect(got.map((i) => i.value)).toEqual(["a.example", "b.example"]);
});

test("the cap bounds the RESULT so a hostile page cannot produce an endless list", () => {
  const many = Array.from({ length: 400 }, (_, i) => `h${i}.example`).join(" ");
  expect(extractIocs(many, 50)).toHaveLength(50);
});

test("the ignore list silences a label without silencing its neighbours", () => {
  const iocs = extractIocs("a.example.com notexample.com evil.test");
  const kept = applyIgnoreList(iocs, ["example"]).map((i) => i.value);
  expect(kept).not.toContain("a.example.com");
  expect(kept).toContain("notexample.com");
  expect(kept).toContain("evil.test");
});

test("an empty ignore list changes nothing", () => {
  const iocs = extractIocs("a.example.com 198.51.100.7");
  expect(applyIgnoreList(iocs, []).length).toBe(iocs.length);
  expect(applyIgnoreList(iocs, ["   "]).length).toBe(iocs.length);
});

test("the clipboard form groups by kind and is pasteable as-is", () => {
  const txt = iocsToText(extractIocs("https://a.example/x 198.51.100.7 d41d8cd98f00b204e9800998ecf8427e"));
  expect(txt).toContain("# url (1)");
  expect(txt).toContain("# ipv4 (1)");
  expect(txt).toContain("# md5 (1)");
  expect(txt.split("\n").filter((l) => l && !l.startsWith("#"))).toHaveLength(3);
});

test("empty and junk input yield nothing rather than throwing", () => {
  expect(extractIocs("")).toEqual([]);
  expect(extractIocs("   \n\t  ")).toEqual([]);
  expect(extractIocs("no indicators here at all")).toEqual([]);
});
