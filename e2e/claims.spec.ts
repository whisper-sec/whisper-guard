// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// NO SHIPPED SURFACE MAY QUOTE THE SIZE OF THE GRAPH FROM A CONSTANT.
//
// The figure is published live and it moves. A number typed into a page is
// stale the day after it ships, and a security product quoting a stale
// number about its own coverage is worse than one quoting none: the reader
// cannot tell the difference between a measurement and a memory, and the
// memory is always the flattering one.
//
// The first-run page carried "7.4 billion nodes" for exactly this reason -
// it was true when it was written. It is now read from the public stats
// endpoint on load, and this stops the next one from being typed.
//
// The check is a grep, so it is only worth anything if it can fail. It is
// mutation-tested against a planted line below, because a repository-wide
// sweep that matches nothing passes silently and forever.

import { test, expect } from "@playwright/test";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");

/**
 * A graph-scale claim: a big round count of nodes, edges or objects. Written
 * to catch the shapes a person actually writes ("7.4 billion nodes",
 * "39.5B edges", "7,482,240,523 nodes"), not every number in the tree.
 */
const CLAIM_RE =
  /\b\d[\d.,]*\s*(?:billion|million|B|M)?\s*(?:\+\s*)?(?:graph\s+)?(?:nodes|edges|objects)\b/i;

/** Files that ship to a reader, or that a reader reads about us. */
function shippedFiles(): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir)) {
      if (entry === "node_modules" || entry === ".git" || entry === "dist") continue;
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else if (/\.(html|ts|md)$/.test(entry) && !full.includes(`${"e2e"}/`)) {
        out.push(full);
      }
    }
  };
  walk(join(ROOT, "src"));
  walk(join(ROOT, "store"));
  out.push(join(ROOT, "README.md"));
  return out;
}

/**
 * Lines that state a graph size. Comments are included deliberately: a
 * comment saying "the graph has 7.4B nodes" is a claim a future author will
 * copy into a sentence.
 */
function claims(text: string): string[] {
  return text
    .split("\n")
    .filter((line) => CLAIM_RE.test(line))
    // The live path is allowed to talk about nodes and edges: it is what
    // reads them. It is recognised by naming the reading, not by its path,
    // so moving the file does not silently widen the exemption.
    .filter((line) => !/read live|graphScale|scale\.nodes|sc\.nodes|res\.scale|GraphScale/.test(line));
}

test("the graph's size is never quoted from a constant on a shipped surface", () => {
  // CONTROL: the sweep must be able to find one. If this stops failing, the
  // assertion below is decoration and every future hardcoded figure ships.
  const planted = "Every site is checked against 7.4 billion nodes of ground truth.";
  expect(claims(planted), "the sweep cannot detect a hardcoded figure").toHaveLength(1);
  expect(claims("Every site is checked live against the Whisper graph."), "the sweep flags innocent prose").toHaveLength(0);

  const offenders: string[] = [];
  for (const file of shippedFiles()) {
    let text: string;
    try {
      text = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    for (const line of claims(text)) {
      offenders.push(`${file.slice(ROOT.length + 1)}: ${line.trim()}`);
    }
  }
  expect(
    offenders,
    `these lines quote the graph's size from a constant; read it from the stats endpoint instead:\n${offenders.join("\n")}`,
  ).toEqual([]);
});

// ------------------------------------------------- fixture hygiene: the pixels
//
// NO REAL BUSINESS MAY BE NAMED ON A RUNG IN A PUBLISHED FIGURE.
//
// The hostnames in these fixtures were already reserved, the addresses are
// RFC 5737 documentation space and the ASNs are private-use. The physical
// rung was new and had none of that discipline: it named real colocation
// facilities and real internet exchanges, so a named operator appeared
// directly beneath a red CRITICAL badge in screenshots bound for two
// extension stores. The picture asserted something untrue about a real
// business, published by a security company.
//
// The operator is deliberately not named here either. Removing the claim
// from the image and restating it in searchable English, in a public
// repository, is the same claim about the same party in a form that indexes.
//
// A reviewer caught it by eye. This makes it permanent, and it is a
// whitelist rather than a blacklist because the set of real facilities is
// unbounded while the set of acceptable fixture names is one word long.

const PRESENCE_RE = /(facilities|exchanges|facilitySample|ixSample)\s*:\s*\[([^\]]*)\]/g;

function fixtureFacilityNames(text: string): string[] {
  const out: string[] = [];
  for (const m of text.matchAll(PRESENCE_RE)) {
    for (const q of (m[2] ?? "").matchAll(/"([^"]+)"/g)) {
      const name = q[1];
      if (name) out.push(name);
    }
  }
  return out;
}

test("no fixture names a real facility or exchange: published pixels stay fictional", () => {
  // CONTROL: the sweep can find one, and does not flag a compliant one.
  // An INVENTED offending name: it fails the startsWith("Example") rule,
  // which is all the control needs, and naming a real operator to prove a
  // regex works would repeat the mistake this test exists to prevent.
  expect(fixtureFacilityNames('facilities: ["Acme Carrier Hotel MTL3"],')).toEqual(["Acme Carrier Hotel MTL3"]);
  expect(fixtureFacilityNames('exchanges: ["Example Exchange LON"],')).toEqual(["Example Exchange LON"]);
  expect(fixtureFacilityNames("nothing here"), "the sweep invents matches").toEqual([]);

  const offenders: string[] = [];
  // RECURSE. The first version walked e2e/ and skipped directories, which
  // missed e2e/helpers/ - the one place the presence fixtures are actually
  // typed and served. A sweep that cannot see where the data lives is a
  // sweep that passes for the wrong reason.
  const walk = (dir: string, rel: string): void => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full, `${rel}${entry}/`);
        continue;
      }
      if (!entry.endsWith(".ts")) continue;
      // This file itself is skipped, because the control above is a
      // deliberate offending string and the sweep would otherwise report its
      // own test data. The control stays inline rather than moving out of
      // reach: a checker whose ability to fail lives in another file is a
      // checker nobody re-proves.
      if (entry === "claims.spec.ts") continue;
      for (const name of fixtureFacilityNames(readFileSync(full, "utf8"))) {
        // One word, and it is the same word the reserved domains use.
        if (!name.startsWith("Example")) offenders.push(`${rel}${entry}: "${name}"`);
      }
    }
  };
  walk(join(ROOT, "e2e"), "e2e/");
  expect(
    offenders,
    `these fixtures name something that may be a real business, and they render into published screenshots:\n${offenders.join(
      "\n",
    )}\nName them "Example ..." instead.`,
  ).toEqual([]);
});
