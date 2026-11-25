// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// The five verdict tiles are designer art, committed as delivered and never
// generated. This spec pins their bytes, keeps every icon file free of text,
// time and editor metadata, and checks the generator's write guard. No
// browser, no network.

import { test, expect } from "@playwright/test";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { assertGeneratedTarget, GENERATED_STATES, VERDICT_STATES } from "../scripts/icon-targets.mjs";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const SIZES = [16, 32, 48, 128];

const sha = (file: string): string => createHash("sha256").update(readFileSync(join(ROOT, file))).digest("hex");

// A new delivery of the art updates these in the same change.
const PINS: Record<string, string> = {
  "icons/benign-16.png": "5480e4be4cff8c3786229c2764b03fb88eeac4fe6471956c0f8b106c61319601",
  "icons/benign-32.png": "a635c85b8816036a727db64153197af32a1c5f06c2725c13832db61e007a2d14",
  "icons/benign-48.png": "db8a3934daa20a4ae8e581a151475eec064d189ead760fc536d2ddb95d05371a",
  "icons/benign-128.png": "9baa344c8fe8f7e66310943f71e3fbd3e861460ac2c319d9340a3987dfe33746",
  "icons/suspicious-16.png": "03d1076f5e54a5c40c5dcc70e63cd2ee43a9b64f8df5458fbf7f9f9f6011d7f3",
  "icons/suspicious-32.png": "c4a984f1e49cbc3e04741d91d7f01f9f0b6b509d4b9f9c4e8b1c2136ad22addf",
  "icons/suspicious-48.png": "71bb9a1a13d3ffc68a2300728519e5cfc4927507a2e9343d637d978ea7fdb67b",
  "icons/suspicious-128.png": "a33098856b9f80281f1309006a7912c3c95b7b2e448f942d0ae023bd459c93bd",
  "icons/malicious-16.png": "8cbf64e9ca9d38c6b8890999b03a6d2f300547cca624286e089372c717e6dedc",
  "icons/malicious-32.png": "af8e72fb22718e3c84fd733f705477fcac20637cade85fa3374bbca246fe8fcb",
  "icons/malicious-48.png": "d492f855bb932dfbfbc63fcedca348383e4c9082de4154d54060c5c0c29d4105",
  "icons/malicious-128.png": "4fa69f6bd684ebc26ac27a7498584ad51572318f5c20a97b1ea93736f624ebc3",
  "icons/unknown-16.png": "e95b66743d74d413f0fb0666900363067d884ce84c24cb024075b622e60443af",
  "icons/unknown-32.png": "32078eff903d6f8786f2b9675bf794edde7932d7cac76cb9a4772adc1e7d9bae",
  "icons/unknown-48.png": "149a5f9ccc725f6c4e6640e269499d6f84f5bd42e6bc640f199e389c9f4ca334",
  "icons/unknown-128.png": "9ba640137908538d7318e7a644ca0db0e4941d0d9b442d05717045bcc9c10f3c",
  "icons/checking-16.png": "268c34ecb5d917d67011dd9fe8bf7f228ec3811c6224814de65d7d12e5a40fa8",
  "icons/checking-32.png": "18bb717a8cab54b8c0ed90416beab329b08571c7e27181408fa7d941cb626ec8",
  "icons/checking-48.png": "17fd9b82d84b213b2ff0b080d95b1e8c86b41046d2ade26a1966bc5d0e2e927f",
  "icons/checking-128.png": "50254e2d1c34d4a0c8132d14cb180af7b5fbf3bdbcaf5616d25fdf39e9c22436",
  "assets/icons/benign.svg": "ef0a924ce7a2d34709143110145a5cdf144286336db85bf8243efaddabf621ef",
  "assets/icons/suspicious.svg": "fb0ad6d3aad79a4238fd5e51aa41ebe260a71a770c60494d4d036b3b8fdc0c3e",
  "assets/icons/malicious.svg": "45f59d6d1dd2c90604f45977bb839fe883e799eea05a466d5531e2152427289f",
  "assets/icons/unknown.svg": "6cd6f950af6cda4d0165b6c257f1fd2eea5d3348667004d7ff775974889e2e85",
  "assets/icons/checking.svg": "1c3043d18ab20739d6d5fd611d4f884993c209e217b10e7a76ba696dab8e68c3",
};

test("the five verdict tiles and their masters are the delivered art, byte for byte", () => {
  expect(Object.keys(PINS)).toHaveLength(VERDICT_STATES.length * (SIZES.length + 1));
  for (const [file, want] of Object.entries(PINS)) {
    expect(
      sha(file),
      `${file} changed. A new delivery of the art updates the pins in this spec in the same change; the generator never writes these files.`,
    ).toBe(want);
  }
});

// ----------------------------------------------------------- metadata

const ALLOWED_CHUNKS = new Set(["IHDR", "PLTE", "tRNS", "IDAT", "IEND"]);

/** Chunk types of a PNG, in order; throws on a bad signature or a truncated chunk. */
function chunkTypes(png: Buffer, what: string): string[] {
  expect(png.subarray(0, 8).toString("hex"), `${what}: PNG signature`).toBe("89504e470d0a1a0a");
  const types: string[] = [];
  let at = 8;
  while (at < png.length) {
    expect(at + 12, `${what}: truncated chunk`).toBeLessThanOrEqual(png.length);
    const len = png.readUInt32BE(at);
    types.push(png.subarray(at + 4, at + 8).toString("latin1"));
    at += 12 + len;
    if (types[types.length - 1] === "IEND") break;
  }
  expect(at, `${what}: bytes after IEND`).toBe(png.length);
  return types;
}

function expectCleanPng(png: Buffer, what: string): void {
  const types = chunkTypes(png, what);
  expect(types[0], `${what}: first chunk`).toBe("IHDR");
  expect(types[types.length - 1], `${what}: last chunk`).toBe("IEND");
  for (const t of types) expect(ALLOWED_CHUNKS.has(t), `${what}: chunk ${t} carries text, time or editor data`).toBe(true);
}

test("every toolbar PNG carries only the chunks that draw it", () => {
  const files = readdirSync(join(ROOT, "icons")).filter((f) => f.endsWith(".png"));
  expect(files.length).toBeGreaterThanOrEqual(7 * SIZES.length);
  for (const f of files) expectCleanPng(readFileSync(join(ROOT, "icons", f)), `icons/${f}`);
});

test("every icon master is free of metadata, comments and editor namespaces", () => {
  const files = readdirSync(join(ROOT, "assets", "icons")).filter((f) => f.endsWith(".svg"));
  expect(files.length).toBeGreaterThanOrEqual(8);
  for (const f of files) {
    const svg = readFileSync(join(ROOT, "assets", "icons", f), "utf8");
    const what = `assets/icons/${f}`;
    expect(svg, `${what}: <metadata`).not.toContain("<metadata");
    expect(svg, `${what}: comment`).not.toContain("<!--");
    // Embedded data is checked by the chunk rule below, not by name: base64
    // can contain these letters by chance.
    const text = svg.replace(/data:[^"]*/g, "data:");
    for (const ns of ["inkscape", "sodipodi", "xmp", "adobe"]) {
      expect(text.toLowerCase(), `${what}: ${ns}`).not.toContain(ns);
    }
    const state = f.replace(/\.svg$/, "");
    if ((VERDICT_STATES as readonly string[]).includes(state)) {
      expect(svg, `${what}: embedded data`).not.toContain("data:");
    }
    // A generated master embeds a PNG; it follows the same chunk rule.
    for (const m of svg.matchAll(/data:image\/png;base64,([A-Za-z0-9+/=]+)/g)) {
      expectCleanPng(Buffer.from(m[1]!, "base64"), `${what} (embedded)`);
    }
  }
});

// A closed list of what a master may contain: shapes, gradients and, in the
// generated masters only, one embedded PNG. Nothing that runs or fetches.
const ELEMENTS = new Set(["svg", "defs", "linearGradient", "stop", "rect", "path", "circle", "polygon"]);

test("every icon master holds only drawing elements and no script, style, link or handler", () => {
  const files = readdirSync(join(ROOT, "assets", "icons")).filter((f) => f.endsWith(".svg"));
  expect(files).toHaveLength(8);
  for (const f of files) {
    const what = `assets/icons/${f}`;
    const svg = readFileSync(join(ROOT, "assets", "icons", f), "utf8");
    const generated = !(VERDICT_STATES as readonly string[]).includes(f.replace(/\.svg$/, ""));
    // The tag scan below sees only tags that open with a letter, so the file
    // must start with the root element and carry no processing instruction
    // (an external stylesheet) or declaration (a DOCTYPE with entities).
    expect(svg.startsWith("<svg"), `${what}: does not start with <svg`).toBe(true);
    expect(svg.includes("<?"), `${what}: processing instruction`).toBe(false);
    expect(svg.includes("<!"), `${what}: declaration or comment`).toBe(false);
    for (const bad of ["<style", "<script", "<foreignobject"]) {
      expect(svg.toLowerCase(), `${what}: ${bad}`).not.toContain(bad);
    }
    for (const tag of svg.matchAll(/<\/?([A-Za-z][\w:.-]*)((?:[^>"']|"[^"]*"|'[^']*')*)>/g)) {
      const name = tag[1]!;
      const attrs = tag[2]!;
      const allowed = ELEMENTS.has(name) || (name === "image" && generated);
      expect(allowed, `${what}: element <${name}>`).toBe(true);
      for (const attr of attrs.matchAll(/([^\s=/]+)\s*=\s*("[^"]*"|'[^']*')/g)) {
        const an = attr[1]!;
        const value = attr[2]!.slice(1, -1);
        expect(/^on/i.test(an), `${what}: handler attribute ${an}`).toBe(false);
        if (/^(xlink:)?href$/i.test(an)) {
          expect(name === "image" && value.startsWith("data:image/png;base64,"), `${what}: ${an} on <${name}>`).toBe(true);
        }
      }
    }
    for (const u of svg.replace(/data:[^"]*/g, "data:").matchAll(/url\(\s*([^)]*)\)/g)) {
      expect(u[1]!.trim().replace(/^["']/, "").startsWith("#"), `${what}: url(${u[1]})`).toBe(true);
    }
  }
});

// ------------------------------------------------------- generator guard

test("the generator guard refuses every verdict target and anything outside the two folders", () => {
  const refused: string[] = [];
  for (const s of VERDICT_STATES) {
    refused.push(`assets/icons/${s}.svg`);
    for (const z of SIZES) refused.push(`icons/${s}-${z}.png`);
  }
  refused.push(
    "icons/malicious-16.png",
    "assets/icons/unknown.svg",
    "icons/other-16.png",
    "icons/base-16.svg",
    "assets/icons/base.png",
    "assets/logo.png",
    "store/base-16.png",
    "../icons/base-16.png",
    "icons/../icons/benign-16.png",
    "icons/base-16.png/../benign-16.png",
    "icons/base-17.png",
  );
  for (const p of refused) expect(() => assertGeneratedTarget(join(ROOT, p)), p).toThrow();
  expect(() => assertGeneratedTarget("/tmp/base-16.png")).toThrow();
});

test("the generator guard accepts the generated states", () => {
  expect([...GENERATED_STATES].sort()).toEqual(["base", "neutral", "signedout"]);
  for (const s of GENERATED_STATES) {
    expect(() => assertGeneratedTarget(join(ROOT, "assets", "icons", `${s}.svg`))).not.toThrow();
    for (const z of SIZES) expect(() => assertGeneratedTarget(join(ROOT, "icons", `${s}-${z}.png`))).not.toThrow();
  }
});

test("the generator guard refuses a symlinked target and a folder that resolves elsewhere", () => {
  const tmp = mkdtempSync(join(tmpdir(), "icon-guard-"));
  try {
    const png = join(tmp, "icons");
    const svg = join(tmp, "assets", "icons");
    mkdirSync(png, { recursive: true });
    mkdirSync(svg, { recursive: true });
    const dirs = { png, svg };
    const elsewhere = join(tmp, "elsewhere.png");
    copyFileSync(join(ROOT, "icons", "base-16.png"), elsewhere);

    const plain = join(png, "base-16.png");
    expect(() => assertGeneratedTarget(plain, dirs)).not.toThrow();

    symlinkSync(elsewhere, plain);
    expect(() => assertGeneratedTarget(plain, dirs)).toThrow();

    // A folder that is a link is judged by where it really points.
    const toSvg = join(tmp, "toSvg");
    symlinkSync(svg, toSvg);
    expect(() => assertGeneratedTarget(join(toSvg, "base-16.png"), dirs)).toThrow();
    expect(() => assertGeneratedTarget(join(toSvg, "base.svg"), dirs)).not.toThrow();
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});
