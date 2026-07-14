// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Daily signed corpus refresh over chrome.alarms. Only the corpus host is
// ever contacted and no browsing data rides along: it is a plain GET of a
// public JSON document. The payload must carry a valid Ed25519 signature
// from the corpus signing key; while the key is not yet published (empty
// config) remote updates are skipped entirely and the bundled corpus
// stands. On any failure the last good corpus is retained.

import { CORPUS_SIGNING_KEY_B64U, CORPUS_UPDATE_MINUTES, CORPUS_URL } from "../shared/config";
import type { Corpus } from "../shared/types";
import { getSettings } from "./settings";
import { invalidateIndex } from "../detector/corpus";

export const CORPUS_ALARM = "whisper-guard-corpus";

export function scheduleCorpusUpdates(): void {
  chrome.alarms.create(CORPUS_ALARM, { periodInMinutes: CORPUS_UPDATE_MINUTES, delayInMinutes: 5 });
}

function b64uToBytes(s: string): Uint8Array {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function verifySignature(payload: string, signatureB64u: string): Promise<boolean> {
  if (CORPUS_SIGNING_KEY_B64U === "") return false;
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: "OKP", crv: "Ed25519", x: CORPUS_SIGNING_KEY_B64U },
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const sigSource = b64uToBytes(signatureB64u);
    const sig = new ArrayBuffer(sigSource.byteLength);
    new Uint8Array(sig).set(sigSource);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig, new TextEncoder().encode(payload));
  } catch {
    return false;
  }
}

export async function updateCorpusNow(): Promise<{ updated: boolean; reason: string }> {
  const settings = await getSettings();
  if (!settings.corpusAutoUpdate) return { updated: false, reason: "auto-update is off" };
  if (CORPUS_SIGNING_KEY_B64U === "") {
    return { updated: false, reason: "no corpus signing key published yet; using the bundled corpus" };
  }
  let res: Response;
  try {
    res = await fetch(CORPUS_URL, { headers: { accept: "application/json" } });
  } catch {
    return { updated: false, reason: "corpus host unreachable; keeping the last good corpus" };
  }
  if (!res.ok) return { updated: false, reason: `corpus fetch returned HTTP ${res.status}` };

  let envelope: { corpus?: unknown; signature?: unknown };
  let raw: string;
  try {
    raw = await res.text();
    envelope = JSON.parse(raw) as { corpus?: unknown; signature?: unknown };
  } catch {
    return { updated: false, reason: "corpus payload was not JSON" };
  }
  const corpus = envelope.corpus as Corpus | undefined;
  const signature = envelope.signature;
  if (!corpus || typeof corpus.version !== "number" || !Array.isArray(corpus.brands) || typeof signature !== "string") {
    return { updated: false, reason: "corpus payload incomplete" };
  }
  if (!(await verifySignature(JSON.stringify(corpus), signature))) {
    return { updated: false, reason: "corpus signature invalid; keeping the last good corpus" };
  }
  try {
    const current = (await chrome.storage.local.get("corpus"))["corpus"] as Corpus | undefined;
    if (current && current.version >= corpus.version) {
      return { updated: false, reason: "already up to date" };
    }
    await chrome.storage.local.set({ corpus, corpusUpdated: new Date().toISOString() });
    invalidateIndex();
    return { updated: true, reason: `corpus v${corpus.version} installed` };
  } catch {
    return { updated: false, reason: "could not store the corpus; keeping the last good one" };
  }
}
