// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// One memo in front of the chain walk, and one reason for it that is worth
// stating plainly.
//
// The graph's public tier allows an anonymous caller a hundred queries an
// hour from one address (measured, not assumed: CALL whisper.quota()). A
// chain costs seven of them (four in the first round, up to three in the second). Building it on every navigation would empty a
// reader's budget inside twenty minutes of ordinary browsing and leave
// nothing for the assess call that is the thing actually protecting them.
//
// So the chain is built when a reader OPENS THE PANEL, which is a
// deliberate ask, and the result is held for CHAIN_TTL_MS so that
// reopening the panel, or opening it on a second tab of the same site, is
// free. Two panels asking at once share one walk rather than racing.

import { CHAIN_TTL_MS } from "../shared/config";
import type { ChainRungKind, RungDetail, SiteChain } from "../shared/types";
import { buildChain, rungDetail } from "./chain";

const memo = new Map<string, { chain: SiteChain; at: number }>();
const inFlight = new Map<string, Promise<SiteChain>>();

/** Keep the memo small: a browser session touches many names and a chain
 *  is a fat object. Oldest-first eviction is enough here. */
const MAX_ENTRIES = 64;

function evict(): void {
  while (memo.size > MAX_ENTRIES) {
    const oldest = memo.keys().next();
    if (oldest.done) return;
    memo.delete(oldest.value);
  }
}

export async function chainFor(host: string): Promise<SiteChain> {
  const h = host.toLowerCase();
  const hit = memo.get(h);
  if (hit && Date.now() - hit.at < CHAIN_TTL_MS) return hit.chain;

  const running = inFlight.get(h);
  if (running) return running;

  const p = buildChain(h)
    .then((chain) => {
      memo.set(h, { chain, at: Date.now() });
      evict();
      return chain;
    })
    .finally(() => {
      inFlight.delete(h);
    });
  inFlight.set(h, p);
  return p;
}

/** Drop the memo (used by the tests, and on sign-in, where the tier
 *  changes and a keyless-shaped chain should not be reused as a keyed one). */
export function resetChainCache(): void {
  memo.clear();
}

/**
 * What is behind one rung. Goes through the memo so expanding a rung reuses
 * the walk the panel already paid for rather than starting a second one.
 */
export async function rungDetailFor(host: string, kind: ChainRungKind): Promise<RungDetail> {
  await chainFor(host);
  return rungDetail(host.toLowerCase(), kind);
}
