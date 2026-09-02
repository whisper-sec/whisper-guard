// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// Runs INSIDE the page. This file exists so the privacy invariant is a fact of
// the architecture rather than a promise in a comment: the page's text is read
// here, reduced to indicators here, and dies here. Only Ioc[] crosses back to
// the extension, exactly as the link scan returns hostnames and nothing else.
//
// It stashes its result on a window property rather than relying on a script's
// completion value, which is not dependable across bundler output formats. The
// background reads that property with a second, trivial injection.
import { extractIocs } from "../shared/ioc";

const MAX_TEXT = 400_000;
const CAP = 2000;

const body = document.body;
const text = body ? body.innerText || body.textContent || "" : "";
// The slice happens in the page too: an oversized document is never carried
// across the boundary just to be trimmed on the other side.
const bounded = text.length > MAX_TEXT ? text.slice(0, MAX_TEXT) : text;

(window as unknown as { __whisperIocs?: unknown }).__whisperIocs = extractIocs(bounded, CAP);
