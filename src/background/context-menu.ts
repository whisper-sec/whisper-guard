// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// "Check this link with Whisper": the pre-navigation safe path. Right-click
// a link (or a selected URL-looking string) and vet the DESTINATION before
// you ever navigate: on-device detector always, the keyed live band when
// signed in. Only the hostname is extracted; the result opens in a small
// extension window. Zero new permissions, zero new egress.

import { ext } from "../shared/api";
import { extractHostname } from "../shared/hostname";

export const MENU_ID = "whisper-guard-check-link";

export function installContextMenu(): void {
  ext.contextMenus.removeAll(() => {
    ext.contextMenus.create({
      id: MENU_ID,
      title: "Check this link with Whisper",
      contexts: ["link", "selection"],
    });
  });
}

function hostFromSelection(text: string): string | null {
  const t = text.trim();
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(t) ? t : `https://${t}`;
  return extractHostname(candidate);
}

export function onMenuClicked(info: chrome.contextMenus.OnClickData): void {
  if (info.menuItemId !== MENU_ID) return;
  const host = info.linkUrl
    ? extractHostname(info.linkUrl)
    : info.selectionText
      ? hostFromSelection(info.selectionText)
      : null;
  const url = host
    ? chrome.runtime.getURL(`check-link.html?host=${encodeURIComponent(host)}`)
    : chrome.runtime.getURL("check-link.html");
  ext.windows
    .create({ url, type: "popup", width: 420, height: 560 })
    .catch(() => ext.tabs.create({ url }).catch(() => undefined));
}
