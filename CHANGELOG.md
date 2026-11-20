# Changelog

What changed for people who use Whisper Guard, newest release first.

## 2.7.2

No new permissions, no new endpoints, and no new data collected.

### Improved

- Page scan: flagged rows come first, then the rows that were checked, then the rows that were never assessed. Hovering a row shows its full value.
- First run and Settings say where cookie auto-decline can run: only on a tab where you open Guard, or on every page once Active Shield is on.
- The Fleet view shows when your fleet cannot be read. Before, it kept the last data on screen.
- The page scan sends less: only the hostnames it finds. IP addresses, file hashes and CVE ids found on the page are no longer sent, and the store listings say so.

### Fixed

- Page scan: IP addresses, file hashes and CVE ids read "Not assessed". Before, each showed a green chip although nothing had assessed it.
- First run and Settings: a protection that needs Active Shield says "needs Active Shield" and is shown as off until Active Shield is on. Before, it was shown as on from the first install.
- First run and Settings always show the protections as off after you remove the all-sites permission while either page is open.
- Signing in, pasting a key or signing out updates the tabs that are already open. Before, a tab could keep the earlier answer in its toolbar mark and panel until its next page load.
- Private windows: a check there adds nothing to the destination log behind "This browser", to the answer cache or to the session risk list.
- A link opened with a middle, Ctrl, Cmd or Shift click that Guard holds for a check reopens where the browser would have put it: in the same kind of window, and for a tab, in the window you clicked in.
- Cookie auto-decline runs only on the page it was started for. When the tab moves on, the next page gets it only when it is started there too.
- The warning banner and the password-field caution appear once, at the top of the page. A frame inside the page no longer draws its own.
- The warning page states a block, shows its evidence and offers Continue only when Guard is blocking that site. Otherwise it says no block is in effect. It works only as a tab's own page, not inside a frame.

## 2.7.1

No new permissions, no new endpoints, and no new data collected.

### Improved

- "Open in console" in the panel and "Open the console" in Settings go straight to the Whisper console at its new address, without a redirect.
- The panel says when a check is still running or could not be done.

### Fixed

- The toolbar mark stays on every page. Before, a flagged site could lose its warning mark after one click on an internal link, while the panel still showed the right verdict.
- A slow answer for a site you have already left no longer lands on the page you moved to. It cannot change that page's mark, panel, warning or block.
- Each tab keeps its verdict when the browser puts the extension's background to sleep, so the panel no longer says "Nothing to check on this page" about a site that was checked.
- The dashboard's live refresh, every 30 seconds, stops when the last dashboard closes. Before, it kept running once a dashboard had been opened.
