# Chrome Web Store: paste-ready fields (Whisper Guard 2.5.0)

Open this file in your editor and copy each block into the matching CWS field.

===============================================================================
STORE LISTING TAB
===============================================================================

--- Name ---
Whisper Guard

--- Summary (132 max) ---
The Whisper security graph in your browser: a live safety verdict on every site, plus a dashboard of where your devices go.

--- Category ---
Privacy & Security

--- Language ---
English

--- Description ---
Whisper Guard brings the Whisper security graph into your browser: a live verdict on every site, and a dashboard of where your devices actually go.

The moment you install it, the toolbar mark answers "is THIS site safe?" on every page you visit, with no account needed: green for no known threat, amber for suspicious, a red stop plate reserved for evidenced-malicious sites, and an honest UNKNOWN for the internet's long tail. Click the mark for who runs the site and where it lives, how old the domain is, the threat feeds it is listed in, and a look-alike neighborhood confirmed against the graph.

An on-device detector also checks every site against 800+ heavily phished brands: homoglyph tricks (paypa1.com, Cyrillic lookalikes), swapped endings (paypal.tk), hyphen squats (face-book.com), fake subdomains (paypal.com.evil.example) and combo squats (paypal-secure-login.com). One tap takes you to the real site. Right-click any link to vet it before you open it.

The "This browser" dashboard shows where this browser goes, enriched through the graph: which companies answer, in which countries, on which networks, and what is flagged. No account needed.

Sign in free (one tap, no API key to handle) to unlock your whole fleet: every device and agent on your Whisper account in one view, per-endpoint drill-downs with an explainable identity-health score, and one control that gives this browser its own routable Whisper IPv6 identity and routes its traffic out through it, so it becomes a first-class endpoint anyone can verify by public RDAP. The same one control is in the toolbar panel and on the dashboard.

Every surface follows your system's light or dark setting, and all of them use the same design system as the Whisper console, so moving between the two is moving inside one product.

Privacy is the product:
- Only a site's NAME is ever checked. Never the page, the path, what you type, or your history. Your on-device destination list never leaves the device.
- The bare hostname goes to exactly one endpoint to answer the safety check and is not retained to build a browsing profile. One switch turns the live check off, after which only the on-device detector runs and nothing leaves at all.
- No telemetry, no analytics, no sync. Open source (MIT).

Whisper also holds a click before it lands: following a link to another site, or submitting a form off-origin, pauses just long enough to check that destination's name, and an evidenced-malicious destination gets an inline panel with the verdict, the receipts, and both exits. The destination is never contacted and nothing you typed leaves the page. If Whisper is slow or unreachable the click simply proceeds. A calm line in the panel counts what was handled for you today, by category only, never which sites, and there is no toast or notification anywhere.

Optional Active Shield adds a full-page stop before known credential-phishing pages, a caution when a password field gains focus on a flagged site, and an amber banner on look-alikes. It asks for the browser's own on-page permission only when you turn it on, and declining it keeps everything else working.

If Whisper is unreachable the extension fails open: browsing is never blocked and the on-device protection keeps running.

--- Homepage URL ---
https://whisper.online/docs/whisper-guard

--- Support URL ---
https://github.com/whisper-sec/whisper-guard/issues


===============================================================================
PRIVACY TAB
===============================================================================

--- Single purpose description ---
Whisper Guard warns the user before phishing and look-alike websites and shows where their devices connect, using an on-device brand-impersonation detector plus per-site safety verdicts and destination enrichment from the Whisper security graph.

--- activeTab justification ---
Acts on the current tab when the user clicks the toolbar icon, to show that page's safety verdict and details. No access to other tabs.

--- webNavigation justification ---
Reads the hostname of the page being visited so it can be checked for safety and shown in the "This browser" dashboard. The URL's path, query and content are discarded at parse time; only the hostname is used.

--- storage justification ---
Stores local settings, the local verdict cache, the on-device destination log, and the sign-in credential. Everything is local; nothing is synced.

--- scripting justification ---
Injects Whisper's own on-page code, never remote code, for three things. (1) Pre-click interception: on an eligible page it installs capture-phase click and form-submit handlers that hold an outbound action long enough to check the destination HOSTNAME, and draw the inline warning panel when that destination is evidenced-malicious. (2) The optional cookie-consent decline: it inspects the page locally for a consent banner and clicks that banner's own reject control, at most once per document; it runs in a page's sub-frames as well as its top document, because that is where most large publishers render the wall, under the same rules everywhere, so a page carrying both a top-level banner and a framed consent wall may see one click in each; nothing about the page is sent anywhere. (3) After the user opts into Active Shield, the amber banner and the password-field caution on flagged sites. It also reads, on the user's click, only the <a href> hostnames of the current page for the optional pre-click link sweep. Page text, paths, queries and form values are never read and never transmitted; the panels render in closed shadow roots.

--- contextMenus justification ---
Adds the "Check this link with Whisper" right-click action so the user can vet a link's destination before opening it.

--- declarativeNetRequest justification ---
Blocks navigation to evidenced-malicious sites before the request leaves the browser: the full-page stop for known credential-phishing sites under Active Shield, and a session-scoped rule for a single host that Whisper just held a click to, so the same destination cannot slip through in another tab. Rules are applied declaratively and request contents are not read. Every such session block is listed in the popup with a one-click clear, so it is never a dead end.

--- alarms justification ---
Schedules the daily signed brand-corpus update check and, when the user is signed in, the periodic fleet-activity poll for the dashboard.

--- proxy justification ---
Powers the optional "Protect this browser" feature, which routes this browser through Whisper egress so it becomes an endpoint on the user's account. Chrome does not allow "proxy" to be optional, so it is declared required, but the proxy is only set when the user turns routing on and is never touched otherwise. Routing is off by default.

--- webRequest justification ---
Supplies the egress credential for the optional "Protect this browser" routing. Used at runtime only on the user's click to enable routing, never for general request monitoring.

--- webRequestAuthProvider justification ---
Provides the proxy authorization for the optional Whisper egress route, so the routed browser authenticates to the egress. Used only when the user enables routing.

--- privacy justification ---
Hardens WebRTC to proxied-only while the optional Whisper egress route is on, so the browser's real IP cannot leak around the proxy. Applied only when routing is enabled.

--- Host permission justification ---
graph.whisper.online: the graph, carrying both arms. The safety check + destination enrichment (hostname only) is the only thing a browsing hostname ever reaches. The signed-in control plane (the user's own fleet roster, enrollment and egress) always carries the user's key and never a browsing hostname, and is not called at all when signed out. console.whisper.security: the sign-in device flow, two unauthenticated endpoints, and nothing else (no browsing data); it is a sign-in origin, never a destination. get.whisper.online: signed brand-corpus updates (no browsing data). rdap.whisper.online: public identity verification of the user's own endpoints (IP literals only). nic.whisper.online: the public network statistics document, a plain GET of one public JSON file with no query string, no header, no body and no cookie, so nothing about the user can ride on it. It is how the extension shows the live size of the graph and the resolvers' current latency instead of quoting a figure baked into the build, which would be stale the day after release. No other host is ever contacted. The extension also OPENS console.whisper.online in a tab when the user asks for the console; it is never fetched from, so it needs no host permission.

--- Remote code ---
No, I am not using Remote code.

--- Data usage: what user data do you collect ---
Tick ONLY: Web history
(Leave everything else unchecked: no PII, health, financial, authentication,
personal communications, location, user activity, or website content. The
on-device destination log never leaves the device; page content is never read.
Web history is ticked because the current site's hostname is transmitted to the
server for the live safety verdict, and Google counts any off-device
transmission as "collection".

"Website content" stays unticked even though the scripting justification above
says Guard reads the <a href> hostnames of the page. A reviewer diffing this
listing against itself lands exactly there, so to pre-empt it: Google's
"Website content" category enumerates hyperlinks, and what LEAVES the device is
never a hyperlink. The link sweep runs on the user's click, takes each
link's hostname on the device and reduces it to the registrable domain (the
bare hostname when no domain can be derived), and sends only those. That is the
same shape as the current site's hostname already covered by Web history. No
href, no path, no query, no anchor text and no page text is transmitted.)

--- Certify all three ---
[x] I do not sell or transfer user data to third parties, outside of the approved use cases
[x] I do not use or transfer user data for purposes that are unrelated to my item's single purpose
[x] I do not use or transfer user data to determine creditworthiness or for lending purposes

--- Privacy policy URL ---
https://whisper.online/privacy
