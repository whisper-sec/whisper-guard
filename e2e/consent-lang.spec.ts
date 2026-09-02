// SPDX-License-Identifier: MIT
// Copyright (c) 2026 viaGraph B.V. (Whisper Security)
//
// e2e: the cookie auto-decline, in the languages consent walls are
// actually written in.
//
// The decline vocabulary used to be English only. The comment beside it
// said the CMP-specific selectors covered other languages, and that was
// not true: a selector covers a PLATFORM, and the generic pass is what
// catches the thousands of home-rolled banners that are not one of the
// named six. So a reader in Berlin or Warsaw got the platform banners
// handled and every other banner ignored, on the continent whose law put
// the banners there in the first place.
//
// Each language gets the same three-button banner a real site ships:
// accept, decline, and a settings button that opens a panel rather than
// declining anything. The assertion is not "something was clicked". It is
// that the DECLINE button was clicked and the other two were not, which is
// the only version of this test that can fail for the right reason. A pass
// that fired on the accept button would be the worst outcome this feature
// has, and a test that only counted clicks would call it a success.
//
// THE CONTROLS, and they matter more than the positive cases:
//
//   1. CONSENT-OR-PAY. A wall whose only refusal is "Reject all and
//      subscribe" must be left alone in every language. That is a paywall,
//      and clicking it is a purchase. It is also the shape of every miss
//      the live probe recorded on theguardian.com, lemonde.fr and zeit.de,
//      so teaching the module those languages must NOT turn those into
//      clicks.
//   2. AN ACCEPT-ONLY WALL. Nothing to decline means nothing to click.
//
// Site hostnames carry no consent-ish word, for the same reason as in
// consent.spec.ts: the wire sweep there greps the whole capture log.

import { test, expect } from "@playwright/test";
import { E2ENetwork } from "./helpers/servers";
import {
  ACCEPT_STYLE_PATTERNS,
  isAcceptStyleLabel,
  isCorroboratingLabel,
  isDeclineLabel,
  vetoesAcceptStyle,
} from "../src/content/consent";
import {
  launchExtension,
  makeShieldDist,
  setSettings,
  visit,
  waitForIcon,
  type Extension,
} from "./helpers/extension";

let net: E2ENetwork;
let ext: Extension;

const RECORDER = `<script>
  window.__clicks = [];
  addEventListener("click", (ev) => {
    const b = ev.target && ev.target.closest ? ev.target.closest("button,[role='button'],input") : null;
    if (b) window.__clicks.push(b.id || b.className || b.tagName);
  }, true);
</script>`;

/**
 * One banner, three buttons, in one language. The button IDs are always the
 * same so the assertion is about WHICH intent was chosen, never about the
 * words, and the words are the only thing that varies between cases.
 */
function banner(lang: string, body: string, accept: string, decline: string, settings: string): string {
  return `<!doctype html>
<html lang="${lang}"><head><title>${lang}</title></head><body>
<h1>${lang}</h1>${RECORDER}
<div role="dialog" aria-label="banner"
     style="position:fixed;bottom:0;left:0;right:0;background:#eee;padding:16px">
  <p>${body}</p>
  <div>
    <button id="btn-settings">${settings}</button>
    <button id="btn-accept">${accept}</button>
    <button id="btn-decline">${decline}</button>
  </div>
</div>
</body></html>`;
}

/**
 * The consent-or-pay wall: the only refusal on offer costs money. Two
 * buttons, and NEITHER is a plain decline.
 */
function payWall(lang: string, body: string, accept: string, rejectAndPay: string): string {
  return `<!doctype html>
<html lang="${lang}"><head><title>${lang}</title></head><body>
<h1>${lang}</h1>${RECORDER}
<div role="dialog" aria-label="banner"
     style="position:fixed;bottom:0;left:0;right:0;background:#eee;padding:16px">
  <p>${body}</p>
  <div>
    <button id="btn-accept">${accept}</button>
    <button id="btn-pay">${rejectAndPay}</button>
  </div>
</div>
</body></html>`;
}

/**
 * The cases. Every string is the wording a real banner in that language
 * uses, accents and all: the module normalises before matching, and a test
 * that quietly spelled them without accents would prove only that the
 * accent-stripping was never needed.
 */
interface LangCase {
  lang: string;
  host: string;
  body: string;
  accept: string;
  decline: string;
  settings: string;
}

const CASES: LangCase[] = [
  {
    lang: "de",
    host: "site-de-fx-guard-e2e.com",
    body: "Wir verwenden Cookies und benötigen Ihre Einwilligung.",
    accept: "Alle akzeptieren",
    decline: "Alle ablehnen",
    settings: "Einstellungen",
  },
  {
    lang: "de-nur",
    host: "site-de2-fx-guard-e2e.com",
    body: "Diese Website nutzt Cookies. Datenschutz ist uns wichtig.",
    accept: "Ich stimme zu",
    decline: "Nur notwendige Cookies",
    settings: "Auswahl verwalten",
  },
  {
    lang: "fr",
    host: "site-fr-fx-guard-e2e.com",
    body: "Nous utilisons des cookies et votre consentement est requis.",
    accept: "Tout accepter",
    decline: "Tout refuser",
    settings: "Paramètres",
  },
  {
    lang: "fr-sans",
    host: "site-fr2-fx-guard-e2e.com",
    body: "Ce site dépose des cookies. Voir notre politique de confidentialité.",
    accept: "J'accepte",
    // The phrase that names the very thing it refuses. It survives only
    // because the module decides the explicit family before the veto.
    decline: "Continuer sans accepter",
    settings: "Personnaliser",
  },
  {
    lang: "es",
    host: "site-es-fx-guard-e2e.com",
    body: "Utilizamos cookies. Consulta nuestra política de privacidad.",
    accept: "Aceptar todo",
    decline: "Rechazar todo",
    settings: "Configurar",
  },
  {
    lang: "it",
    host: "site-it-fx-guard-e2e.com",
    body: "Questo sito utilizza cookie e richiede il tuo consenso.",
    accept: "Accetta tutto",
    decline: "Rifiuta tutto",
    settings: "Personalizza",
  },
  {
    lang: "nl",
    host: "site-nl-fx-guard-e2e.com",
    body: "Wij gebruiken cookies en vragen uw toestemming.",
    accept: "Alles accepteren",
    decline: "Alleen noodzakelijke",
    settings: "Instellingen beheren",
  },
  {
    lang: "pt",
    host: "site-pt-fx-guard-e2e.com",
    body: "Utilizamos cookies. Leia a nossa política de privacidade.",
    accept: "Aceitar tudo",
    decline: "Rejeitar tudo",
    settings: "Definições",
  },
  {
    lang: "pl",
    host: "site-pl-fx-guard-e2e.com",
    // Polish diacritics AND a decline that contains the accept verb:
    // "nie zgadzam się" holds "zgadzam się", which the veto would catch.
    body: "Używamy plików cookie i prosimy o zgodę.",
    accept: "Zgadzam się",
    decline: "Tylko niezbędne",
    settings: "Ustawienia",
  },
  {
    lang: "sv",
    host: "site-sv-fx-guard-e2e.com",
    body: "Vi använder cookies och behöver ditt samtycke.",
    accept: "Acceptera alla",
    decline: "Endast nödvändiga",
    settings: "Inställningar",
  },
  {
    lang: "tr",
    host: "site-tr-fx-guard-e2e.com",
    // Turkish dotless i, which Unicode will not decompose: the module folds
    // it explicitly, and this case is why.
    body: "Çerezleri kullanıyoruz ve onayınıza ihtiyacımız var.",
    accept: "Tümünü kabul et",
    decline: "Yalnızca gerekli",
    settings: "Ayarlar",
  },
  {
    lang: "cs",
    host: "site-cs-fx-guard-e2e.com",
    body: "Používáme soubory cookie a potřebujeme váš souhlas.",
    accept: "Přijmout vše",
    decline: "Odmítnout vše",
    settings: "Nastavení",
  },
];

/** The consent-or-pay walls, which must be left strictly alone. */
const PAY_CASES = [
  {
    lang: "en",
    host: "site-pay-en-fx-guard-e2e.com",
    body: "We use cookies. Choose how to continue.",
    accept: "Yes, I accept",
    pay: "Reject all and subscribe",
  },
  {
    lang: "de",
    host: "site-pay-de-fx-guard-e2e.com",
    body: "Wir verwenden Cookies. Bitte wählen Sie.",
    accept: "Zustimmen und weiter",
    pay: "Ablehnen und Abo abschließen",
  },
  {
    lang: "fr",
    host: "site-pay-fr-fx-guard-e2e.com",
    body: "Nous utilisons des cookies. Faites votre choix.",
    accept: "Accepter et continuer",
    pay: "Refuser et s'abonner",
  },
];

/** The one accept-only wall: nothing to decline is nothing to click. */
const ACCEPT_ONLY_HOST = "site-only-fx-guard-e2e.com";

test.beforeAll(async () => {
  net = new E2ENetwork();
  await net.start();
  for (const c of CASES) {
    net.setVerdict(c.host, { band: "NONE", coverage: "known-clean", label: "clean" });
    net.setPage(c.host, banner(c.lang, c.body, c.accept, c.decline, c.settings));
  }
  for (const c of PAY_CASES) {
    net.setVerdict(c.host, { band: "NONE", coverage: "known-clean", label: "clean" });
    net.setPage(c.host, payWall(c.lang, c.body, c.accept, c.pay));
  }
  net.setVerdict(ACCEPT_ONLY_HOST, { band: "NONE", coverage: "known-clean", label: "clean" });
  net.setPage(
    ACCEPT_ONLY_HOST,
    `<!doctype html><html lang="de"><head><title>only</title></head><body>
<h1>only</h1>${RECORDER}
<div role="dialog" aria-label="banner" style="position:fixed;bottom:0;left:0;right:0;background:#eee;padding:16px">
  <p>Wir verwenden Cookies und benötigen Ihre Einwilligung.</p>
  <button id="btn-accept">Alle akzeptieren</button>
</div></body></html>`,
  );

  ext = await launchExtension({ proxyPort: net.proxyPort, dist: makeShieldDist() });
  await setSettings(ext, { shield: true, cookieDecline: true, amberBanner: false, fieldGuard: false });
});

test.afterAll(async () => {
  await ext?.close();
  await net?.stop();
});

async function clicks(page: import("@playwright/test").Page): Promise<string[]> {
  return page.evaluate(() => (window as unknown as { __clicks: string[] }).__clicks ?? []);
}

for (const c of CASES) {
  test(`${c.lang}: "${c.decline}" is clicked, "${c.accept}" and "${c.settings}" are not`, async () => {
    const { page, tabId } = await visit(ext, `https://${c.host}/`);
    await waitForIcon(ext, tabId, ["benign", "unknown"]);
    await page.waitForTimeout(1800);
    const clicked = await clicks(page);
    expect(clicked, `expected the decline button in ${c.lang}, got ${JSON.stringify(clicked)}`).toEqual([
      "btn-decline",
    ]);
    await page.close();
  });
}

for (const c of PAY_CASES) {
  test(`${c.lang} consent-or-pay: "${c.pay}" costs money, so nothing is clicked`, async () => {
    const { page, tabId } = await visit(ext, `https://${c.host}/`);
    await waitForIcon(ext, tabId, ["benign", "unknown"]);
    await page.waitForTimeout(1800);
    expect(await clicks(page), "a paywall button was pressed on the reader's behalf").toEqual([]);
    await page.close();
  });
}

test("an accept-only wall in another language is still never accepted", async () => {
  const { page, tabId } = await visit(ext, `https://${ACCEPT_ONLY_HOST}/`);
  await waitForIcon(ext, tabId, ["benign", "unknown"]);
  await page.waitForTimeout(1800);
  expect(await clicks(page), "the module accepted on the reader's behalf").toEqual([]);
  await page.close();
});

// ------------------------------------------------------------- the invariant
//
// The generic pass corroborates a decline with an accept-style SIBLING, and
// that is only safe while no phrase can be both. The module states it as a
// comment beside the loop; a comment is a wish, so this is the check.
//
// It is written as two real corpora of button labels rather than as
// machinery that generates samples from the regexes, because a test that
// derives its inputs from the thing under test can agree with a bug. These
// are the words the buttons actually say.

/** What an ACCEPT button says. Every one must be vetoed. */
const ACCEPT_LABELS = [
  "Accept all", "I agree", "Allow all cookies", "Enable", "Consent", "Got it", "OK", "Yes",
  "Alle akzeptieren", "Zustimmen", "Ich stimme zu", "Ich stimme allem zu", "Einverstanden",
  "Erlauben", "Alle zulassen",
  // Measured on the live internet 2026-09-02, on the three German
  // publishers the probe visits: these are the words their walls use.
  "Einwilligen und weiter", "Zustimmen und weiter",
  "Tout accepter", "J'accepte", "Autoriser",
  "Aceptar todo", "Acepto", "Permitir",
  "Accetta tutto", "Accetto", "Consenti",
  "Alles accepteren", "Akkoord", "Toestaan",
  "Aceitar tudo", "Aceito",
  "Akceptuję", "Zgadzam się", "Zezwól",
  "Acceptera alla", "Godkänn alla", "Godta alle", "Tillat alle",
  "Hyväksy kaikki", "Salli",
  "Přijmout vše", "Souhlasím", "Povolit",
  "Tümünü kabul et", "İzin ver",
  "Permite toate",
];

/** What a DECLINE button says. None may look like an accept. */
const DECLINE_LABELS = [
  "Reject all", "Decline", "Refuse", "Deny all", "Necessary only", "Continue without accepting",
  "Alle ablehnen", "Nur notwendige Cookies", "Nur erforderliche", "Nicht zustimmen",
  "Tout refuser", "Refuser", "Continuer sans accepter", "Uniquement les nécessaires",
  "Rechazar todo", "Denegar", "Solo las necesarias", "Continuar sin aceptar",
  "Rifiuta tutto", "Solo i necessari", "Continua senza accettare",
  "Alles weigeren", "Alleen noodzakelijke", "Doorgaan zonder accepteren",
  "Rejeitar tudo", "Recusar", "Apenas os essenciais",
  "Odrzuć wszystko", "Tylko niezbędne", "Nie zgadzam się",
  "Avvisa alla", "Endast nödvändiga", "Kun nødvendige", "Avvis alle",
  "Hylkää kaikki", "Vain välttämättömät",
  "Odmítnout vše", "Pouze nezbytné",
  "Tümünü reddet", "Yalnızca gerekli",
  "Respinge tot", "Doar necesare",
];

test("no phrase can be both a decline and the sibling that corroborates it", () => {
  // CONTROL FIRST. The checker has to be able to answer both ways, or a
  // function that returns true for everything satisfies the loop below and
  // proves nothing.
  expect(vetoesAcceptStyle("Accept all"), "the veto misses a plain accept").toBe(true);
  expect(vetoesAcceptStyle("Reject all"), "the veto fires on a plain decline").toBe(false);
  expect(isDeclineLabel("Reject all"), "the decline test misses a plain decline").toBe(true);
  expect(isDeclineLabel("Accept all"), "the decline test fires on a plain accept").toBe(false);
  expect(isCorroboratingLabel("Accept all"), "a plain accept does not corroborate").toBe(true);
  expect(isCorroboratingLabel("Reject all"), "a plain decline corroborates").toBe(false);
  expect(ACCEPT_STYLE_PATTERNS.length, "the accept-style list is empty").toBeGreaterThan(20);

  // 1. Every accept label corroborates AND is vetoed, so the loop can never
  //    mistake the corroboration for the click.
  for (const label of ACCEPT_LABELS) {
    expect(isAcceptStyleLabel(label), `"${label}" does not read as an accept`).toBe(true);
    expect(isCorroboratingLabel(label), `"${label}" does not corroborate a banner`).toBe(true);
    expect(
      vetoesAcceptStyle(label),
      `"${label}" corroborates a banner but is NOT vetoed: it could be clicked as a decline`,
    ).toBe(true);
    expect(isDeclineLabel(label), `"${label}" would be CLICKED as a decline`).toBe(false);
  }

  // 2. Every decline label is recognised, and none of them looks like an
  //    accept, which would make it the corroboration instead of the click.
  for (const label of DECLINE_LABELS) {
    expect(isDeclineLabel(label), `"${label}" is not recognised as a decline`).toBe(true);
    // The one that matters: a refusal can never stand in for the accept a
    // real banner offers. "Nicht zustimmen" and "Nie zgadzam sie" DO read
    // as accept-style, because they name what they refuse; what they must
    // never do is corroborate.
    expect(
      isCorroboratingLabel(label),
      `"${label}" is a refusal but would corroborate a banner that has no accept at all`,
    ).toBe(false);
  }
});
