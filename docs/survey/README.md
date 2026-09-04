# The survey

Every surface Guard has, photographed as it stands before the overhaul, from
the real built extension in a real browser against the hermetic mock network.
Captured by `e2e/survey.spec.ts`; re-run it with

```
npx playwright test e2e/survey.spec.ts
```

Beside each picture is `measurements.json`, written by the same run. It is
the point of the exercise. A screenshot shows what a surface looks like; the
numbers say how much of it was **drawn** and how much was **narrated**.

Three columns matter:

- **drawnMarks** - elements whose geometry carries a value: an svg, a canvas,
  a fill whose width is a fraction of a track, a rail whose colour is the
  verdict.
- **narratedFacts** - numbers that arrive as text in a sentence with no mark
  anywhere in the same block. The reader has to parse them.
- **selfAnimating** - elements still changing on their own after load,
  without being poked.

## The census

| surface | content / viewport | drawn | narrated | alive |
|---|---|---|---|---|
| popup / signed out / flagged | 1287 / 600 | 11 | 4 | 0 |
| popup / signed out / ordinary | 1116 / 600 | 11 | 2 | 0 |
| popup / signed out / unknown name | 1153 / 600 | 11 | 2 | 0 |
| popup / signed in | 1097 / 600 | 10 | 2 | 0 |
| dashboard / this browser | 901 / 900 | 2 | 17 | 0 |
| dashboard / fleet | 900 / 900 | 1 | 10 | 0 |
| dashboard / endpoint | 1622 / 900 | 2 | 11 | 0 |
| options | 1545 / 900 | 0 | 0 | 0 |
| first run | 973 / 900 | 0 | 1 | 0 |
| warning interstitial | 900 / 900 | 0 | 0 | 0 |
| check a link | 900 / 900 | 0 | 0 | 0 |

**`selfAnimating` is zero in every column.** Not one surface in the product
changes after it has finished loading. That is issue point 2, measured.

The dashboard columns invert against the popup: the popup draws 11 marks and
narrates 2, the dashboard draws 2 and narrates 17. The overhaul reached the
popup and stopped there.

---

## Surface by surface

### popup / signed out / flagged site
`popup-signedout-flagged.png` - the panel over a site the graph lists as a
credential-phishing suspect. It shows the verdict rail, the on-device
look-alike catch with its way out, the seven-rung chain, the scored factors,
the keyless tier meter and an activity line. **Mostly drawn, and the best
surface in the product.** The chain is real: seven joins, each with its own
value and annotation. But the rail is a decorated list - every rung is the
same dot at the same size on the same straight line, so it reads as a table
with a line down the left rather than as a path through a graph. Nothing
distinguishes a rung that carries the whole finding (`9 flagged neighbours`)
from one that carries an address. Below the fold sit four collapsed
`<details>` rows - "The full graph answer", "Who runs it", "Look-alike
neighborhood", "This session" - which is four facts hidden behind a
disclosure triangle each. **Drawn, with a narrated tail.**

### popup / signed out / ordinary site
`popup-signedout-ordinary.png`, and light in
`popup-signedout-ordinary-light.png`. The case the panel has to justify:
nothing is wrong, and the chain is still worth reading. All seven rungs
joined, `top-1k rank 812`, `14 facilities - 4 exchanges`. The evidence line
`JOINED BY RESOLVES_TO->IPV4->DELEGATED_TO->VENDOR:mediaco` is the single
most product-specific string on the surface and it is rendered as raw
monospace debug output. **Drawn, with the best fact on the page narrated.**

### popup / signed out / a name the graph has never seen
`popup-signedout-unknown.png` - the honest common state, correctly refusing
to read as green. Same shape as above.

### popup / signed in
`popup-signedin.png` - identical to the signed-out panel with the tier meter
swapped for the protect control. Signing in changes one card. **Drawn.**

### dashboard / this browser
`dashboard-this-browser.png` - the graph-scale band with a resolver-pulse
sparkline, the protect control, six stat tiles, four analytic cards and the
activity ledger. **This is the 2.5.** Six tiles are bare integers with no
mark. Three of the four analytic cards - `BY COMPANY`, `BY NETWORK`, `BY
COUNTRY` - are the *same bar-list primitive over the same three rows*, every
bar identical because every count is 1, and each card is two-thirds empty
below its content. The ledger is a table. Nothing on the page shows a
destination joined to any other destination, which is the one thing the
graph is for: three flat groupings of three rows, when the interesting fact
is that they *share* infrastructure. **Narrated, 17 to 2.**

### dashboard / fleet
`dashboard-fleet.png` - **the 40% dead space, exactly as filed.** Six stat
tiles reading `0`, four empty analytic cards, an empty ledger, and the
bottom third of the viewport is bare background. The empty state is not
handled: it draws the full furniture of a populated page and puts zeros in
it. **Narrated, 10 to 1.**

### dashboard / endpoint
`dashboard-endpoint.png` - the deepest surface. Seven bare-integer tiles, an
identity-health ring (a real drawn primitive, and the best thing on the
dashboard), a connection constellation that is empty here, then an enormous
policy form: four preset cards, five protection checkboxes, a country
blocker, a rule builder and a danger zone. Content runs to 1622px. **The
form is correct and completely undrawn** - no preset shows what it would
have blocked, no protection shows how often it would have fired. **Narrated,
11 to 2.**

### options
`options.png` - seven cards of prose and checkboxes. **Zero drawn marks,
zero narrated numbers, 50% dead in the first viewport.** Honest and
well-written; it is a settings page and reads like one.

### first run
`firstrun.png` - the first thing anyone sees. Three cards, all paragraphs.
The "See it work" card fetches one real verdict and renders it as a single
label-value row. **Zero drawn marks.** The moment the product has to prove
it is alive, it hands over three paragraphs of text.

### warning interstitial
`warning.png` - **the most consequential surface in the product and the most
narrated.** This is the page that stands between a person and typing their
password into a phishing site. It is a hexagon, two sentences, and a
four-row label-value table (`WHY / WHY / WHO / AGE`). Zero drawn marks, 62%
dead space. The chain that the popup draws seven rungs of does not appear
here at all, at the one moment it would change a decision. It also renders
two `WHY` rows straight from two different fields without reconciling them,
so they can state different feed counts on the same page.

### check a link
`check-link.png` - right-click a link, vet it before opening. Functionally
correct: on-device look-alike catch, graph verdict, a way to the real site.
Presented as unstyled text in the top-left corner of a full browser tab.
**Zero drawn marks, 67% dead space.** No chain, no evidence, no layout.

---

## What the survey says to build

1. The popup has a chain; **no other surface does**, including the two where
   a decision is actually being made (warning, check-link).
2. The dashboard repeats one bar-list primitive three times over the same
   rows and calls it three charts. The joins between those rows are the
   product and are drawn nowhere.
3. Nothing anywhere is alive.
4. The four surfaces outside the popup and dashboard have **zero** drawn
   marks between them and average 57% dead space.

---

# After

The same census, re-run by the same spec against the rebuilt extension. The
captures in this directory are the AFTER state; the before state is
described above and its numbers are in the table there.

| surface | content / viewport | drawn | narrated | before (drawn / narrated) |
|---|---|---|---|---|
| popup / signed out / flagged | 1336 / 600 | 12 | 3 | 11 / 4 |
| popup / signed out / ordinary | 1187 / 600 | 12 | 1 | 11 / 2 |
| popup / signed out / unknown name | 1201 / 600 | 12 | 1 | 11 / 2 |
| popup / signed in | 1168 / 600 | 11 | 1 | 10 / 2 |
| **dashboard / this browser** | 1081 / 900 | **9** | **4** | 2 / 17 |
| dashboard / fleet (empty) | 900 / 900 | 1 | 5 | 1 / 10 |
| dashboard / endpoint | 1622 / 900 | 3 | 11 | 2 / 11 |
| options | 1545 / 900 | 0 | 0 | 0 / 0 |
| first run | 973 / 900 | 0 | 1 | 0 / 1 |
| **warning interstitial** | 900 / 900 | **11** | 2 | 0 / 0 |
| **check a link** | 618 / 560 | **9** | 0 | 0 / 0 |

## What the numbers do and do not say

**The dashboard inverted.** 2 drawn against 17 narrated became 9 against 4.
The three cards that were one bar-list repeated over the same rows are one
join: destinations, the networks that announce them, the operators holding
those networks, the jurisdictions they sit in, with weighted ribbons between
them. The narrowing left to right is the finding, and it is the only thing
on either dashboard that needs a graph rather than a feed.

**The two decision surfaces went from nothing to the most drawn things in
the product.** The interstitial and the pre-click window had zero marks
between them, at the two moments a person is actually deciding. Both now
carry the seven-rung walk, the age of the name against a year with the
product's own threshold ticked on it, and the flagged neighbourhood as one
mark per flagged host.

**check-link's dead space was partly my measurement, not the product.** The
before table measured it at 1280x900 with 67% dead. It opens as a 420x560
popup window, which is what the after row measures. The zero drawn marks
were real either way.

**`selfAnimating` is still 0, and that column now measures the wrong thing.**
It counts running CSS animations at the instant of capture. The live mark
added in this pass is not a CSS animation and, more to the point, it is
deliberately still unless something arrived: it moves one tick per committed
navigation, and on the fleet view one tick per poll that brought activity
newer than the last, never for the poll itself. It dims when nothing has
arrived for 75 seconds. A number in this column would mean the surface was
moving while nothing was happening, which is the thing the mark exists not
to do.

Two controls in `e2e/drawn.spec.ts` are what make that claim checkable: one
waits four seconds on the browser view with nothing arriving and fails if a
single mark appears, and one sits on the fleet view through two full
fifteen-second poll cycles with an unchanged fixture and fails if the poll
alone ticks it. Both are mutation-proved against a planted timer.

## What is still narrated

- **dashboard / endpoint, 11 narrated.** The identity ring moved to the
  shared arc primitive, but the protection policy below it (four presets,
  five protections, a country blocker, a rule builder) is still entirely
  words and checkboxes. No preset shows what it would have blocked; no
  protection shows how often it would have fired. That is the largest
  remaining piece of narration in the product and it needs data the
  extension does not currently ask for.
- **first run, 0 drawn.** Three cards of prose, and the first thing anyone
  sees.
- **options, 0 drawn.** A settings page, and it reads like one. Left alone
  deliberately.
- **dashboard / fleet reads 1 drawn** only because the survey fixture's
  fleet has no traffic. In that state the analytics are now hidden rather
  than drawn as six tiles of zeros inside four empty card frames, which is
  the honest answer and the reason the narrated count fell from 10 to 5.
