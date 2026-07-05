# ZKB test platform — what it lets us test

The ZKB test platform (`testplattform.zkb.ch`) exposes a **Defaultwerte** (default settings)
page that configures what its simulation returns: which pain.001/camt versions it validates and
generates, which booking types appear in the camt statements, and which reporting messages
(camt.052/053/054) are produced. This document records the settings we run against so the mapping
to our implementation is explicit, and tracks which of them we have actually verified end to end.

It reflects the platform configuration captured on **2026-07-04**. The page has a **Speichern**
(save) / **Zurücksetzen** (reset) control, so these values can change — re-check the platform if a
test behaves unexpectedly.

## Current settings

### Channel (Kanal)

The channel governs how the **pain.002 status message** is delivered back.

| Option | Selected |
| --- | --- |
| e-Banking | ⬜ |
| Datalink EBICS | ✅ (set 2026-07-04) |

> Switched to **Datalink EBICS** so the pain.002 status message is returned over EBICS after a
> pain.001 upload (M3). Does not affect the camt.053 download.

### pain.001 / camt.05x versions

| Setting | Value |
| --- | --- |
| Validation against (Validierung gegen) | **pain.001.001.09.ch.03 — SPS 2025** (alt: pain.001.001.03.ch.02 — SPS 2021) |
| Simulation to (Simulation nach) | **camt.05x.001.08 — SPS 2025** (alt: camt.05x.001.04 — SPS 2021) |

The simulation emits **camt.053.001.08**, which matches our download BTF
(`EOP / CH / camt.053 / 08 / ZIP`, `models.CAMT_053`). Uploads (M3) target
**pain.001.001.09.ch.03**.

### pain.002 (Überweisung)

| Setting | Value |
| --- | --- |
| Technical pain.002 message (technische pain.002-Meldung) | ❌ off |
| pain.002 validation message (pain.002-Validierungsmeldung) | ✅ on |
| Simulate a reject for every third transaction (Für jede dritte Transaktion einen Reject erzeugen) | ✅ (set 2026-07-04) |

So an upload returns a **pain.002 validation message**, and **every third transaction is rejected**
in the simulation — which lets M3 exercise both the accepted and the rejected pain.002 paths.

### Simulated booking details in the camt messages

**Standard bookings (Standard-Buchungen) — ✅ enabled:**

- Bank payment inbound domestic: CHF
- Bank payment inbound foreign: USD
- Bank payment inbound foreign: EUR (SEPA)
- Bank payment inbound foreign: CHF
- Account-closing bookings (Kontoabschlussbuchungen)
- ATM withdrawal (Bancomatbezug)
- Payment return (Zahlungsretoure)

**Other (Sonstige) — ⬜ disabled:** FX buy/sell, securities buy/sell, securities coupon credit,
credit-card credit.

These are the entries our camt.053 parser will encounter in the downloaded statement.

### Reporting (Avisierungen)

| Message | Enabled | Notes |
| --- | --- | --- |
| Intraday statement (camt.052) | ⬜ | with none of the collective-detail options |
| **End-of-day statement (camt.053)** | ✅ | **our download target**; collective-booking detail options all off |
| Booking advice credits (camt.054) | ⬜ | |
| Booking advice debits (camt.054) | ⬜ | |
| QR collective resolutions, credits (camt.054 QRR) | ✅ | delivered as a separate camt.054 |
| SCOR collective resolutions, credits (camt.054 SCOR) | ✅ | delivered as a separate camt.054 |
| LSV collective resolutions, credits (camt.054 LSV) | ✅ | delivered as a separate camt.054 |
| Collective resolutions, payment orders (camt.054) | ⬜ | |

### QR-Rechnung (QR-bill collection)

- Additional collection on the first six digits of the QR reference (QRR): ⬜ off
- Additional collection on positions 5–10 of the SCOR reference: ⬜ off

## Mapping to our implementation, and verification status

| Capability | Platform setting | Our code | Status |
| --- | --- | --- | --- |
| Handshake (INI/HIA/HPB) | mit Schlüsseln profile | `client.ini/hia/hpb` | ✅ verified end to end |
| End-of-day statement download | camt.053 enabled, camt.053.001.08 | `client.download(CAMT_053)` / `download_statements()` | ⏳ built + XSD-valid; **live download not yet run** |
| camt.053 parsing (balances, entries) | Standard-Buchungen | `formats/camt053.py` | ⏳ unit-tested; not yet run on real simulation output |
| Intraday statement (camt.052) | disabled | — | ⬜ not implemented (not enabled on the platform) |
| Booking advices (camt.054 incl. QRR/SCOR/LSV) | three camt.054 enabled | — | ⬜ not implemented (out of MVP scope) |
| pain.001 upload | pain.001.001.09.ch.03 | — | ⬜ M3 |
| pain.002 status back | validation message on; channel = e-Banking | — | ⬜ M3 (needs channel → Datalink EBICS) |
| Reject simulation (negative path) | off | — | ⬜ M3 (enable to test rejects) |

**Legend:** ✅ verified · ⏳ implemented, live-verification pending · ⬜ not started / out of scope.

## How the simulation is driven (validated 2026-07-05)

The test platform separates two facilities, which matters when interpreting results:

- **The web upload** (*Zahlungsdatei/Simulationsdaten hochladen*) is what drives the simulation.
  Uploading a `pain.001` there validates it against `pain.001.001.09.ch.03` and, if accepted,
  books it and produces a result ZIP (downloadable via the page's **Download** button) containing:
  a `Protokoll.txt` validation log, two `pain.002.001.10` status reports (technical `ACTC`, then
  business `ACCP`/`RJCT`), and — once accepted — a `camt.053` statement.
- **The EBICS channel** is validated independently. Our `BTU` upload is **accepted** by the EBICS
  server (correct AuthSignature, A006 signature, and encryption), but on this platform it does
  **not** feed the web simulation, and the web simulation's `camt.053`/`pain.002` are **not**
  exposed back over the EBICS download queue (EOP stays `090005`).

Practical consequences for testing:

- The test account (a CHF account, IBAN kept out of the repo) is held at ZKB, so the **debtor
  agent BIC must be `ZKBKCHZZ`**; a foreign agent is rejected with `AGNT` /
  "Multibanking ist nicht zulässig".
- Our `camt.053` parser is validated against a **real** ZKB simulation statement (balances
  reconcile: opening + credits − debits = closing; the initiated payment appears as a debit).
- `pain.002` is confirmed to be `pain.002.001.10` — matching the `PAIN_002` BTF version.

## What HAA/HTD and BTF probing established (2026-07-05)

Live probes of the EBICS admin order types settled the two open EBICS-channel questions with
the bank's own registry as the oracle:

- **`HTD`** (subscriber permissions) confirms every BTF we send matches the registration exactly
  — including `EOP/CH/camt.053/08/ZIP` and `MCT/CH/pain.001/09` (`NumSigRequired=0`). Crucially,
  `PSR/CH/pain.002/10` is registered **without a Container**: requesting it with `Container=ZIP`
  is what produced `091005` (the human-readable catalogue's "ZIP" column describes the delivered
  file, not the BTF registration). `PAIN_002` was fixed accordingly and now gets `090005`.
- **`HAA`** (order types with data available) returns an **empty list** — the bank itself
  confirms nothing is ever queued on the EBICS side, regardless of upload route. EBICS `BTU`
  uploads are accepted (all variants probed: with/without `SignatureFlag`, with/without
  `fileName`, valid content, same-day execution date, well past the manual's 10–30 s processing
  window) but never appear in the web table nor produce EBICS-retrievable results, and web-upload
  results are never bridged to the EBICS queues (even when left unconsumed in the GUI).
- These probes also completed **full live BTD download transactions** (initialise → decrypt →
  receipt) and revealed that the bank acknowledges a positive receipt with
  **`011000 EBICS_DOWNLOAD_POSTPROCESS_DONE`** — a success code the client now accepts.

The manual (`ZKB_Testplattform_BenHB.pdf`, §3.7.4–3.7.5) documents EBICS submission/retrieval as
supported, so the dead EBICS→simulation bridge contradicts the platform's own documentation.

## Open items surfaced by these settings

1. **Ask ZKB support** (`support.epayment@zkb.ch`) why EBICS-submitted pain.001 files are
   accepted but never processed by the simulation, and why simulation results never appear in
   the EBICS download queues (`HAA` stays empty) — the Benutzerhandbuch documents both flows.
2. **camt.054 booking advices** (QRR/SCOR/LSV are enabled here) are a plausible near-term read
   feature after the MVP, but remain out of the current scope.
