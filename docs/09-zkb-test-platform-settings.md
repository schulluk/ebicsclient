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
| Supported versions (HEV) | — | `client.supported_versions()` | ✅ live (H002 to H005, as in HPD) |
| Handshake (INI/HIA/HPB) | mit Schlüsseln profile | `client.ini/hia/hpb` | ✅ verified end to end |
| End-of-day statement download | camt.053 enabled, camt.053.001.08 | `client.download(CAMT_053)` / `download_statements()` | ✅ live (balances reconcile) |
| camt.053 parsing (balances, entries) | Standard-Buchungen | `formats/camt053.py` | ✅ live |
| Intraday statement (camt.052) | produced since at least 2026-10-26 (the table above predates it) | `download_intraday_statements()` | ✅ live |
| Booking advices (camt.054 incl. QRR/SCOR/LSV) | QRR/SCOR/LSV collective resolutions enabled | `download_booking_advices(btf)` | ✅ live; see the simulation section below |
| Single transactions of a booking (references, payer, remittance text) | QRR/SCOR/LSV collective resolutions enabled | `Entry.transactions` | ✅ live (version 04 from simulated credits, version 08 from a pain.001 batch debit) |
| pain.001 upload | pain.001.001.09.ch.03 | `client.upload(PAIN_001, …)` | ✅ live (processed since the A006 fix) |
| pain.002 status back | validation message on; channel = Datalink EBICS | `download_payment_status_reports()` | ✅ live |
| Reject simulation (negative path) | every third transaction | — | ✅ live (`PART`, two rejected) |
| Simulated incoming credits (QRR/SCOR/NON/LSV) | CSV upload `OTH/BIL/CH004TPS/csv` | `tools/zkb-incoming-payments.py` | ✅ live (test tool, not library API) |

**Legend:** ✅ verified · ⏳ implemented, live-verification pending · ⬜ not started / out of scope.

## Simulated incoming credits over EBICS (validated 2026-10-26)

The platform simulates incoming QR-bill credits with a QR reference (`QRR`) or an ISO 11649
creditor reference (`SCOR`), credits without a reference (`NON`), and LSV+ collections (`LSV`)
from a CSV file (manual section 2.3.1), uploaded over EBICS as `OTH / BIL / CH004TPS / csv`
(ZKB order type `XTC`). [`tools/zkb-incoming-payments.py`](../tools/zkb-incoming-payments.py)
builds that file, uploads it, then downloads and parses everything HAA lists and reconciles
the credits against what it sent: each product's booking, then each payment's single
transaction (`NtryDtls/TxDtls`) with its reference, reference type, amount, payer and
remittance text. Two runs on 2026-10-26 matched all eight payments exactly.

A run of eight credits (three QRR, two SCOR, one NON, two LSV) was processed within seconds; the
platform's protocol (`Protokoll.txt`, in the `XTD` archive) reported the file correct. What came
back, and where:

| BTF (ZKB order type) | Content |
| --- | --- |
| `STM/CH/camt.052` (Z52), `EOP/CH/camt.053` (Z53) | each product as one collective credit for its total, next to the predefined bookings enabled under *Standard-Buchungen* |
| `REP/CH/XQRR/camt.054` (ZQR) | the QRR collective credit, with one `TxDtls` per payment carrying its QR reference |
| `REP/CH/XSCR/camt.054` (ZRF) | the SCOR collective credit, with the creditor references |
| `REP/CH/XDDD/camt.054` (ZS3) | the LSV+ collective credit — `XDDD` is the LSV+ variant |
| `REP/CH/XDCI/camt.054` (ZS2) | one notification per booking of the day, credits and debits alike |
| `REP/CH/XABK/camt.054` (ZS4) | after a pain.001 upload: the batch debit of the payment file with its single transactions |
| `OTH/BIL/CH004TPE/msc` (XTD) | a ZIP holding a ZIP of every result file plus `Protokoll.txt` |

Three platform behaviours to know:

- **The simulated credits came back as camt version 04**, although the pain.001 upload earlier
  the same day produced version 08 and the settings above say camt.05x.001.08. HAA listed
  only the version-04 BTFs. Version 08 of `XQRR`/`XSCR`/`XDDD` is therefore not yet
  validated with data; the bank does accept those tuples (`090005`, while an unregistered
  option is refused with `091005`).
- **Each collective-resolution ZIP held its document twice** (byte-identical, same
  notification ID), while the `XTD` archive held one copy. The parser returns what the bank
  sent, so a caller summing camt.054 amounts must de-duplicate by notification ID.
- **Every processed file produces its own statement**, not a running one: each camt.053 opens
  at the same balance and holds that file's bookings plus the predefined *Standard-Buchungen*
  (manual section 2.4), which therefore recur in every run.
- **The camt.052 and camt.053 carry the single transactions of the simulated collective
  credits too**, although the settings above have the collective-detail options off. So each
  payment appears three times: in camt.052, in camt.053 and in its camt.054.
- **A run that is never fetched stays waiting**, and the next `fetch` downloads it with the
  new one: the ZIPs then hold the documents of both runs. The referenced payments are told
  apart by their run-specific references, and the `NON` payment by its remittance text,
  which carries the run stamp.

## How the simulation is driven (validated 2026-07-05)

The test platform separates two facilities, which matters when interpreting results:

- **The web upload** (*Zahlungsdatei/Simulationsdaten hochladen*) is what drives the simulation.
  Uploading a `pain.001` there validates it against `pain.001.001.09.ch.03` and, if accepted,
  books it and produces a result ZIP (downloadable via the page's **Download** button) containing:
  a `Protokoll.txt` validation log, two `pain.002.001.10` status reports (technical `ACTC`, then
  business `ACCP`/`RJCT`), and — once accepted — a `camt.053` statement.
- **The EBICS channel** is validated independently. Our `BTU` upload is **accepted** by the EBICS
  server (correct AuthSignature and encryption), but on this platform it does
  **not** feed the web simulation, and the web simulation's `camt.053`/`pain.002` are **not**
  exposed back over the EBICS download queue (EOP stays `090005`).

> **Correction (2026-10-26).** The "dead bridge" below was our bug, not the platform's. The A006
> signature had the wrong shape (EMSA-PSS over the order data instead of over its SHA-256 hash
> value, spec 14.1.4.2.5). The EBICS exchange still returned `000000`, because a BTU order's
> signature is verified *after* the exchange (spec 5.1.3.1), and the platform then dropped the
> order quietly.
> A PUB key change, which the bank verifies synchronously, exposed it (`091301`). With the
> corrected signature, an EBICS upload of a 6-transaction pain.001 was processed: HAA then
> listed `EOP/camt.053`, `STM/camt.052`, `REP/camt.054` (twice), `PSR/pain.002` and `OTH/BIL`,
> and the pain.002 reports read `ACTC`, then `PART` with 2 rejected transactions — the
> "every third transaction" simulation setting. See [docs/12](12-verification-ledger.md),
> incident 3.

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
- **`HAA`** (order types with data available) returned an **empty list** at the time — the bank
  itself confirmed nothing was queued on the EBICS side, regardless of upload route (explained
  by the A006 correction above; since then EBICS uploads do produce data). EBICS `BTU`
  uploads are accepted (all variants probed: with/without `SignatureFlag`, with/without
  `fileName`, valid content, same-day execution date, well past the manual's 10–30 s processing
  window) but never appear in the web table nor produce EBICS-retrievable results, and web-upload
  results are never bridged to the EBICS queues (even when left unconsumed in the GUI).
- These probes also completed **full live BTD download transactions** (initialise → decrypt →
  receipt) and revealed that the bank acknowledges a positive receipt with
  **`011000 EBICS_DOWNLOAD_POSTPROCESS_DONE`** — a success code the client now accepts.

The manual (`ZKB_Testplattform_BenHB.pdf`, §3.7.4–3.7.5) documents EBICS submission/retrieval as
supported, so the dead EBICS→simulation bridge contradicted the platform's own documentation —
rightly, as the 2026-10-26 correction above shows.

## Open items surfaced by these settings

1. ~~Ask ZKB support why EBICS-submitted pain.001 files are never processed~~ — resolved
   2026-10-26: the cause was the client's A006 signature, not the platform (see above).
2. ~~camt.054 booking advices~~ — parsed live since 2026-10-26 (see the simulation section),
   with the single transactions of each collective booking (`Entry.transactions`). Still
   open: why the simulated credits arrive as camt version 04 (check *Simulation nach* on the
   Defaultwerte page).
