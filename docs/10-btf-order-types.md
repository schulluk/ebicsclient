# ZKB EBICS order types and their H005 BTF mapping

ZKB publishes, for each business transaction, the legacy **EBICS 2.5 order type** (Auftragsart)
and the equivalent **EBICS 3.0 (H005) Business Transaction Format** — the `ServiceName / Scope /
ServiceOption / MsgName / Version / Container` tuple that H005 uses in place of an order type. This
table is that catalogue, transcribed from the ZKB test platform on **2026-07-04**.

It is a generic, per-bank catalogue (the same for every ZKB customer) and carries **no
account-specific data** — that is why it lives in the repo. The account's own onboarding values
(Host ID, Partner/User ID, bank-key hashes) are deliberately **not** committed; they live in the
workspace `../local/` directory, outside the repo.

Our download BTF (`models.CAMT_053`) is defined directly from the **Z53 / camt.053 v08** row below,
so this table is the external oracle for that constant.

## Uploads

| 2.5 type | Description | ServiceName | Scope | ServiceOption | MsgName | Version | Container |
| --- | --- | --- | --- | --- | --- | --- | --- |
| XE2 | pain.001 — CH payment submission | MCT | CH | — | pain.001 | 03 | — |
| XE2 | pain.001 — CH payment submission | MCT | CH | — | pain.001 | **09** | — |
| XCT | pain.001 — CH (CGI schema) | MCT | CGI | XCH | pain.001 | 03 | — |
| XCT | pain.001 — CH (CGI schema) | MCT | CGI | XCH | pain.001 | 09 | — |
| CCT | pain.001 — SEPA payment submission | SCT | GLB | — | pain.001 | 03 | — |
| CCT | pain.001 — SEPA payment submission | SCT | GLB | — | pain.001 | 09 | — |
| XTC | CSV input file for camt-message simulation | OTH | BIL | CH004TPS | csv | — | — |

For our M3 CH payment upload the target is **XE2** = `MCT / CH / pain.001 / 09` (matching the
platform's `pain.001.001.09.ch.03` validation version; see [docs/09](09-zkb-test-platform-settings.md)).

**CCT (`SCT / pain.001 / 09`) is only in the experimental module**
(`ebicsclient.experimental.PAIN_001_SEPA`). HTD registers it without the `GLB` scope. The
test platform answered uploads under both tuples, with and without `GLB`, with `000000`, but
never processed them: no pain.002, no booking, no protocol entry (2026-10-27). The customer
acknowledgement (HAC) shows the bank rejected both in its signature check with `TD03`
IncorrectFileStructure. The same SEPA file was processed under `XE2` and under `XCT`, so at
ZKB a SEPA payment (payment type S) goes through `PAIN_001` or `PAIN_001_CGI`.

## Downloads

| 2.5 type | Description | ServiceName | Scope | ServiceOption | MsgName | Version | Container |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Z01 | pain.002 — CH status report | PSR | CH | — | pain.002 | 03 | ZIP |
| Z01 | pain.002 — CH status report | PSR | CH | — | pain.002 | **10** | ZIP |
| Z52 | camt.052 — CH intraday statement | STM | CH | — | camt.052 | 04 | ZIP |
| Z52 | camt.052 — CH intraday statement | STM | CH | — | camt.052 | 08 | ZIP |
| Z53 | camt.053 — CH end-of-day statement | EOP | CH | — | camt.053 | 04 | ZIP |
| **Z53** | **camt.053 — CH end-of-day statement** | **EOP** | **CH** | **—** | **camt.053** | **08** | **ZIP** |
| Z54 | camt.054 — CH collective-booking info | REP | CH | — | camt.054 | 04 | ZIP |
| Z54 | camt.054 — CH collective-booking info | REP | CH | — | camt.054 | 08 | ZIP |
| ZS2 | camt.054 — CH booking information | REP | CH | XDCI | camt.054 | 04 / 08 | ZIP |
| ZS3 | camt.054 — CH collective-booking info (DDD) | REP | CH | XDDD | camt.054 | 04 / 08 | ZIP |
| ZS4 | camt.054 — CH collective-booking info, debit only | REP | CH | XABK | camt.054 | 04 / 08 | ZIP |
| ZQR | camt.054 — CH collective-booking info (QRR) | REP | CH | XQRR | camt.054 | 04 / 08 | ZIP |
| ZRF | camt.054 — CH collective-booking info (SCOR) | REP | CH | XSCR | camt.054 | 04 / 08 | ZIP |
| XTD | ZIP archive of all result files | OTH | BIL | CH004TPE | msc | — | ZIP |

`XTD` (`OTH / BIL / CH004TPE / msc`) and `XTC` (`OTH / BIL / CH004TPS / csv`) exist only on the
test platform: `XTD` bundles every result file of a run into one ZIP, and `XTC` feeds the
simulation of incoming credits. Both are used by
[`tools/zkb-incoming-payments.py`](../tools/zkb-incoming-payments.py), not by the library API.

Where this catalogue and the bank's HTD registry disagree, HTD wins. HTD registers
`PSR / CH / pain.002 / 10` **without** a container (a request with `ZIP` is refused with
`091005`), and the SEPA `SCT / pain.001` entries **without** the `GLB` scope.

## Library constants

Each constant is the row above, checked against the bank's HTD registry
(`tests/test_h005.py`) and downloaded or uploaded live (see [docs/09](09-zkb-test-platform-settings.md)).

| Order type | Constant | Content (observed live) |
| --- | --- | --- |
| XE2 v09 | `PAIN_001` | payment submission |
| XCT v09 | `PAIN_001_CGI` | payment submission in the original ISO schema; the test platform accepts only SEPA payments (type S) in it |
| CCT v09 | `experimental.PAIN_001_SEPA` | experimental: accepted by the test platform, never processed |
| Z01 v10 | `PAIN_002` | payment status reports |
| Z52 v08 | `CAMT_052` | intraday report |
| Z53 v08 | `CAMT_053` | end-of-day statement |
| Z54 v08 | `CAMT_054` | not delivered in the 2026-10-26 runs; ZKB used the variants below |
| ZS2 v08 | `CAMT_054_BOOKING_INFORMATION` | one notification per booking, credits and debits |
| ZS4 v08 | `CAMT_054_COLLECTIVE_DEBITS` | a payment file's batch debit with its single transactions |
| ZQR, ZRF, ZS3 | — | collective QRR, SCOR and LSV+ credits; delivered so far only in version 04, so no constant yet |

Until a variant has its own constant, `download_booking_advices` takes any of these tuples as a
`BusinessTransactionFormat`.
