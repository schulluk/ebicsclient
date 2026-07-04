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

The row we consume today is **Z53 / EOP / CH / camt.053 / 08 / ZIP**, which is exactly
`models.CAMT_053`. `XTD` (`OTH / BIL / CH004TPE / msc`) is a test-platform aggregate that bundles
every result file into one ZIP — useful for eyeballing what a run produced, but not a typed
business message.

## Mapping to milestones

- **M2 (read, current):** `Z53` camt.053 v08 — implemented as `CAMT_053`.
- **M3 (write):** `XE2` pain.001 v09 upload → `Z01` pain.002 v10 download for the status report.
- **Post-MVP backlog:** `Z52` camt.052 intraday, and the `Z54`/`ZS*`/`ZQR`/`ZRF` camt.054 advices
  (several are enabled on the platform — see [docs/09](09-zkb-test-platform-settings.md)).

When these are built, each becomes a `BusinessTransactionFormat` constant beside `CAMT_053`,
sourced from the row above rather than assumed.
