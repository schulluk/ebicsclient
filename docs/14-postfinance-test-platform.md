# PostFinance test platform — catalogue, behaviour, settings, and what is validated there

The PostFinance *Testplattform Geschäftskunden* (`testplattform.postfinance.ch`, EBICS endpoint
`isotest.postfinance.ch`) is the second bank test platform ebicsclient runs against, next to
ZKB's ([docs/09](09-zkb-test-platform-settings.md)). It is free, open to non-customers, and
documented in PostFinance's *Benutzerhandbuch für die Testplattform* (499.75 de, May 2025,
50 pages; public at
`https://testplattform.postfinance.ch/corporates/help/PostFinance_Testplattform_BenHB.pdf`),
cited below as "manual §x". This document records the platform's EBICS catalogue, the behaviour
that matters for protocol testing, the settings we run against (captured **2026-10-28**), and how
far our access is validated.

> The subscriber's own data (customer and subscriber ID, keyring, bank-key hashes) live in the
> workspace `../local/postfinance.env`, outside the repo. The handshake runner and the examples
> read `../local/.env` — the **ZKB** subscriber — unless `EBICS_ENV_FILE` points elsewhere:
>
> ```console
> EBICS_ENV_FILE=../local/postfinance.env uv run python examples/zkb_handshake.py hpb
> ```

## Status (2026-10-28)

| Step | Result |
| --- | --- |
| `generate`, `ini`, `hia` | keyring created; INI and HIA both `SUBMITTED` (`000000`) at the first attempt |
| `hpb` before the activation | `061001 EBICS_AUTHENTICATION_FAILED` — the answer ZKB gives before *EBICS-Teilnehmer freischalten* too ([docs/09](09-zkb-test-platform-settings.md), suspension section) |
| *EBICS-Teilnehmer freischalten*, then `hpb` | succeeded; both bank-key hashes match the "mit Schlüsseln" values on the EBICS-Daten page |
| HEV, HPD, HTD, HKD, HAA | all answered; the registry is below. User status `1`; HKD lists no accounts, before and after the web app's *Auftraggeberkonto* existed |
| pain.001.001.09 upload (`MCT / CH / pain.001 / 09`), two blocks, four payments | accepted (`000000`, bank order `N002`) and processed within five seconds |
| downloads after the upload | camt.053, pain.002, camt.054 and the `XTD` archive fetched and parsed (round-trip section below); the library's container-less `PAIN_002` was refused with `091005` |
| second upload (same payments, no `Dbtr/PstlAdr`), fetched with the typed methods | order `N003`; `download_payment_status_reports(PAIN_002_ZIP)`, `download_statements()` and `download_booking_advices()` all served; the statement opened at 500 000.00 again (*Kontostand beibehalten*); protocol without hints |
| third upload through the handshake runner (`upload`, then `pain002`) | order `N004`; the `pain002` step read the ZIP form from HTD and fetched both reports |
| fourth upload, `SignatureFlag` as the empty element the schema defines | order `N005`; HAC logs `TS01`, `DS01` (signature correct) and `ORDER_HAC_FINAL_POS`; pain.002 `ACCP` for both blocks |
| HAC with `KEEP`, then with `ACKNOWLEDGE` | the negative receipt answered `011001 EBICS_DOWNLOAD_POSTPROCESS_SKIPPED`, the positive one `011000 EBICS_DOWNLOAD_POSTPROCESS_DONE`, each in the header with `000000` in the body; the kept log came again, one entry longer |

These runs used the working tree of 2026-10-28, which already sends the bank-key digests in the
certificate-DER form of EBICS 3.0 (the uncommitted change behind the ledger's `BankPubKeyDigests`
row): PostFinance accepted that form in every download so far. Nothing below counts as validated
until the verification table at the end says so.

## Access and activation

*Einstellungen → EBICS-Daten* in the web app shows the connection data (EBICS URL
`https://isotest.postfinance.ch/ebicsweb/ebicsweb`, the host ID, and one ID that serves as
customer ID and subscriber ID — all kept in `../local/postfinance.env`) and the bank-key hashes,
with two buttons: *EBICS-Teilnehmer freischalten* and *EBICS-Teilnehmer zurücksetzen* (manual
§4.5.1, §4.8.5). The ceremony, from the
page text and §4.5.1: send INI and HIA, click *freischalten*, then fetch the bank keys with HPB.
No letter. After a reset the initialisation is run again from the start (§4.8.5). The platform
offers EBICS 2.5 order types and EBICS 3.0 BTF parameters side by side; we use H005 only.

The hash scheme is the one ZKB uses ([docs/05](05-zkb-onboarding.md)): one SHA-256 for "EBICS 2.5
und EBICS 3.0 mit Schlüsseln", printed identically for X002 and E002, and another for "EBICS 3.0
mit Zertifikaten", again identical for both. At ZKB the two values are the `e m` public-key digest
and the certificate-DER digest of a single key pair; whether PostFinance also uses one key pair
is what HPB will show. Pinning uses the "mit Schlüsseln" pair, as for ZKB.

## Order types and their BTF mapping

Transcribed from the EBICS-Daten page on 2026-10-28; the same table is manual §4.5.2.

### Uploads

| 2.5 type | Description | ServiceName | Scope | ServiceOption | MsgName | Version | Container |
| --- | --- | --- | --- | --- | --- | --- | --- |
| XE2 | pain.001 payment order (EZAG), 2009 | MCT | CH | — | pain.001 | 03 | — |
| — | pain.001 payment order (EZAG), 2019 | MCT | CH | — | pain.001 | **09** | — |
| XL5 | pain.008 CH-DD direct debit, COR1 | DDD | BIL | CH001COR | pain.008 | 02 | — |
| XL6 | pain.008 CH-DD direct debit, B2B | DDD | BIL | CH001B2B | pain.008 | 02 | — |
| XTC | CSV input for the QRR/ASR simulation | OTH | BIL | CH002LMF | csv | — | — |

### Downloads

| 2.5 type | Description | ServiceName | Scope | ServiceOption | MsgName | Version | Container |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Z01 | pain.002 status report (EZAG and CH-DD), 2009 | PSR | CH | — | pain.002 | 03 | ZIP |
| — | pain.002 status report (EZAG and CH-DD), 2019 | PSR | CH | — | pain.002 | **10** | ZIP |
| Z52 | camt.052 intraday report | STM | CH | — | camt.052 | 04 | ZIP |
| — | camt.052 intraday report | STM | CH | — | camt.052 | **08** | ZIP |
| Z53 | camt.053 end-of-period statement | EOP | CH | — | camt.053 | 04 | ZIP |
| — | camt.053 end-of-period statement | EOP | CH | — | camt.053 | **08** | ZIP |
| ZS2 | camt.054 credit and debit advices, "nicht im Angebot auf der Testplattform" | REP | CH | XDCI | camt.054 | 04 | ZIP |
| — | the same, 2019 | REP | CH | XDCI | camt.054 | 08 | ZIP |
| Z54 | camt.054 collective-booking resolutions: EZAG, CH-DD, returns, virtual QRR account, ASR, IBAN (SCOR/NON-SCOR) | REP | CH | — | camt.054 | 04 | ZIP |
| — | the same, 2019 | REP | CH | — | camt.054 | **08** | ZIP |
| STA | MT940 statement | EOP | CH | — | mt940 | — | — |
| VMK | MT942 intraday report | STM | CH | — | mt942 | — | — |
| XTD | every result file of the platform, as one ZIP | OTH | BIL | CH002LME | msc | — | ZIP |

EZAG is PostFinance's name for the pain.001 payment order (*Elektronischer Zahlungsauftrag*),
CH-DD the Swiss direct debit (pain.008), ASR the *Auszahlungsschein mit Referenznummer* (a cash
payout slip, manual §1.3), QRR the QR-bill with QR reference, and RS-PID the biller's
identification in CH-DD.

Where this catalogue differs from ZKB's ([docs/10](10-btf-order-types.md)):

- The platform-only tuples carry PostFinance's own options: `XTC` = `OTH / BIL / CH002LMF / csv`
  (ZKB `CH004TPS`) and `XTD` = `OTH / BIL / CH002LME / msc` (ZKB `CH004TPE`). The CSV format
  differs too (manual §4.7.7: semicolon-separated, header
  `Product;Channel;Account;Currency;Amount;Reference;Name;Street;Number;Postcode;City;Country`,
  plus QRR-only columns up to `RemittanceInformationText`; `Product` is `ASR`, `ASR+` or `QRR`,
  `Channel` one of `PO`, `OC`, `PF`, `OB`, `EZ`), so
  [`tools/zkb-incoming-payments.py`](../tools/zkb-incoming-payments.py) does not apply as it is.
- Direct debits are offered: `DDD / BIL / CH001COR | CH001B2B / pain.008 / 02`. ZKB's test
  platform lists none.
- No SEPA `SCT` and no CGI (`MCT / CGI / XCH`) upload tuples.
- camt.054 comes as `REP / CH` (Z54) and `REP / CH / XDCI` (ZS2) only — none of ZKB's `XQRR`,
  `XSCR`, `XDDD` and `XABK` variants — and ZS2 is marked as not offered on the test platform. So
  the plain `CAMT_054` constant, which ZKB never served, is the one that matters here.
- MT940 and MT942 are listed as BTFs (`EOP / CH / mt940`, `STM / CH / mt942`). The library does
  not read them.

The version-09/08 rows are exactly the library's `PAIN_001`, `CAMT_052`, `CAMT_053` and
`CAMT_054` constants. **`PAIN_002` is not:** the library's default `PSR / CH / pain.002 / 10`
carries no container, because ZKB's HTD registers it that way and refuses the ZIP form with
`091005` ([docs/10](10-btf-order-types.md)), while PostFinance's HTD registers it **with** the
ZIP container, exactly as its catalogue says (registry below), and refuses the container-less
form with `091005` (probed twice on 2026-10-28). The same business transaction is registered
differently at the two banks, so the library carries both tuples: `PAIN_002_ZIP` is the
PostFinance form, and `download_payment_status_reports(btf)` takes either. The `pain002`
step of `examples/zkb_handshake.py` asks HTD which form the bank registers and requests
that one (validated here with a third upload, order `N004`).

## What HEV, HPD, HTD and HKD established (2026-10-28)

- **HEV:** `H002` (02.30), `H003` (02.40), `H004` (02.50), `H005` (03.00) — the same range as ZKB.
- **HPD:** institute name "Corp. norm. Auth.", one URL (the endpoint above, valid from
  2020-11-11), protocol versions H002–H005, X001/X002, E001/E002, A004/A005/A006; recovery
  supported, pre-validation not, HKD/HTD and HAA supported. As at ZKB.
- **HTD:** user status `1`, 35 partner order types and 35 user permissions. Every upload
  permission carries signature class `E`, every upload order type `NumSigRequired` `0`, and the
  key-management types (INI, HIA, PUB, HCA, HCS, SPR) class `T`: a single-user subscriber, so EDS
  cannot be exercised here either, and none of the `HV*` order types is registered (see *No
  release flows* below). `HAC` and `PTK` are registered (ZKB served both without listing them).
- **HKD:** no accounts (none created yet), the same 35 order types.
- **HAA:** empty — nothing has been uploaded.

The registered BTFs, in HTD's order, with the containers and options the printed catalogue
leaves out or lacks:

| Admin type | BTF (service / scope / option / message / version / container) | Bank's description |
| --- | --- | --- |
| BTD | `EOP / CH / — / camt.053 / 08 / ZIP` | Kontoauszug am Ende einer Berichtsperiode camt.053 (Version 08) |
| BTD | `PSR / CH / — / pain.002 / 10 / ZIP` | Statusreport gemischt Zahlung/Lastschrift/CH-DD/SDD pain.002 (Version 10) |
| BTD | `REP / CH / — / camt.054 / 08 / ZIP` | Auflösung Sammelbuchungen Zahlungen (FI sammelt) camt.054 (Version 08) |
| BTD | `EOP / CH / — / mt940 / — / —` | Swift-Tagesauszuege abholen |
| BTD | `STM / CH / — / camt.052 / 08 / ZIP` | Saldenreport, Intraday-Kontobewegungen camt.052 (Version 08) |
| BTD | `STM / CH / — / mt942 / — / —` | Saldenreport, Intraday-Kontoauszug im SWIFT-Format |
| BTD | `OTH / BIL / CH002LME / msc / — / ZIP` | Abholung Ergebnisse Testbank (XTD) |
| BTD | `PSR / CH / — / pain.002 / 03 / ZIP` | Statusreport gemischt Zahlung/Lastschrift/CH-DD/SDD: EZAG, CH-DD/SEPA-DD |
| BTD | `STM / CH / — / camt.052 / 04 / ZIP` | Saldenreport, Intraday-Kontobewegungen |
| BTD | `EOP / CH / — / camt.053 / 04 / ZIP` | Kontoauszug am Ende einer Berichtsperiode |
| BTD | `REP / CH / — / camt.054 / 04 / ZIP` | Auflösung Sammelbuchungen Zahlungen (FI sammelt): EZAG, CH-DD/SEPA-DD, Returns (ES), ESR/ASR, ES |
| BTD | `REP / CH / XDCI / camt.054 / 04 / ZIP` | Gut- und Lastschriftsanzeigen (ZS2) |
| BTD | `REP / BIL / CH001IMG / camt.054 / 04 / ZIP` | ES-Detailavisierung für Avisierung mit Belegbild — not in the printed catalogue |
| BTU | `MCT / CH / — / pain.001 / 09 / —` | Zahlungsauftrag pain.001 (Version 09) |
| BTU | `MCT / CH / — / pain.001 / 03 / —` | Zahlungsauftrag |
| BTU | `SDD / CH / — / pain.008 / — / —` and `… / 02 / —` | SEPA Zahlungsverkehr Direct Debit Initiation, CORE — not in the printed catalogue |
| BTU | `SDD / CH / XB2B / pain.008 / — / —` and `… / 02 / —` | SEPA Zahlungsverkehr Direct Debit Initiation, B2B — not in the printed catalogue |
| BTU | `DDD / BIL / CH001COR / pain.008 / 02 / —` | CH-Direct Debit COR1 |
| BTU | `DDD / BIL / CH001B2B / pain.008 / 02 / —` | CH-Direct Debit B2B |
| BTU | `OTH / BIL / CH002LMF / csv / — / —` | Upload CSV für Testbank (XTC) |

Two things the registry says that the catalogue does not: ZS2 (`XDCI`) and the `CH001IMG` image
advice exist only in version 04, and SEPA direct-debit tuples (`SDD`) are registered although the
web app offers no SEPA product.

## First round-trip over EBICS (2026-10-28)

One pain.001.001.09 with two payment blocks — three CHF payments to Swiss IBANs (one of them
to a PostFinance creditor) and one EUR SEPA payment to a French IBAN — debiting the
*Auftraggeberkonto*, debtor agent `POFICHBEXXX`, structured addresses, no `BtchBookg` (so the
default `true`), uploaded as `MCT / CH / pain.001 / 09`. The exchange answered `000000`; the
bank's order ID was `N002`. Five seconds later HAA listed four BTFs, all fetched with a
positive receipt and kept under `local/postfinance-runs/<stamp>/fetch/`:

| BTF | Delivered |
| --- | --- |
| `PSR / CH / pain.002 / 10 / ZIP` | one ZIP with two `pain.002.001.10` documents, one per payment block, each `PmtInfSts` `ACCP` and no group status; `InitgPty` is the BIC `POFICHBE`, `CreDtTm` in UTC. No technical `ACTC` message: the simulated channel is E-Finance (manual §4.7) |
| `EOP / CH / camt.053 / 08 / ZIP` | one `camt.053.001.08` statement (`AddtlInf` `SPS/2/TEST`): opening 500 000.00, closing 499 512.96 CHF; one collective debit per payment block with `BkTxCd` `PMNT/ICDT/AUTT`, `AddtlNtryInf` "EZAG ISO 20022 SAMMELAUFTRAG E-FINANCE <PmtInfId> <MsgId>" and a single `TxDtls` carrying `MsgId`, `PmtInfId` and a `UETR`; the EUR block shows `AmtDtls` with the instructed EUR 75.00, the counter value CHF 90.59 and the fixed rate 1.2078 of manual §3.1.3. No fees (simulation off) |
| `REP / CH / camt.054 / 08 / ZIP` | one ZIP with four `camt.054.001.08` notifications, all in version 08 as configured: per payment block an *Einzelbestätigung* (one entry for the block total with one `TxDtls` per payment: `InstrId`, `EndToEndId`, `UETR`, creditor name, structured address and IBAN; `BkTxCd` sub-family `DMCT` for the domestic payments, `BOOK` for the one to a PostFinance account, `ESCT` for the SEPA payment) and an *Ausführungsbestätigung* (the same entry with one `TxDtls` carrying only `MsgId` and `PmtInfId`) |
| `OTH / BIL / CH002LME / msc / ZIP` (XTD) | one flat ZIP: `Protokoll.txt`, the two pain.002, the camt.053, the four camt.054 and the uploaded pain.001 under the bank's name `<user>.MCT_CH_pain.001_09.N002.<number>.xml`, the messages named the E-Finance way (`camt.053_T_<IBAN>_…`). Unlike ZKB's XTD, no ZIP inside the ZIP |

The protocol reported the file correct with two hints, both "Das Element 'PstlAdr' sollte nicht
verwendet werden" for `Dbtr/PstlAdr`: PostFinance takes the debtor's address from the account,
so a pain.001 for this platform should leave the debtor's postal address out. The country of
the debtor IBAN (a GB example IBAN) did not matter.

Observations for the parsers:

- `camt053.parse`, `camt054.parse` and `pain002.parse` handled every file; the balances
  reconcile (500 000.00 − 396.45 − 90.59 = 499 512.96) and `Entry.transactions` carries the
  single payments of the *Einzelbestätigung* with references, creditor and remittance text.
- The platform splits unstructured remittance information into `Ustrd` lines of 35 characters
  and pads the last one with spaces ("ebicsClient PostFinance test 202610", then "28002202
  payment 1" followed by 17 spaces). The parser returns the lines as sent; a caller that wants
  the text back joins them and strips the padding.
- The EBICS ZIP members are named after the BTF
  (`2026-10-28_EOP_CH_camt.053_08_-_ZIP_<time>.<sequence>.xml`), the XTD members after the
  E-Finance convention.
- The UETRs are not per payment: the camt.053's two `TxDtls` share one, the three transactions
  of a camt.054 block another.

**Second run (2026-10-28, 07:35):** the same four payments with new IDs and without
`Dbtr/PstlAdr`, fetched through the typed methods. The protocol then reports the file correct
without hints. The statement opened at 500 000.00 again, so *Kontostand beibehalten* does what
the manual says (§4.7.2), and closed at the same 499 512.96. The default
`download_payment_status_reports()` was refused with `091005` once more;
`download_payment_status_reports(PAIN_002_ZIP)`, `download_statements()` and
`download_booking_advices()` returned the two reports, the statement and the four
notifications. Bank order `N003`.

## Platform behaviour that matters over EBICS (manual)

- **Everything is processed at once.** Payments are executed immediately whatever their execution
  date; one statement is produced per account and booking day, with the requested execution date
  as the booking date (§3.1.1). An EBICS upload is processed within 10 to 30 seconds (§4.7.9).
- **No duplicate check** for EZAG and CH-DD files: the same file may be submitted again and again
  (§3.3.1, §3.3.2), unlike production. Convenient for repeating a test.
- **Uploads need no signature:** "Die Dateien können ohne Unterschrift hochgeladen werden"
  (§4.7.9). A `000000` therefore says even less about the A006 signature than at ZKB, where a
  wrong signature only dropped the order after the exchange ([docs/09](09-zkb-test-platform-settings.md),
  correction of 2026-10-26). A signature that *is* supplied gets verified: HAC logs `DS01` for
  every upload (2026-10-28); whether a wrong one is rejected has not been probed.
- **No release flows, hence no EDS:** §3.3 lists "Freigabe (Einzel- und Kollektivunterschrift)"
  among the processes the platform cannot test, *EBICS-Zugang anlegen* creates exactly one EBICS
  subscriber per test customer (§4.5.1) with no way to add a second, and HTD registers none of
  the `HV*` order types — the same limit ZKB's support confirmed for its platform on 2026-10-26.
  PostFinance **production** does offer EDS: the *EBICS Parameterdatenblatt PostFinance* (01765
  de, version 19; `https://www.postfinance.ch/content/dam/pfch/doc/0_399/01765_de.pdf`) lists
  HVD, HVE, HVS, HVT, HVU and HVZ among its system order types, and the *Factsheet EBICS für
  Softwarehersteller* (460.186 de, 01.2025;
  `https://www.postfinance.ch/content/dam/pfch/doc/460_479/460_186_de.pdf`) describes release by
  distributed signature per user with the classes E, T and Kollektivunterschrift A/B, given from
  the EBICS client or PostFinance's *EBICS VEU App*, next to the person-neutral Corporate Seal
  (E, T). Exercising EDS at PostFinance therefore needs a production contract with those rights,
  not the test platform.
- **Results are ZIP archives**, which "entspricht nicht dem Verhalten in der Produktion" (§3.3),
  and `XTD` arrives as a ZIP without the `.zip` suffix (§4.7.12). Nothing is pushed; the customer
  fetches (§3.3).
- **EBICS downloads expire after one day:** "in EBICS: alle Dateien, die älter als einen Tag sind"
  are deleted (§4.7.16); other files after 90 days.
- **Accounts** are IBANs with a valid check digit, real or not (§3.1.2, §4.7.2). A new account
  starts at 500 000 in CHF, EUR or USD; the balance is carried forward from file to file unless
  *Kontostand beibehalten* pins it, for reproducible runs (§4.7.2). An order whose debtor IBAN is
  not registered is rejected as a whole, and without a registered account only the file format is
  checked (§4.7.2, §4.7.9). USD accounts take transfers only; ASR needs a CHF account.
- **camt.052:** two reports per file, morning and afternoon. The first B-level order of a file
  goes into both reports and the camt.053, the second only into the afternoon report and the
  camt.053, the third only into the camt.053; then the pattern repeats (§3.4). Not produced for
  QRR/ASR or QR-bills.
- **Error simulation**, when enabled: every fifth transaction fails — for transfers a reject or a
  return chosen by payment type (`MS03`, `CH21`, `NARR`, ...); for CH-DD format errors at
  transactions 5, 10, 15, 20, 25 and 30, execution errors at 7 and 12 (a separate pain.002) and a
  refund at 17; for QRR/ASR a reversal at 5, a correction at 10, rejects at 15 and 20 (§3.5). A
  return produces a second camt.053 for the following day (§4.7.6.7). A file with more than 1000
  errors is rejected outright (§3.5).
- **Fees and interest** can be simulated as fixed entries at the end of the camt.053 (§4.7.6.7);
  EZAG fees (express orders, Giro International, `DEBT` charges) appear in the camt.054 (§3.2).
- **The simulated channel** (E-Finance, File Delivery Services / H-Net / Connect Direct, SWIFT
  FileAct) changes the generated file names, and only the two file-transfer channels produce the
  *technical* pain.002 acknowledgement; under E-Finance it is not generated (§4.7, §4.7.6.7).
- **Day-end processing** (several files merged into one consistent set of camt messages) is
  web-only: "Über SFTP bzw. EBICS kann keine Tagesendverarbeitung erfolgen" (§4.7.11).

## Settings (captured 2026-10-28, as found after registration)

### Produktnutzung

| Option | Selected |
| --- | --- |
| Produktangebot 1: ISO 20022 2009 (pain V03) and 2013 (camt V04), SPS 2021 (1.2) | ⬜ |
| Produktangebot 2: ISO 20022 2019 (pain V09 and camt V08) and 2013 (camt V04), SPS 2025 (2.2), QR-Rechnung SPS 2025 (2.3) | ✅ |

Under Produktangebot 2 the platform validates pain.001.001.09 and generates camt.052/053/054 in
versions 04 and 08 (manual §3.2); which version is delivered is chosen per message under
*Avisierung*.

### Einstellungen

- **Konten:** one *Auftraggeberkonto* since 2026-10-28 — a fictitious GB example IBAN with a
  valid check digit (kept out of the repo), CHF, balance 500 000, *Kontostand beibehalten* on.
  The page warns that without an *Auftraggeberkonto* matching the payment files neither the camt
  messages nor the business validation are available. Columns: IBAN, Kontostand, Währung,
  Kontostand beibehalten, ASR, Virtuelles Konto QRR, RS-PID.
- **ASR-Kundennummern, Virtuelles Konto QRR, Lastschriften (RS-PID): none**; each needs an
  account first. An ASR number is nine digits with prefix `02`, on a CHF account with a CH or LI
  IBAN; a virtual QRR account is `CH` + bank ID `30000` + the IBAN's last nine digits, or generated
  by the platform, on a CH/LI account in CHF or EUR; an RS-PID is 17 digits starting with `41`
  with mod-97 remainder 1, on a CHF or EUR account (manual §4.7.3–4.7.5).

### Avisierung → Kontoavisierung (applies to all products)

| Setting | Value |
| --- | --- |
| Kontoauszug mit Detailavisierung (camt.053) | ⬜ |
| Kontoauszug mit Sammelbuchung (camt.053) | ✅ Version 8 (camt.053.001.08); alternative: Version 4 |
| Intraday-Kontobewegungen (camt.052) | ⬜ |
| Kontoauszug MT940 | ⬜ |
| Intraday-Kontobewegungen MT942 | ⬜ |

### Avisierung → EZAG (answers to a pain.001)

| Message | Value |
| --- | --- |
| Verarbeitungsmeldung (pain.002) | always; cannot be disabled |
| Intraday-Kontobewegungen (camt.052), MT942 | ✗ (follow the Kontoavisierung) |
| Kontoauszug mit Sammelbuchung (camt.053) | ✓ (follows the Kontoavisierung); MT940 ✗ |
| Ausführungsbestätigung (camt.054) | ✅ Version 8 (camt.054.001.08) |
| Einzelbestätigung (camt.054) | ✅ Version 8 (camt.054.001.08) |
| Gutschriftsavisierung, Rückbuchung Drittpartei (camt.054) | ⬜ (enabling it switches the error simulation on, §4.7.6.3) |

A pain.001 overrides the camt.054 choice per file with `Proprietary` = `CND` (execution
confirmation), `CWD` or `SIA` (single confirmation) or `NOA` (none); `BtchBookg` `false` books
single debits in the camt.053, the default `true` one collective debit (page text; §4.7.6.3).

### Avisierung → CH-DD (answers to a pain.008)

pain.002 ✓, camt.052 ✗, camt.053 Sammelbuchung ✓; camt.054 detail: **alle RS-PIDs getrennt
avisieren** (alternative: zusammen).

### Avisierung → ASR (answers to a CSV)

camt.053 Sammelbuchung ✓; camt.054 detail: **alle Kundennummern (ASR) getrennt avisieren**.

### Avisierung → QR-Rechnung (virtual QRR account, IBAN SCOR/NON-SCOR)

camt.053 Sammelbuchung ✓; camt.054 detail: **alle virtuellen Konto QRR getrennt avisieren**;
bookings: **Sammelbuchung aller QRR** (alternative: Einzelbuchung jeder QRR; *Sammelbuchung aller
QRR mit SCOR* off).

### Avisierung → Simulation

| Setting | Value |
| --- | --- |
| Simulation von Rejects und Rückbuchungen | ⬜ |
| Zinsen | keine Zinsen simulieren |
| Gebührenbelastung (Preise) simulieren | ⬜ |
| Kanal | ✅ E-Finance (alternatives: File Delivery Services / H-Net / Connect Direct; SWIFT FileAct) |

## Mapping to our implementation, and verification status

| Capability | Platform | Our code | Status |
| --- | --- | --- | --- |
| Handshake INI/HIA | mit Schlüsseln profile | `client.ini()`, `client.hia()` | ✅ live (both `SUBMITTED`, 2026-10-28) |
| HPB with pinned hashes | EBICS-Daten page | `client.hpb(pinned=…)` | ✅ live (both hashes match, 2026-10-28; the keys arrive as certificates) |
| HEV, HPD, HTD, HKD, HAA | — | `supported_versions()`, `bank_parameters()`, `subscriber_info()`, `customer_info()`, `available_order_types()` | ✅ live (2026-10-28, with the certificate-DER `BankPubKeyDigests`) |
| End-of-day statement download | `EOP / CH / camt.053 / 08 / ZIP` | `download_statements()` | ✅ live (2026-10-28, three runs: balances reconcile, one collective debit per payment block; the third fetched with the explicit `CAMT_053` argument) |
| Intraday report | `STM / CH / camt.052 / 08 / ZIP` | `download_intraday_statements()` | ⏳ needs *Intraday-Kontobewegungen* enabled; `download_intraday_statements(CAMT_052)` answered `090005`, so the tuple is registered and merely empty |
| Booking advices | `REP / CH / camt.054 / 08 / ZIP` (Z54) | `download_booking_advices()` | ✅ live (2026-10-28, two runs: four notifications in version 08, single transactions with references, creditor and remittance text) |
| pain.001 upload | `MCT / CH / pain.001 / 09` | `client.upload(PAIN_001, …)` | ✅ live (2026-10-28: accepted, processed, booked; the fourth run with `SignatureFlag` as the schema's empty element) |
| Receipt answers by polarity | `011000` after a positive, `011001` after a negative receipt | `parse_download_receipt_response(…, positive=…)`, `ReceiptMismatchError` | ✅ live (2026-10-28: HAC with `KEEP` and with `ACKNOWLEDGE`) |
| HAC customer acknowledgement | administrative order `HAC` | `customer_acknowledgement()` | ✅ live (2026-10-28: 49 entries kept, 50 taken; each upload logs `TS01`, `DS01`, `ORDER_HAC_FINAL_POS`; each download `TS01`) |
| pain.002 back | `PSR / CH / pain.002 / 10 / ZIP` | `download_payment_status_reports(PAIN_002_ZIP)` | ✅ live (2026-10-28, two runs: one report per payment block, `ACCP`) |
| pain.002 with the default `PAIN_002` | `PSR / CH / pain.002 / 10`, no container | `download_payment_status_reports()` | ❌ `091005 EBICS_INVALID_ORDER_IDENTIFIER` on both runs: ZKB's registration, which PostFinance refuses — pass `PAIN_002_ZIP` here |
| Test-platform result archive | `OTH / BIL / CH002LME / msc / ZIP` (XTD) | `client.download(…)` with a hand-built BTF | ✅ live (2026-10-28: one flat ZIP with the protocol, every message and the uploaded file) |
| CH-DD direct debit (pain.008) | `DDD / BIL / CH001COR \| CH001B2B / pain.008 / 02` | — (no constant) | ⬜ out of scope; the first place a direct debit could be tested |
| QRR/ASR simulation input (CSV) | `OTH / BIL / CH002LMF / csv` | — (the ZKB tool does not fit) | ⬜ |
| Bank-side A006 verification | uploads accepted "ohne Unterschrift" | — | 🟡 HAC logs `DS01` (signature correct) for every upload, so the platform verifies the signature it gets; whether a wrong one is rejected has not been probed |
| EDS (HVU, HVZ, HVD, HVT, HVE, HVS) | not offered: release flows excluded (§3.3), one subscriber per test customer (§4.5.1), no `HV*` type in HTD | — (not implemented; see [docs/13](13-standard-conformance.md)) | ⬜ cannot be exercised here; PostFinance production lists all six in its parameter sheet 01765 |

**Legend:** ✅ verified · 🟡 partly verified · ⏳ implemented, live-verification pending · ❌ fails at this bank · ⬜ not started / out of scope.

## Next steps, in order

1. Check on a later day whether the first run's EBICS files have expired (manual §4.7.16).
2. Optional probes: a wrong A006 signature (is it detected at all? HAC is registered, so the
   customer acknowledgement can tell), the file-transfer channel (technical pain.002), CH-DD
   (`DDD / BIL / CH001COR`), the CSV simulation (`OTH / BIL / CH002LMF / csv`).

## Open items

- Does the platform reject a wrong A006 signature? It verifies the signature it gets (HAC
  logs `DS01` for every upload); a wrong-signature probe, judged by the customer
  acknowledgement as at ZKB, has not been run.
- Is the technical pain.002 of the file-transfer channels also delivered over EBICS?
- Does the platform reject a foreign debtor agent BIC, as ZKB does ("Multibanking ist nicht
  zulässig")? `POFICHBEXXX` with a GB debtor IBAN went through; a foreign BIC has not been tried.
