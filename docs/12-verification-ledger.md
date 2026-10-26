# Verification ledger — every protocol claim, its source, its oracle

## Why this exists

Three times now, a wrong-but-self-consistent implementation passed every test we had:

1. **Exclusive c14n instead of inclusive C14N 1.0** ([docs/08](08-parity-and-xsd-findings.md)) — round-trip tests proved
   consistency, not interoperability.
2. **The EBICS 2.x public-key hash on the initialisation letter** — the EBICS 3.0 letter
   carries the SHA-256 of the DER-encoded *certificate* (spec 4.4.1.2.3), not the
   `exponent modulus` hash. The ZKB test platform auto-activates subscribers, so the letter
   had no oracle; the flaw surfaced only when a real production activation failed. It cost a
   bank round-trip, a subscriber reset, and re-initialisation.

3. **The A006 electronic signature signed the order data instead of its hash value.** Spec
   14.1.4.2.5 defines A006 as EMSA-PSS over `SHA-256(M)` (so the data is hashed twice), and
   spec 14 leaves CR, LF and Ctrl-Z out of that hash; the client ran EMSA-PSS over the raw
   bytes. The ledger listed A006 as "live" because ZKB *accepted* pain.001 uploads — but a
   bank-technical order is processed, signature included, only after the EBICS exchange has
   returned `000000` (spec 5.1.3.1), so acceptance never exercised it (docs/09 records that
   those uploads silently never reached the platform's processing). The first order the bank
   verifies within the exchange, PUB (spec 4.3, 5.1.3.1), was rejected with
   `091301 EBICS_SIGNATURE_VERIFICATION_FAILED`; the spec-conformant signature was then
   accepted, and a pain.001 upload signed the same way was processed (2026-10-26).

All three incidents share one root: **a protocol claim implemented from prior knowledge instead
of a cited source, in a spot without an external oracle** — and in the third, an oracle that
looked like one but never ran. This ledger makes that state visible: every protocol-surface claim gets a row with its normative citation, its oracle,
and its status. A row without an oracle is a liability, not a detail — it must be labelled
UNVERIFIED here and in the README until an oracle exists.

## Rules

- **Protocol surface** is anything the bank parses, compares, or verifies — *including the
  paper letters*. Rendering that a bank back office machine-compares is wire format.
- **Version boundary**: knowledge from EBICS 2.x is contamination until re-cited against
  the 3.0 spec. The spec's own amendment-history table (pages 2–3) is the checklist of
  everything that changed; a 2.5→3.0 audit against it was completed on 2026-07-22.
- **Golden vectors come from the authority** — spec examples, XSD, or live bank behaviour;
  never derived from our own output. The spec's example letters (11.5.1/11.5.2) publish
  certificates *with* their expected hashes: `tests/test_spec_letter_vectors.py` pins them.
- New protocol code lands with a row here, or it does not land.
- **Mandated vs bank-dependent.** For behaviour the standard *mandates*, spec/XSD conformance
  is the bar — confirming it at one bank proves nothing about the next (ZKB → Commerzbank →
  Deutsche Bank never ends), so a mandated row reaches `spec` and is done. For behaviour the
  standard *leaves to the bank*, no amount of standard-following makes it universal; such rows
  stay `bank-dependent` by nature — surfaced to callers, never silently assumed, not a gap to
  close. The at-a-glance split is in [docs/13-standard-conformance.md](13-standard-conformance.md).

## Status legend

- **live** — accepted/produced by the ZKB platform in real transactions.
- **spec-vector** — matches examples published in the specification.
- **XSD** — validated against the H005 schema files.
- **parity** — cross-checked against an independent implementation (`tools/php-parity/`).
- **UNVERIFIED** — no oracle yet; labelled as such wherever the claim is used.

## The ledger

| Claim | Normative source | Oracle | Status |
|---|---|---|---|
| Namespace `urn:org:ebics:H005`; schema file names | Spec, schema-files amendment note; XSDs | XSD + live | live |
| AuthSignature over `authenticate="true"` nodes, inclusive C14N 1.0, RSA-SHA256/X002 | Spec 5.5.1.2.1; H005 XSD | XSD, parity, live | live |
| A006 ES = EMSA-PSS over the **hash value** `SHA-256(M)` (SHA-256, MGF1-SHA256, salt = 32); `M` = order data without CR, LF, Ctrl-Z | Spec 14.1.4.2.5 (sign the hash), 14.1.4.2 (PSS parameters), 14 (CR/LF/Ctrl-Z excluded) | live: PUB, HCS, HCA accepted by ZKB, which verifies their ES within the exchange (spec 4.3, 5.1.3.1); the earlier single-hash form was rejected `091301`. A pain.001 signed this way was then processed (pain.002 `ACTC`, `PART`). Plus a verifier transcribed from spec 14.1.4.2.3 (`test_crypto.py`). BTU *acceptance* alone is **not** an oracle — its ES is checked after the exchange (spec 5.1.3.1) | live (since 2026-10-26; before that the "live" label was wrong, see incident 3) |
| `DataDigest` = the same hash value the ES signs (`SHA-256` of the order data without CR, LF, Ctrl-Z) | Spec 5.3 ("the hash value of the order data that has been signed"), 5.5.1.1.1 (`@SignatureVersion` names the process that computes it), 14 | live (accepted on PUB/HCS/HCA and BTU) | live |
| Order data: deflate → AES-128-CBC (null IV) → base64; transaction key RSA-PKCS1v15 to E002 | Spec 15 (encryption annex refs) | live (downloads decrypt, uploads accepted) | live |
| BTF structures (BTD/BTU order params), `SignatureFlag` replaces order attributes | Spec BTF chapters; amendment table | XSD + live | live |
| Receipt code `011000` = positive acknowledgement | Observed; Annex 1 return codes | live | live |
| Return-code fail-closed table | Annex 1; live ReportText | live + fail-closed design | live |
| camt.052/053/054 parsers: identification, account, balances, entries (amount, sign, status, booking/value date, reference). The parsers read the camt namespace from each document and accept version 04 as well as 08; comparing that version with the request is `VersionPolicy.STRICT` (next row) | ISO 20022 camt.052/053/054 message definitions; Swiss Implementation Guidelines for reports (SPS) | live: ZKB test-platform reports downloaded over EBICS on 2026-10-26 (version 08 after a pain.001 upload, version 04 after a simulated-credit upload). camt.053 balances reconcile (opening + entries = closing), and the simulated credits ([`tools/zkb-incoming-payments.py`](../tools/zkb-incoming-payments.py)) appear with their exact totals in camt.052, camt.053 and camt.054. The inputs are known amounts and the outputs are the bank's, so neither side comes from this library | live |
| `VersionPolicy.STRICT`: before the receipt, every delivered document's root namespace `urn:iso:std:iso:20022:tech:xsd:<message>.<variant>.<version>` must name the BTF's `MsgName` and `version`; anything else (another version or message, a non-ISO namespace, none) raises `MessageVersionMismatchError` and sends a negative receipt. No `variant` is sent, so none is compared. The default `ACCEPT_ANY` runs the same comparison but only logs a warning and returns the data | `ebics_orders_H005.xsd` `MessageType` (`version`: "usable for ISO20022 messages"); ISO 20022 schemas name the message identifier in their target namespace | live: all 29 versioned ZKB downloads saved on 2026-10-26 declare exactly the message and version their BTF requested (camt.052/053/054 at 04 and 08, pain.002 at 10). A strict client then downloaded the six versioned BTFs waiting at 04 (camt.052, camt.053, camt.054 `XQRR`/`XSCR`/`XDCI`/`XDDD`) with `KEEP` and accepted each one. The same bank bytes, checked as if version 08 had been requested, were each rejected. ZKB never substitutes a version (a version-08 request with only version-04 data waiting returns `090005`), so no bank-made mismatch exists to test against | live (acceptance at 04; rejection on bank bytes) |
| camt.054 variant BTFs `REP/CH/<option>/camt.054/08/ZIP`: `XDCI` one notification per booking, `XABK` collective debits, `XQRR`/`XSCR`/`XDDD` collective QRR / SCOR / LSV+ credits | ZKB HTD registry; ZKB order-type catalogue ([docs/10](10-btf-order-types.md)) | HTD + live: data downloaded under `XDCI` and `XABK` in version 08, and under `XQRR`, `XSCR`, `XDDD` in version 04 only. All five version-08 tuples are accepted (`090005` no data, while an unregistered option draws `091005`) | live (`XDCI`, `XABK` at 08; constants `CAMT_054_BOOKING_INFORMATION`, `CAMT_054_COLLECTIVE_DEBITS`) / live at 04 only (`XQRR`, `XSCR`, `XDDD`; no constants yet) |
| Single transactions of a booking: every `NtryDtls/TxDtls` of an entry, read as amount (in its own currency), `CdtDbtInd`, `Refs` (`AcctSvcrRef`, `MsgId`, `PmtInfId`, `InstrId`, `EndToEndId`), debtor and creditor name (version 08 through the `Party40Choice` `Pty` or `Agt/FinInstnId`, version 04 directly) and account IBAN, `RmtInf` (`Ustrd`; `Strd/CdtrRefInf` with `Tp/CdOrPrtry` `Cd` or `Prtry` and `Ref`; `Strd/AddtlRmtInf`). Reference types: `SCOR` (code), `QRR` and `ISR Reference` (proprietary) | ISO 20022 schemas camt.052/053/054 version 04 (`EntryDetails3`, `EntryTransaction4`, `TransactionParties3`) and 08 (`EntryDetails9`, `EntryTransaction10`, `TransactionParties6`, `Party40Choice`); `CreditorReferenceInformation2`; ZKB ISO 20022 handbook 1.12, section 10.7.3 (D-level, reference types) | live, version 04: two runs of [`tools/zkb-incoming-payments.py`](../tools/zkb-incoming-payments.py) on 2026-10-26 (`reconcile_transactions`). Each of the eight simulated payments (three QRR, two SCOR, one NON, two LSV+) came back as a single transaction with exactly the reference, reference type, amount, payer and remittance text sent, in camt.054 (`XQRR`, `XSCR`, `XDDD`, `XDCI`) and in camt.052 and camt.053. Live, version 08: the batch debit of a pain.001 uploaded over EBICS (camt.054 `XABK`, camt.052, camt.053) resolves into its accepted transactions with the message, payment, instruction and end-to-end IDs, amounts, creditor names and IBANs and remittance texts sent. Every fixture validates against the ISO schema of its version. An `Agt` party, an account without an IBAN and a `CdtrRefInf` without `Tp` or `Ref` are covered only by hand-written, schema-valid documents | live (versions 04 and 08) / XSD (`Agt`, non-IBAN account, partial `CdtrRefInf`) |
| Simulated-credit input `OTH/BIL/CH004TPS/csv` (ZKB test platform only; not library API) | ZKB test-platform manual 2.3.1 (CSV format), table 3 (BTF); HTD | live: uploaded over EBICS and processed — the platform's protocol reports the file correct, and the credits are booked | live (test tool) |
| **Letter: SHA-256 over certificate DER, uppercase; INI letter (A006) + HIA letter (X002, E002); certificates in PEM** | **Spec 4.4.1.2.3, 11.5.1, 11.5.2** | **spec-vector** (`test_spec_letter_vectors.py`) | spec-vector; **live activation pending** |
| Deterministic self-signed certificates; unlimited validity permitted | Swiss MPG EBICS 3.0, section 6.1 | determinism tests; bank acceptance of self-signed certs is live | live (acceptance) |
| `public_key_hash` (`e m`, lowercase, no leading zeros) for HPB out-of-band comparison and pinning | ZKB Bankparameterdaten publish this format | live (hashes match ZKB's published values) | live |
| `BankPubKeyDigests` content: we send the `e m` public-key digest | **Spec 5.5.1.1 says certificate-DER hash** | ZKB test platform accepts `e m` in every transaction | **live-on-test, spec-divergent — watch-item** ([docs/05](05-zkb-onboarding.md)); first suspect on `EBICS_BANK_PUBKEY_UPDATE_REQUIRED` |
| `EncryptionPubKeyDigest` = hash of the public RSA key | Spec ("In addition to the hash value of the public RSA key…") | live (uploads accepted) | live |
| Dated download: BTD `DateRange` (Start, End; both inclusive ISO dates; after `Service`, before `Parameter`) | Spec 5.6.1; `ebics_orders_H005.xsd` `BTDParamsType`/`DateRangeType` | XSD (`test_dated_download_initialisation_request_validates`) + live (ZKB test platform accepted the element: dated `EOP/camt.053` returned `090005 no-data`, not a format rejection) | live |
| Negative receipt (`ReceiptCode` 1) leaves data un-consumed; acknowledge only after decrypt/validate | Spec 5.6.1.2.2 (positive=0 marks downloaded, negative=1 does not) | XSD (both polarities validate) + spec + tests | spec — mandated behaviour; implementing to spec is the bar (not a per-bank confirmation) |
| Non-consuming `KEEP` read (deliberate negative ack) | Spec 5.6.1.2.2 negative acknowledgement | XSD + spec | spec |
| Bank **re-serves already-delivered data** for a past `DateRange` | **Bank-dependent** — the spec does not guarantee it | none (test platform has no data to re-serve) | **bank-dependent (per spec)** — not a verification gap; never assumed, surfaced to callers |
| Bank **honours** the `DateRange` filter (vs. accepting yet ignoring it) | **Bank-dependent** | strict client-side out-of-range check (`DateRangeMismatchError`) guards against silent ignore | bank-dependent (per spec); the library fails closed if a bank ignores it |
| HPB response: `X509Data` mandatory, `X509Certificate` optional within it → bare-key fallback | ebics_types_H005.xsd `PubKeyInfoType`; xmldsig schema | XSD | XSD |
| Bank keys ≥ 2048 bits rejected otherwise | Spec 4.7 (key-length increase) | unit tests | XSD/spec-cited |
| HPD and HKD are admin downloads with empty `StandardOrderParams` (like HAA/HTD) | Spec 9.2, 9.2.1, 9.3, 9.3.1 ("does not contain specific data beyond the general transaction description"); `StaticHeaderOrderDetailsType` | XSD (`test_admin_download_request_validates`) + live (ZKB served both) | live |
| HPD order data: `HPDResponseOrderData` = `AccessParams` (URL+, Institute, HostID?) + `ProtocolParams` (Version lists; optional Recovery, PreValidation, ClientDataDownload, DownloadableOrderData) | Spec 9.2.2; `HPDResponseOrderDataType` (ebics_orders_H005.xsd). The spec's table still lists `X509Data`, deleted from the XSD by the 3.0 amendments (amendment history, schema change 11) — the XSD wins | XSD (the real ZKB response validates; sanitized fixture `hpd_zkb_sample.xml`) + live | live |
| HPD support flags: parameter omitted ⇒ not supported; present without `@supported` ⇒ supported | Spec 9.2 (standard procedure for optional protocol parameters); `OptSupportFlag` default `true` | spec + tests; live (ZKB sends explicit flags) | spec |
| HKD order data: `HKDResponseOrderData` = `PartnerInfo` (AddressInfo, BankInfo/HostID, AccountInfo*, OrderInfo+) + `UserInfo`+ (UserID@Status, Name?, Permission+) | Spec 9.3.2; `HKDResponseOrderDataType`, `PartnerInfoType`, `UserInfoType` | XSD (the real ZKB response validates; sanitized fixture `hkd_zkb_sample.xml`) + live | live |
| HKD/HTD `AccountInfo`: account numbers (IBAN / national / free format), bank codes, `Currency` default EUR, holder | `AccountType` (ebics_types_H005.xsd); spec 9.3.2.1.3 | XSD (hand-written, schema-validated fixture `hkd_accounts_example.xml`) — **not live**: the ZKB test subscriber has no accounts in HKD/HTD | XSD |
| `UsageOrderTypes`: absent ⇒ account unrestricted; empty ⇒ enabled for no BTF; else the permitted BTFs | Spec 9.3.2.1.3. The XSD annotation of `UsageOrderType` says "unsupported" BTFs, contradicting both the spec and the `AccountInfo` annotation — the spec text is followed | spec (not live: no accounts on the test platform) | spec |
| Permission attributes: `AuthorisationLevel` ∈ {E, A, B, T}, `AccountID`, `MaxAmount` (`Currency` default EUR) | `UserPermissionType`, `AuthorisationLevelType`, `AmountType`; spec 9.3.2.1.3 | live (ZKB sends E on BTU, T on key management); AccountID/MaxAmount XSD-only | live (level) / XSD (account, amount) |
| PUB, HCA, HCS are regular upload transactions: `AdminOrderType` + empty `StandardOrderParams`, body with `DataEncryptionInfo`, `SignatureData`, `DataDigest` | Spec 4.6.1.1; `StaticHeaderOrderDetailsType` (OrderParams mandatory) | XSD (`test_key_change_initialisation_request_validates`, fully valid — no SignatureFlag) + live | live |
| Key-change order data: PUB = `SignaturePubKeyOrderData` (S002, as INI); HCA = `HCARequestOrderData`; HCS = `HCSRequestOrderData` (auth, enc, `esig:SignaturePubKeyInfo`, PartnerID, UserID); keys as X.509 certificates | Spec 4.6.1.2, 4.2; ebics_orders_H005.xsd, ebics_signature_S002.xsd | XSD (`test_key_change_order_data_validates`) + live | live |
| A key change is signed (exactly one ES) with the **current** A006 and authenticated with the **current** X002; no letter | Spec 4.6.1 (incl. "the subscriber's old bank-technical key … is used for this ES"), 4.6.1.1 | live: each change accepted, and the following order succeeded only with the new keys (PUB → HCS signed with the new A006; HCS → HPB/HTD with the new X002/E002; HCA → HTD/HPD/HKD) | live |
| Key changes are processed synchronously: the response to the last segment is the outcome, and the new keys are valid immediately afterwards | Spec 4.3, 5.1.3.1 | live (the next request with the new keys succeeded at once); the client's "unconfirmed" path (`KeyChangeUnconfirmedError`) rests on this | live (immediate validity) / spec (outcome rule) |
| Key-management return codes `0912xx`, `091301`, `090004`, `091003`, `091004`, `091008` | Annex 1 (codes and names); spec 4.6.1.1 (which apply to PUB/HCA/HCS) | `091301` observed live; the rest spec | spec |
| A key must not serve two roles (`EBICS_KEYMGMT_DUPLICATE_KEY`) — refused client-side | Annex 1 (091218) | tests | spec |
| H005-only; no H004 and earlier | Owner decision ([docs/04](04-implementation-plan.md)) | n/a | n/a |

## 2.5→3.0 amendment audit (2026-07-22)

Walked the spec's amendment-history table against the codebase. Findings: the letter-hash
flaw (fixed, 1.4.0), the `BankPubKeyDigests` divergence (watch-item above), and one
comment upgraded from folklore to an XSD citation (HPB bare-key fallback). Everything else
was either already conformant, validated live, or out of scope (FTAM, A004, HAC, H3K —
H3K is explicitly unsupported in Switzerland per Swiss MPG 6.1).
