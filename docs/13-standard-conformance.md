# EBICS 3.0 (H005) coverage & gaps

An honest overview of what this library **supports today** and what it **does not yet do**,
measured against the EBICS 3.0 (H005) standard. Gaps are shown on purpose: this page doubles
as the backlog for deciding what to build next. "Not implemented" here means exactly that —
absent, not excluded — unless the **Notes** say otherwise.

> This is the at-a-glance map. The per-claim spec citations and oracles behind each *supported*
> row live in the [verification ledger](12-verification-ledger.md).

## In numbers

Counted over the capability rows of this page on 2026-10-28, the deliberately excluded H004
row aside; "implemented" is a ✅ row, "partial" a 🟡 row. Update the counts when rows change.

| Area | Rows | Implemented | Partial | Missing | Implemented share |
|---|---|---|---|---|---|
| Key ceremony & key management | 17 | 13 | 1 | 3 | 76 % |
| Request header | 3 | 1 | 0 | 2 | 33 % |
| **Read — downloads** | 28 | 24 | 3 | 1 | **86 %** |
| **Write — uploads** | 13 | 9 | 2 | 2 | **69 %** |
| **EDS / VEU** | 7 | 0 | 0 | 7 | **0 %** |
| **All** | **68** | **47** | **6** | **15** | **69 %** |

By order type: 15 of the 22 administrative order types of H005 (spec chapter 13) are
implemented. Missing are H3K and the six EDS order types (HVU, HVZ, HVD, HVT, HVE, HVS).

Every behaviour the standard requires unconditionally is implemented, five of them in part:
the upper key-length bounds, the abort on a response that fails verification, the bank's
segment signals in a download, the SEPA BTF `SCT` (experimental) and pain.008 (through a
custom BTF, without a typed helper). Everything missing is optional in the standard (the
EDS family, H3K, `SystemID`, `Product`, `Parameter`, `PreValidation`, `AdditionalOrderInfo`),
left to the bank (A005), or a recommendation (a certified key store). EDS is blocked on a
test environment with several required signatures, not on a design decision; the EDS
section below says what would unblock it.

## Legend

- **Support** — ✅ implemented · 🟡 partial (see Notes) · ❌ not implemented.
- **Rule** — **Mandated** (the standard defines the behaviour), **Bank-dependent** (the
  standard leaves the outcome to the financial institution) or **Recommended** (an annex
  advises it without imposing it).
- **Verification** (supported rows only) — the strongest oracle passed; blank for
  unimplemented rows:
  - **live** — validated in a real bank exchange.
  - **spec-vector** — matches a published spec example.
  - **XSD** — validates against the H005 schema.
  - **spec** — implemented to cited spec text (the right bar for mandated behaviour with no
    live/vector oracle available).
  - **tests** — unit-tested library behaviour.
- **Notes** — workaround, why it matters, or what blocks it.

## Key ceremony & key management

| Capability | Rule | Support | Verification | Notes |
|---|---|---|---|---|
| INI — submit A006 signature key | Mandated | ✅ | live | |
| HIA — submit X002 + E002 keys | Mandated | ✅ | live | |
| HPB — download the bank's public keys | Mandated | ✅ | live | |
| X.509 key transport — self-signed (*mit Schlüsseln*) | Mandated | ✅ | live | |
| X.509 key transport — CA-issued (*mit Zertifikaten*) | Mandated | ✅ | XSD | |
| Initialisation letters (INI + HIA), SHA-256 certificate-DER hash | Mandated | ✅ | spec-vector | |
| HPB key trust via published hash / pinning | Bank-dependent | ✅ | live | Published hashes are out-of-band per bank (spec 4.4.2.1, 4.6.2), in one of two forms: the public-key (`e m`) hash, or the SHA-256 over the bank certificate in DER form, which is what EBICS 3.0 means by a key's hash value (spec 5.5.1.1.1). `Client.hpb(pinned=…)` accepts a value in either form; a key delivered without a certificate matches the public-key form only. `bank_key_hashes()` returns the public-key form. ZKB publishes both for the same key, and an HPB pinned to each form has been accepted (the public-key hash since the first HPB, the certificate hash on 2026-10-28) — see the [ledger](12-verification-ledger.md) |
| Bank-key currency check in every request — `BankPubKeyDigests` | Mandated | ✅ | live | Each bank key is named by the SHA-256 over the certificate HPB delivered for it (spec 5.5.1.1.1, 5.6.1.1.1); `BankKeys` keeps those certificates. A key a bank still delivers without a certificate, carried over from EBICS 2.x, is named by its public-key hash (spec 11.3.2.2), tested offline only. Until 2026-10-27 the public-key hash was sent for every key; the ZKB test platform accepts both forms — see the [ledger](12-verification-ledger.md) |
| Bank certificate chain validation (`TrustAnchorVerifier`) | Bank-dependent | ✅ | spec | Only when a bank mandates a CA |
| PUB — change the bank-technical (signature) key | Mandated | ✅ | live | `change_keys(…, KeyRotation.SIGNATURE)`, no letter. The client adopts the new keys only after the bank confirms; an unknown outcome raises `KeyChangeUnconfirmedError` (keep both keyrings). Persisting is the caller's: `rotate_keyring` + the atomic `save_keyring` |
| HCA — change the authentication + encryption keys | Mandated | ✅ | live | `change_keys(…, KeyRotation.AUTHENTICATION_AND_ENCRYPTION)` (see PUB) |
| HCS — change all three subscriber keys at once | Mandated | ✅ | live | `change_keys(…, KeyRotation.ALL)` (see PUB) |
| SPR — suspend / lock the subscriber's access | Mandated | ✅ | live | `suspend_access()`, e.g. on suspected key compromise (spec 4.5.1). ZKB suspended the test subscriber at once and returned an order ID; INI and HIA with new keys then brought it back without a reset. A lost answer leaves the outcome open and is not repeated automatically; a refused repeat (`061001` at ZKB) does not prove the first one worked |
| Key lengths within the spec's bounds: 2048 to 4096 bits for the A006 key, 2048 bits to 16 Kbit for X002, E002 and the bank's keys | Mandated | 🟡 | tests | The lower bound is enforced: `generate_keyring` and `rotate_keyring` refuse a size below 2048 bits, and HPB refuses a shorter bank key. No upper bound is checked. One `key_size` applies to all three keys, so a size above 4096 bits yields a signature key outside the A006 range (spec 14.1); X002 and E002 may have up to 16 Kbit (spec 4.7, 11.1.1, 11.3.2.1), and a longer bank key is accepted. The default, 2048 bits, is within every bound |
| A005 electronic signature (RSASSA-PKCS1-v1_5) | Bank-dependent | ❌ | | The client signs with A006 only. A bank must support A005 or A006 (spec 11.2.1), so a bank that offers A005 alone cannot be used. ZKB and PostFinance both offer A006 |
| Private keys in a certified key store, such as a PKCS#11 token or an HSM | Recommended | ❌ | | The TLS and KMS annex of 2026-03-20 asks for certified keys or certified key stores, for instance through PKCS#11, at least for keys that give authorising signatures: an ES of class E, A or B, and EDS. For EBICS 2.x and 3.x it recommends this without imposing it; with EBICS 4.0 it is planned to become mandatory. The library holds the three private keys in process memory and stores them in the passphrase-encrypted keyring file (`save_keyring`); it has no PKCS#11 or HSM integration. `CertificateProvider` can draw certificates from such a store, but not the private keys |
| H3K — one-step CA-certificate initialisation | Mandated (optional) | ❌ | | CA profile only; not a priority |

## Request header

| Capability | Rule | Support | Verification | Notes |
|---|---|---|---|---|
| Technical subscriber — `SystemID` (multi-user customer system) | Mandated (optional) | ❌ | | A customer system that serves several subscribers through one server acts as a technical subscriber: it puts its own ID in `SystemID` and signs each request's `AuthSignature` with its own key (spec 3.7). `SystemID` must be present in such a multi-user system (spec 5.5.1.1.1, 5.6.1.1.1). Not implemented: every subscriber authenticates with its own X002 key, as in a single-user system, and `SystemID` is never sent. HAC reports a `SystemID` the bank logged (`system_id`) |
| `Product` — the customer software, named in the request header | Mandated (optional) | ❌ | | Optional information on the customer product (spec 5.5.1.1.1, 5.6.1.1.1); never sent |
| Identifiers and BTF components checked against the schema's types before a request is built | Mandated | ✅ | XSD + tests | The Partner and User IDs must match `[a-zA-Z0-9,=]{1,35}` (`PartnerIDType`, `UserIDType`; spec 12.4), the Host ID is an XML token of at most 35 characters (`HostIDType`), and a `BusinessTransactionFormat` takes only values of `ServiceNameStringType`, `ScopeStringType`, `ServiceOptionStringType`, `MessageNameStringType`, `NumStringType` and `ContainerStringType` (`ebics_types_H005.xsd`). A value outside them raises `ValueError` naming the rule; a bank registry entry (HAA, HTD, HKD) outside the schema is a `ProtocolError` |

## Read — downloads

| Capability | Rule | Support | Verification | Notes |
|---|---|---|---|---|
| BTD download transaction (initialise → transfer → receipt) | Mandated | ✅ | live | |
| Order-data decryption (RSA-unwrap + AES-128-CBC + inflate) | Mandated | ✅ | live | |
| Response `AuthSignature` verification on every response | Mandated | ✅ | live | |
| ↳ a response that fails verification ends the transaction | Mandated | 🟡 | | If the response's `AuthSignature` cannot be verified, the customer system MUST abort the transaction (spec 3.8). The client never uses such a response, but it treats it as a lost answer and repeats the step, after the initialisation, in downloads, uploads and key changes alike. It raises once the transaction's `recovery_attempts` (default 2) are spent. `Client(recovery_attempts=0)` aborts at once |
| Fail-closed on every return code; unknown codes never masked | Mandated | ✅ | live | |
| Multi-segment order data | Mandated | ✅ | live | |
| ↳ the bank's segment signals: an early `lastSegment`, a segment above 1 MB | Mandated (SHOULD) | 🟡 | | Spec 7.2 leaves these irregularities in a download to the client. The client requests exactly the `NumSegments` the initialisation announced and ignores `lastSegment`: if the bank marks an earlier segment as the last one, the client still requests the rest, where it SHOULD continue with the receipt. A segment above 1 MB is accepted, where the client SHOULD end the transaction |
| Positive receipt (consume) / negative receipt (keep) | Mandated | ✅ | live / XSD+spec | |
| ↳ the bank's answer checked against the receipt sent | Mandated | ✅ | live | The bank answers a positive receipt with `011000` `EBICS_DOWNLOAD_POSTPROCESS_DONE` and a negative one with `011001` `EBICS_DOWNLOAD_POSTPROCESS_SKIPPED` (spec 5.6.1.2.2; Annex 1); `000000` passes after either. The other code raises `ReceiptMismatchError`: `011001` after a positive receipt (the data was left undelivered, so it may come again) fails the download, and `011000` after the negative receipt of a `KEEP` read (the data was consumed although declined) fails the read; after a failed validation the validation error carries the mismatch as a note. ZKB and PostFinance both answer `011000` to a positive and `011001` to a negative receipt (HAC with `ACKNOWLEDGE` and with `KEEP`, live 2026-10-28) |
| Acknowledge only after decrypt+validate (no consume-on-error) | Mandated | ✅ | spec + tests | |
| Non-consuming read (`ReceiptPolicy.KEEP`) | Mandated | ✅ | XSD + spec | Deliberate negative ack |
| Fetch statements/reports for a specific date range — BTD `DateRange` (inclusive) | Mandated | ✅ | live | The library sends the range; out-of-range data fails closed (`DateRangeMismatchError`), never returned as a match |
| ↳ the bank actually applying that range, and re-serving already-delivered data | Bank-dependent | 🟡 | | Not guaranteed by the standard; confirm per bank before relying on a dated re-download |
| Delivered message version checked against the BTF `version` (opt-in `VersionPolicy.STRICT`) | Mandated | ✅ | live | Under `STRICT`, a document of another message or version fails closed (`MessageVersionMismatchError`, negative receipt). The default `ACCEPT_ANY` returns what the bank delivered and logs a warning on a mismatch. ZKB never substitutes a version: a request for a version with no data waiting returns `090005` |
| Generic order parameters — `Parameter` Name/Value pairs | Mandated (optional) | ❌ | | Bank-specific query params alongside `DateRange`; not exposed (a custom BTF still works) |
| Arbitrary business download via a custom BTF | Mandated | ✅ | live | Any `BusinessTransactionFormat`, raw bytes returned |
| camt.053 EOD statements — typed parser | Mandated (ISO) | ✅ | live | |
| camt.052 intraday reports — typed parser | Mandated (ISO) | ✅ | live | Read from ZKB reports delivered over EBICS, in camt.052.001.08 and .04 |
| camt.054 booking advices (incl. QRR/SCOR/LSV) — typed parser | Mandated (ISO) | ✅ | live | Read from ZKB advices delivered over EBICS. Simulated QRR, SCOR, LSV+ and unreferenced credits appear with their exact totals ([`tools/zkb-incoming-payments.py`](../tools/zkb-incoming-payments.py)). Variant BTFs: `CAMT_054_BOOKING_INFORMATION` (`XDCI`), `CAMT_054_COLLECTIVE_DEBITS` (`XABK`); the QRR/SCOR/LSV+ variants (`XQRR`/`XSCR`/`XDDD`) have so far delivered data only in version 04 — see [docs/09](09-zkb-test-platform-settings.md) |
| ↳ single transactions of a booking (`NtryDtls/TxDtls`: references, payer and payee, QR or creditor reference, remittance information) | Mandated (ISO) | ✅ | live | `Entry.transactions` (`TransactionDetails`), filled by the camt.052, camt.053 and camt.054 parsers in versions 04 and 08. Read live from simulated QRR, SCOR, LSV+ and unreferenced credits (version 04) and from the batch debit of an uploaded pain.001 (version 08): every reference, amount, name and remittance text matched what was sent. A collective QR-bill credit can thus be matched to its invoices. Fields the bank omits are `None` or empty |
| pain.002 payment status reports — typed parser | Mandated (ISO) | ✅ | live | Read from ZKB reports delivered over EBICS (`ACTC`, then `PART` with rejected transactions) and from PostFinance reports (`ACCP` per payment block). The two banks register the download BTF without and with the ZIP container — `PAIN_002` (ZKB) and `PAIN_002_ZIP` (PostFinance), either passed to `download_payment_status_reports()` |
| HAA — order types with data available | Mandated | ✅ | live | |
| HTD — *this subscriber's* data & permissions | Mandated | ✅ | live | |
| HKD — *customer + all subscribers'* data | Mandated | ✅ | live | `customer_info()`; accounts and account-bound permissions are XSD-only (the test subscriber has none) |
| HPD — bank parameters (versions, optional features) | Mandated | ✅ | live | `bank_parameters()` |
| HAC — customer acknowledgement, the bank's log of EBICS actions (pain.002 form) | Mandated | ✅ | live | `customer_acknowledgement()` returns a `CustomerAcknowledgement`: one entry per protocol step, with the type of action, the ISO reason code, the order, its BTF and the timestamp (spec 10). Parsed before the receipt; `ACKNOWLEDGE` marks the log fetched, `KEEP` leaves it. Read live from ZKB, which logs the verification of each order's signature (`DS01`, or a rejection such as `TD03`) |
| HEV — supported EBICS versions (unsecured discovery) | Mandated | ✅ | live | `supported_versions()` returns `EbicsVersion` items. It needs no keys, so it works before INI. The answer is not signed (TLS only). ZKB answers an unknown Host ID with HTTP 404 instead of a return code |
| Transaction recovery / resumption after an interrupted transfer | Mandated (optional) | ✅ | live | A step whose answer was lost is sent again in the same transaction, and a recovery point the bank names (`EBICS_TX_RECOVERY_SYNC`) is followed; `Client(recovery_attempts=…)`, default 2, `0` turns it off. Live on ZKB for uploads, including a lost answer to the final segment (confirmed, booked once). Multi-segment download recovery is tested offline only, because ZKB's test downloads fit one segment. The initialisation is not recovered (no transaction ID yet; nothing is consumed or ordered by it). A positive receipt whose answer stays lost still raises: ZKB answers a resent receipt with `EBICS_TX_UNKNOWN_TXID`, so the data may be consumed although the call failed |

## Write — uploads

| Capability | Rule | Support | Verification | Notes |
|---|---|---|---|---|
| BTU upload transaction (initialise → transfer) | Mandated | ✅ | live | |
| ↳ outcome of the final segment: definite only with a verified answer | Mandated | ✅ | spec + tests | The order exists once the exchange returned `000000` (spec 5.1.3.1). Without a verified answer to the last segment, `upload()` raises `UploadUnconfirmedError` instead of a retryable error, so a payment is never sent twice by a retry. Recovery (see below) resends the final segment first; a `000000` then confirms the order |
| A006 electronic signature (RSASSA-PSS) | Mandated | ✅ | live | Verified by the bank since 2026-10-26 (PUB/HCS/HCA, checked synchronously). Before that the signature had the wrong shape, and BTU acceptance had not exposed it — see the [ledger](12-verification-ledger.md), incident 3 |
| Order-data encryption to the bank's E002 | Mandated | ✅ | live | |
| ↳ `EncryptionPubKeyDigest` naming the bank's E002 key | Mandated | ✅ | live | The same digest as in `BankPubKeyDigests`: the SHA-256 over the E002 certificate's DER (spec 11.3.2.2), or the public-key hash for a bare key. Live with the public-key hash on every upload until 2026-10-27, and with the certificate form in a pain.001 upload on 2026-10-28 |
| `SignatureFlag` on BTU order params | Mandated | ✅ | XSD + live | Sent as the empty element the schema defines (`SignatureFlagType` restricts `FlagAttribType`): its presence says the order carries the ES. Until 2026-10-28 the client sent the text `true`, which ZKB and PostFinance accepted but the schema rejects. The empty form was processed by both on 2026-10-28: ES verified (`DS01` in HAC), pain.002 delivered |
| Arbitrary business upload via a custom BTF | Mandated | ✅ | live | Any `BusinessTransactionFormat` |
| pain.001 credit transfer submission | Mandated (ISO) | ✅ | live | |
| ↳ in the original ISO schema (CGI), BTF `MCT / CGI / XCH` | Mandated (ISO) | ✅ | live | `PAIN_001_CGI`. Processed by the ZKB test platform for SEPA payments; it rejects foreign-currency payments in this schema |
| ↳ through the SEPA BTF `SCT` | Mandated (ISO) | 🟡 | HTD + XSD | Experimental: `ebicsclient.experimental.PAIN_001_SEPA`. The ZKB test platform accepts such uploads with `000000`, then rejects the file in its signature check with `TD03` "file format incomplete or invalid" (seen in HAC) and never processes it, so the BTF cannot be validated there. The platform's manual assigns this order type the German DK schema (`pain.001.003.xx`) rather than the ISO `pain.001.001.09` sent, the likely reason; a DK file has not been tried. At ZKB, SEPA payments go through `PAIN_001` or `PAIN_001_CGI` |
| pain.008 direct-debit submission | Mandated (ISO) | 🟡 | | Works via a custom BTF; no typed helper |
| Pre-validation before submission — `PreValidation` (account authorisations / amounts) | Mandated (optional) | ❌ | | Optional bank pre-check sent with the order; not implemented. The ZKB test platform does not offer it (HPD `PreValidation supported="false"`), so it cannot be validated there |
| Generic order parameters + `AdditionalOrderInfo` (free-text note ≤255 chars) | Mandated (optional) | ❌ | | Bank-specific Name/Value params and an unstructured order note; not exposed |

## Distributed electronic signatures (EDS / VEU) — multi-person approval

EDS (formerly VEU) is EBICS's workflow for orders that require **several people to sign before
the bank executes them** — dual-control on payments. The entire family is **unimplemented**:
today an order can only be uploaded with all required signatures inside a single request, or
authorised outside EBICS.

Validating EDS needs a subscriber that requires several signatures, and no reachable test
environment offers one: the ZKB and PostFinance test platforms each run a single user with
signature class `E` and `NumSigRequired` `0` (ZKB's support confirmed it has no other way to
test EDS; for PostFinance see [docs/14](14-postfinance-test-platform.md)), and the library
ships only what a bank has accepted. **Help wanted: if you can provide access to an EBICS
test environment with multiple required signatures**, whether a bank test platform, a
vendor's demo server or a production contract willing to test, please open an
[issue](https://github.com/schulluk/ebicsclient/issues) or write to the maintainer via
[ebicsclient.ch](https://ebicsclient.ch). With such access the order types
below will be implemented and validated.

| Order type | Rule | Support | Notes |
|---|---|---|---|
| HVU / HVZ — download the EDS overview (pending orders), plain / with detail | Mandated (optional) | ❌ | |
| HVD — download an order's details for review | Mandated (optional) | ❌ | |
| HVT — download an order's transaction data | Mandated (optional) | ❌ | |
| HVE — add an electronic signature to a pending order | Mandated (optional) | ❌ | |
| HVS — cancel a pending order | Mandated (optional) | ❌ | |
| BTU `SignatureFlag@requestEDS` — hand an order that lacks signatures to the EDS | Mandated (optional) | ❌ | With the attribute, an upload whose signatures do not suffice waits in the EDS for more, added with HVE; without it, the bank rejects the order (spec 3.12, 3.14). Never sent |
| Validate the full quorum workflow | Mandated (optional) | ❌ | Not built; validating it needs a bank profile with several required signatures (no such test setup yet) |

## Out of scope (deliberate)

| Item | Support | Notes |
|---|---|---|
| Legacy EBICS H004 and earlier | ❌ | Owner decision ([docs/04](04-implementation-plan.md)); this client is H005-only |

## The principle behind the verification column

For **mandated** behaviour, the standard is the contract: we implement to the cited spec/XSD
and treat that as sufficient — chasing per-bank confirmation of standard behaviour never ends
(one bank, then the next, then the next…). For **bank-dependent** behaviour, the standard
declines to guarantee the outcome, so the library never assumes it and the row is marked 🟡 —
surfaced to callers (and, for `DateRange`, guarded so we fail closed if a bank ignores it),
not a gap to be "closed" by testing one more bank.
