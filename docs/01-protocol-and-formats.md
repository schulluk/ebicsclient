# EBICS protocol & message formats

## What EBICS is

EBICS (Electronic Banking Internet Communication Standard) is a formal, versioned standard for
client↔bank financial communication over HTTPS, governed by ebics.org and (in CH) profiled by SIX.
Requests/responses are signed/encrypted XML. It is **stable** — versions bump roughly once a decade —
which is exactly why a scoped client is low-maintenance.

- Protocol version we target: **EBICS 3.0**, whose XML schema namespace is **H005**.
- Endpoint (ZKB): `https://ebicsweb.zkb.ch/ebicsweb`

## The two regulatory deadlines driving this (don't confuse them)

1. **EBICS protocol version → ~November 2025.** The pre-3.0 protocol (2.5 / H004) is retired/restricted.
   → We must use **EBICS 3.0 (H005)**. ZKB explicitly recommends H005.
2. **ISO 20022 message format → 21 November 2026.** Since Nov 2022 the Swiss centre ran *two* parallel
   message vintages: **"2009"** (e.g. camt.053.001.**04**, pain.001.001.03) and **"2019"**
   (camt.053.001.**08**, pain.001.001.09). The **2009 vintage is switched off 21 Nov 2026**, in lockstep
   with SEPA/SWIFT. → We must use the **2019 vintage = camt.053.001.08**.

The two are linked: the 2019 messages are generally only available over EBICS 3.0, which is why ZKB
pushes H005. Targeting **H005 + camt.053.001.08** clears both deadlines at once.

## Keys & crypto (EBICS three-key model)

A subscriber holds three RSA key pairs:

| Key | Purpose | EBICS version id |
|---|---|---|
| Signature | Bank-technical / electronic signature (used at INI; signs order data on upload) | **A005** (RSASSA-PKCS1-v1.5) or **A006** (RSASSA-PSS) |
| Authentication | Identification & authentication signature on every request | **X002** |
| Encryption | Encrypts/decrypts order data | **E002** |

- **Auth signature** (`AuthSignature` in each `ebicsRequest`): XML-DSig over nodes with
  `authenticate="true"`, **exclusive C14N (exc-c14n)**, SHA-256 digest, RSA-SHA256 with X002.
- **Order-data encryption**: payload is deflate-compressed → AES-128-CBC encrypted with a random
  *transaction key* → that transaction key is RSA-encrypted to the E002 key. For **download** you
  receive order data encrypted to *your* E002 public key; decrypt the transaction key with your E002
  private key, AES-decrypt, then inflate. Order data is base64 inside `<OrderData>`.

ZKB profile: use **plain keys** ("mit Schlüsseln", confirmed fine for download-only) rather than X.509
certificates ("mit Zertifikaten"); profile **T** (no distributed signature needed since we only download).

## Order types vs BTF (the EBICS 3.0 change)

In 3.0, *business* transactions are identified by **BTF (Business Transaction Format)** descriptors
instead of the old 3-letter order types. **Key-management** order types stay classic:
`INI`, `HIA`, `HPB`, `HCA`, `HCS`, `PUB`, `SPR`, `HPD`, `HKD`, `HTD`, `PTK`.

The one BTF we need (statement download):

| BTF field | Value |
|---|---|
| Service Name | `EOP` (end of period — account statement) |
| Scope | `CH` |
| Container | `ZIP` |
| Message Name | `camt.053` |
| Message Version | `08` |

(Intraday = `STM`/`camt.052`/`08`; detail/notifications = `REP`/`camt.054`/`08`. Ignore every `_04`
variant and the legacy `STA`/`VMK`/MT940/`Z5x` order types — those are the dying 2009/MT formats.)

## Transaction phases (download)

1. **Initialization** — send `ebicsRequest` with the download BTF; bank returns a transaction id,
   number of segments, and the (encrypted) order data / transaction key.
2. **Transfer** — pull each segment (`segmentNumber`), reassemble.
3. **Receipt** — acknowledge (positive/negative) so the bank can mark the order delivered.

## camt.053.001.08 parsing

camt.053 is plain XML. For net-worth tracking the key field is the **closing booked balance**
(`Bal` with `Cd=CLBD`) per account (`Acct/Id/IBAN`), plus optionally the entries (`Ntry`) for a
transaction list. Parsing is trivial relative to the protocol; can be hand-rolled with `lxml`.

## Reference specs

- SIX — EBICS 3.0 (CH profile): https://www.six-group.com/dam/download/banking-services/interbank-clearing/de/standardization/ebics/ebics_3_0.pdf
- EBICS H005 XML schemas: https://www.ebics.de/de/ebics-standard/ebics-schema
- SIX — ISO 20022 Swiss Payment Standards: https://www.six-group.com/en/products-services/banking-services/payment-standardization/standards/iso-20022.html
- ZKB EBICS info: https://www.zkb.ch/de/hilfe/skf/ebics-anbindungen-zkb.html
- ZKB ISO 20022 test platform: https://testplattform.zkb.ch
