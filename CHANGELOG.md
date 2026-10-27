# Changelog

All notable changes to ebicsclient, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Each version is published to
[PyPI](https://pypi.org/project/ebicsclient/) from its `v*` tag. Versions 1.0.0 to 1.2.x
and 1.3.1 were never published.

## [Unreleased]

### Added

- `VersionPolicy`: with `Client(..., version_policy=VersionPolicy.STRICT)`, the client
  compares the message name and version each delivered ISO 20022 document declares with
  the requested BTF before the receipt. A mismatch raises `MessageVersionMismatchError` and
  sends a negative receipt, so the data stays at the bank. The default,
  `VersionPolicy.ACCEPT_ANY`, logs a mismatch as a warning and returns the data.
- BTF constants `CAMT_054_BOOKING_INFORMATION` and `CAMT_054_COLLECTIVE_DEBITS`.
- BTF constant `PAIN_001_CGI` (`MCT / CGI / XCH / pain.001 / 09`) for payments in the
  original ISO 20022 schema. A SEPA payment uploaded under it was processed live by the
  ZKB test platform, which accepts only SEPA payments in this schema.
- `ebicsclient.experimental`, a module for features that are implemented but not yet
  validated against a bank. Nothing in it is exported from `ebicsclient`, and it may change
  without a deprecation period. Its first item is `PAIN_001_SEPA`
  (`SCT / pain.001 / 09`): the tuple matches ZKB's registry, but the ZKB test platform
  accepts uploads under it without ever processing them.
- `Entry.transactions` lists the single transactions behind a booking entry
  (`NtryDtls/TxDtls`) as `TransactionDetails`: the amount, the references (message,
  payment, instruction and end-to-end IDs, and the bank's own), the payer's and payee's
  names and IBANs, the structured creditor references (`CreditorReference`, such as a QR,
  SCOR or LSV+ reference) and the remittance information. A collective booking, such as a
  day's QR-bill credits, can now be matched to its invoices. The camt.052, camt.053 and
  camt.054 parsers fill it for message versions 04 and 08. It was validated live against
  the ZKB test platform, except for a party that is a bank and an account without an IBAN,
  which are checked against the ISO 20022 schema only.
- `Client.supported_versions()` (HEV) asks the bank which EBICS versions it supports and
  returns them as `EbicsVersion` items (protocol version and release, such as `H005`
  and `03.00`). It needs no keys, so it works before INI and HIA, for example to check
  that a bank offers EBICS 3.0. The bank does not sign this answer. Validated live
  against the ZKB test platform.
- Transaction recovery (EBICS 3.0 spec 5.4): when the answer to an upload segment, a
  download segment or a receipt is lost or cannot be verified, the client sends that step
  again in the same transaction and follows the recovery point the bank names
  (`EBICS_TX_RECOVERY_SYNC`). A repeated step stays in its transaction, so the bank never
  takes an order twice. An upload whose final answer was lost is now confirmed when the
  resent segment is accepted, instead of raising `UploadUnconfirmedError`.
  `Client(recovery_attempts=…)` limits the repetitions per transaction (default 2; `0`
  turns recovery off). Validated live against the ZKB test platform for uploads; download
  recovery of several segments is tested offline only.
- `Client.suspend_access()` sends SPR, which suspends the subscriber at the bank, for
  example when a key may be compromised, and returns the bank's order ID. Sending orders
  again then needs a new initialisation with new keys. Validated live against the ZKB test
  platform: the subscriber was suspended at once, and INI and HIA with new keys brought it
  back.
- `Client.customer_acknowledgement()` downloads HAC, the bank's log of the customer's EBICS
  actions since the last download, as a `CustomerAcknowledgement`. Each
  `AcknowledgementEntry` gives the type of action (`AcknowledgementAction`), the ISO reason
  code, the order, its BTF and the timestamp, so it shows, for example, whether the bank
  verified an order's signature. The log is parsed before the receipt; `ReceiptPolicy.KEEP`
  leaves it at the bank. Validated live against the ZKB test platform.
- Python 3.15 is now supported and tested in CI, like 3.11 to 3.14.

### Changed

- A download fails closed with `ProtocolError` when the bank answers a segment request with
  another segment than the one requested, or sends different data for a segment the second
  time.

### Fixed

- **An upload whose last answer was lost looked safe to repeat.** If the connection failed
  after the final segment had been sent, `upload()` raised the transport's
  `TransportError`, marked `TRANSIENT` ("safe to retry"), although the bank may already
  hold the order. A caller that retried could submit a payment twice. `upload()` now raises
  `UploadUnconfirmedError` (marked `PERMANENT`, the original error chained) when the final
  segment was sent without a verified answer: a lost connection, an unverifiable response,
  or an unknown return code. Check whether the order arrived, for example by its pain.002,
  before sending it again. A failure before the final segment, and a verified rejection of
  it, are still raised as before, since the bank then holds no order. Code that catches
  `TransportError` around `upload()` does not catch the new error, which derives from
  `EbicsError`.
- The typed downloads (`download_statements()`, `download_intraday_statements()`,
  `download_booking_advices()`, `download_payment_status_reports()`) parsed the order data
  only after the positive receipt, unless a date range was given. A file the parser
  rejected was then already consumed at the bank and could not be downloaded again. They
  now parse before the receipt, and a `MessageFormatError` sends a negative receipt. Such
  a file now stays at the bank and fails every typed download again; `download()` with
  the same BTF still returns its raw bytes under the default `VersionPolicy`.
- A damaged or unusual ZIP container (an encrypted entry, an unsupported compression
  method, corrupt compressed data) raised standard-library exceptions such as
  `RuntimeError` or `zlib.error` instead of `MessageFormatError`. Every such failure now
  raises `MessageFormatError`, so catching `EbicsError` covers it.

## [1.8.0] - 2026-10-26

### Added

- `Client.bank_parameters()` (HPD) returns `BankParameters`: the bank's access URLs, name
  and host ID, the protocol, authentication, encryption and signature versions it
  supports, and its optional-feature flags.
- `Client.customer_info()` (HKD) returns `CustomerInfo`: the customer's address, accounts
  and registered order types, and every subscriber with their permissions.
- `OrderTypeInfo` now carries the permission's signature class, account and amount limit,
  so `subscriber_info()` (HTD) reports them too.
- Key rotation without a new initialisation letter: `Client.change_keys(new_keyring,
  rotation)` sends PUB (`KeyRotation.SIGNATURE`), HCA
  (`KeyRotation.AUTHENTICATION_AND_ENCRYPTION`) or HCS (`KeyRotation.ALL`), and
  `rotate_keyring()` generates the successor keyring. The client adopts the new keys only
  once the bank confirms the change. If the final answer is lost or cannot be verified,
  `KeyChangeUnconfirmedError` tells the caller to keep both keyrings until it is known
  which one the bank holds.

### Changed

- `save_keyring` writes atomically (temporary file, fsync, rename) and with owner-only
  permissions (mode 0600), so another user or group can no longer read the saved file.

All of it was validated live against the ZKB test platform, except the account data and
a permission's account and amount limit: the test subscriber has none, so those are
checked against the XSD only. 1.8.0 includes the fix released in 1.7.2.

## [1.7.2] - 2026-10-26

### Fixed

- **Uploaded orders carried an invalid electronic signature (A006).** The client ran
  EMSA-PSS over the order data itself instead of over its SHA-256 hash value (EBICS 3.0
  spec 14.1.4.2.5), and did not leave out CR, LF and Ctrl-Z (spec 14). Details in the
  [verification ledger](docs/12-verification-ledger.md), incident 3.

> **If you uploaded orders with ebicsclient 1.7.1 or earlier, check whether they were
> executed.**
>
> **Affected:** every upload (`Client.upload()`, for example pain.001 payments) from 0.1.0
> up to and including 1.7.1. Downloads and the key initialisation (INI, HIA, HPB) are not
> affected.
>
> **What happened:** the bank answers an upload with `000000` before it verifies the
> electronic signature, so `upload()` reported success. The bank then
> rejected the order at the signature check, and it was not executed. The bank may not
> have sent a payment status report (pain.002) for such an order.
>
> **What to do:**
>
> 1. Upgrade: `pip install --upgrade "ebicsclient>=1.7.2"`.
> 2. For every order uploaded with 1.7.1 or earlier, check in the bank's e-banking or on
>    the account statements whether it was executed.
> 3. Resend only the orders that were not executed, so that nothing is paid twice.

## [1.7.1] - 2026-10-04

### Changed

- The README, which is the PyPI page, states the licence terms at the top. No code
  changes.

## [1.7.0] - 2026-10-04

### Changed

- The package metadata and the README link the project website (Homepage, Pricing).
  First release built with the upgraded toolchain. No code changes.

## [1.6.1] - 2026-07-28

### Changed

- Documentation only: the examples use a generic placeholder host ID, and the README
  points to them. No code changes.

## [1.6.0] - 2026-07-28

### Added

- Five runnable examples in `examples/`: a non-consuming peek, a consume-safe nightly
  sync, a dated backfill, a payment upload with its pain.002 round trip, and onboarding
  with the certificate profile.
- Python 3.14 is now tested in CI, like 3.11 to 3.13.

### Fixed

- The transport now closes the HTTP error response of a failed request. On Python 3.14 it
  leaked a temporary file until garbage collection.

## [1.5.0] - 2026-07-27

### Added

- Dated downloads: an optional inclusive `DateRange` for `download()` and the camt and pain
  methods. Booking dates outside the range raise `DateRangeMismatchError`, and the data is
  not acknowledged.
- `ReceiptPolicy.KEEP` reads data without consuming it.
- [docs/13](docs/13-standard-conformance.md) maps every H005 order type and request
  parameter to its support and verification status. The
  [verification ledger](docs/12-verification-ledger.md) records every protocol claim with
  its source and oracle, backed by spec golden vectors.

### Fixed

- Receipts are consume-safe. The client sent the positive receipt before decrypting the
  order data, so a failure afterwards lost the data. It now decrypts and validates first,
  and sends a negative receipt on any failure, so the bank keeps the data for another
  download.

### Changed

- When the bank refuses a repeated INI or HIA as already initialised (091002), the client
  logs a warning: if the keys differ from the first submission, the bank did not receive
  them, and the initialisation letters will not match.

## [1.4.0] - 2026-07-22

### Fixed

- **The initialisation letters printed the EBICS 2.x key hash.** EBICS 3.0 (spec
  4.4.1.2.3, 11.5) requires the certificate in PEM and the SHA-256 hash of its DER
  encoding, so a bank could not match the letters against the keys received with INI and
  HIA. The letters now follow the spec templates (INI letter: A006; HIA letter: X002 and
  E002). Self-signed certificates are now deterministic, so the letters always match what
  INI and HIA sent.

  If you initialised a subscriber with 1.3.3 or earlier and the bank has not activated it:
  have the bank reset the subscriber, run INI and HIA again with 1.4.0 or later, and send
  the new letters.

### Added

- `certificate_fingerprint()`.

## [1.3.3] - 2026-07-17

### Security

- Downloaded order data is inflated in bounded chunks under a 512 MiB ceiling, and ZIP
  containers are limited in entry count and entry size, so a hostile endpoint cannot
  exhaust memory with a small archive.
- HPB rejects a bank RSA key shorter than 2048 bits.

## [1.3.2] - 2026-07-17

### Changed

- Every public entry point validates its input and fails with a message that names the
  fix, for example an EBICS ID that arrives as a number because it was unquoted in a YAML
  or JSON config (which also drops leading zeros).

## [1.3.0] - 2026-07-07

### Added

- Every `ebicsResponse` is authenticated before anything in it is trusted: the bank's X002
  AuthSignature is checked against the key from HPB, which can be pinned. A missing or
  invalid signature raises `ResponseAuthenticationError`.
- `available_order_types()` (HAA) and `subscriber_info()` (HTD).

### Changed

- The client supports EBICS 3.0 (H005) only; H004 is off the roadmap.
- Development status Production/Stable.

## [0.2.0] - 2026-07-06

### Added

- Parsers for pain.002 payment status reports, camt.052 intraday reports and camt.054
  booking advices.
- `UnknownReturnCodeError` for return codes whose meaning is not verified.

### Fixed

- A response with only empty return codes passed as success. It now raises
  `ProtocolError`.
- HTTP redirects were followed, which turned the POST into a GET. The transport now
  refuses them.

## [0.1.1] - 2026-07-06

### Changed

- Releases are published through PyPI Trusted Publishing.

## [0.1.0] - 2026-07-06

First release: an EBICS 3.0 (H005) client with key initialisation (INI, HIA, HPB) and the
initialisation letter as PDF, keys sent as X.509 certificates (self-signed or
bank-issued), bank-key pinning, statement download (BTD) with camt.053 parsing, payment
upload (BTU) with the A006 electronic signature, an HTTPS transport with a TLS 1.2 floor,
and an encrypted keyring.

[Unreleased]: https://github.com/schulluk/ebicsclient/compare/v1.8.0...HEAD
[1.8.0]: https://github.com/schulluk/ebicsclient/compare/v1.7.2...v1.8.0
[1.7.2]: https://github.com/schulluk/ebicsclient/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/schulluk/ebicsclient/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/schulluk/ebicsclient/compare/v1.6.1...v1.7.0
[1.6.1]: https://github.com/schulluk/ebicsclient/compare/v1.6.0...v1.6.1
[1.6.0]: https://github.com/schulluk/ebicsclient/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/schulluk/ebicsclient/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/schulluk/ebicsclient/compare/v1.3.3...v1.4.0
[1.3.3]: https://github.com/schulluk/ebicsclient/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/schulluk/ebicsclient/compare/v1.3.0...v1.3.2
[1.3.0]: https://github.com/schulluk/ebicsclient/compare/v0.2.0...v1.3.0
[0.2.0]: https://github.com/schulluk/ebicsclient/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/schulluk/ebicsclient/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/schulluk/ebicsclient/tree/v0.1.0
