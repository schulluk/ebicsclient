# EBICS 3.0 (H005) coverage & gaps

An honest overview of what this library **supports today** and what it **does not yet do**,
measured against the EBICS 3.0 (H005) standard. Gaps are shown on purpose: this page doubles
as the backlog for deciding what to build next. "Not implemented" here means exactly that —
absent, not excluded — unless the **Notes** say otherwise.

> This is the at-a-glance map. The per-claim spec citations and oracles behind each *supported*
> row live in the [verification ledger](12-verification-ledger.md).

## Legend

- **Support** — ✅ implemented · 🟡 partial (see Notes) · ❌ not implemented.
- **Rule** — **Mandated** (the standard defines the behaviour) or **Bank-dependent** (the
  standard leaves the outcome to the financial institution).
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
| HPB key trust via published hash / pinning | Bank-dependent | ✅ | live | Published hashes are out-of-band per bank |
| Bank certificate chain validation (`TrustAnchorVerifier`) | Bank-dependent | ✅ | spec | Only when a bank mandates a CA |
| PUB — change the bank-technical (signature) key | Mandated | ❌ | | Key rotation; today a key change means full re-init (new INI/HIA + letters) |
| HCA — change the authentication + encryption keys | Mandated | ❌ | | Key rotation (see PUB) |
| HCS — change all three subscriber keys at once | Mandated | ❌ | | Key rotation (see PUB) |
| SPR — suspend / lock the subscriber's access | Mandated | ❌ | | e.g. on suspected key compromise |
| H3K — one-step CA-certificate initialisation | Mandated (optional) | ❌ | | CA profile only; not a priority |

## Read — downloads

| Capability | Rule | Support | Verification | Notes |
|---|---|---|---|---|
| BTD download transaction (initialise → transfer → receipt) | Mandated | ✅ | live | |
| Order-data decryption (RSA-unwrap + AES-128-CBC + inflate) | Mandated | ✅ | live | |
| Response `AuthSignature` verification on every response | Mandated | ✅ | live | |
| Fail-closed on every return code; unknown codes never masked | Mandated | ✅ | live | |
| Multi-segment order data | Mandated | ✅ | live | |
| Positive receipt (consume) / negative receipt (keep) | Mandated | ✅ | live / XSD+spec | |
| Acknowledge only after decrypt+validate (no consume-on-error) | Mandated | ✅ | spec + tests | |
| Non-consuming read (`ReceiptPolicy.KEEP`) | Mandated | ✅ | XSD + spec | Deliberate negative ack |
| Fetch statements/reports for a specific date range — BTD `DateRange` (inclusive) | Mandated | ✅ | live | The library sends the range; out-of-range data fails closed (`DateRangeMismatchError`), never returned as a match |
| ↳ the bank actually applying that range, and re-serving already-delivered data | Bank-dependent | 🟡 | | Not guaranteed by the standard; confirm per bank before relying on a dated re-download |
| Generic order parameters — `Parameter` Name/Value pairs | Mandated (optional) | ❌ | | Bank-specific query params alongside `DateRange`; not exposed (a custom BTF still works) |
| Arbitrary business download via a custom BTF | Mandated | ✅ | live | Any `BusinessTransactionFormat`, raw bytes returned |
| camt.053 EOD statements — typed parser | Mandated (ISO) | ✅ | live | |
| camt.052 intraday reports — typed parser | Mandated (ISO) | ✅ | spec-vector | |
| camt.054 booking advices (incl. QRR/SCOR/LSV) — typed parser | Mandated (ISO) | ✅ | spec-vector | |
| pain.002 payment status reports — typed parser | Mandated (ISO) | ✅ | spec-vector | |
| HAA — order types with data available | Mandated | ✅ | live | |
| HTD — *this subscriber's* data & permissions | Mandated | ✅ | live | |
| HKD — *customer + all subscribers'* data | Mandated | ❌ | | HTD covers only this subscriber |
| HPD — bank parameters (limits, supported order types) | Mandated | ❌ | | Cheap + useful for discovering bank limits |
| HAC — customer protocol / acknowledgements (pain.002 form) | Mandated | ❌ | | Machine-readable action log |
| PTK — customer protocol (textual) | Mandated | ❌ | | Textual counterpart of HAC |
| HEV — supported EBICS versions (unsecured discovery) | Mandated | ❌ | | Pre-init version probe |
| Transaction recovery / resumption after an interrupted transfer | Mandated (optional) | ❌ | | An interrupted download restarts, not resumes |

## Write — uploads

| Capability | Rule | Support | Verification | Notes |
|---|---|---|---|---|
| BTU upload transaction (initialise → transfer) | Mandated | ✅ | live | |
| A006 electronic signature (RSASSA-PSS) | Mandated | ✅ | live | |
| Order-data encryption to the bank's E002 | Mandated | ✅ | live | |
| `SignatureFlag` on BTU order params | Mandated | ✅ | live | |
| Arbitrary business upload via a custom BTF | Mandated | ✅ | live | Any `BusinessTransactionFormat` |
| pain.001 credit transfer submission | Mandated (ISO) | ✅ | live | |
| pain.008 direct-debit submission | Mandated (ISO) | 🟡 | | Works via a custom BTF; no typed helper |
| Pre-validation before submission — `PreValidation` (account authorisations / amounts) | Mandated (optional) | ❌ | | Optional bank pre-check sent with the order; not implemented |
| Generic order parameters + `AdditionalOrderInfo` (free-text note ≤255 chars) | Mandated (optional) | ❌ | | Bank-specific Name/Value params and an unstructured order note; not exposed |

## Distributed electronic signatures (EDS / VEU) — multi-person approval

EDS (formerly VEU) is EBICS's workflow for orders that require **several people to sign before
the bank executes them** — dual-control on payments. The entire family is **unimplemented**:
today an order can only be uploaded with all required signatures inside a single request, or
authorised outside EBICS.

| Order type | Rule | Support | Notes |
|---|---|---|---|
| HVU / HVZ — download the EDS overview (pending orders), plain / with detail | Mandated (optional) | ❌ | |
| HVD — download an order's details for review | Mandated (optional) | ❌ | |
| HVT — download an order's transaction data | Mandated (optional) | ❌ | |
| HVE — add an electronic signature to a pending order | Mandated (optional) | ❌ | |
| HVS — cancel a pending order | Mandated (optional) | ❌ | |
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
