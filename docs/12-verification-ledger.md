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
| H005-only; no H004 and earlier | Owner decision ([docs/04](04-implementation-plan.md)) | n/a | n/a |

## 2.5→3.0 amendment audit (2026-07-22)

Walked the spec's amendment-history table against the codebase. Findings: the letter-hash
flaw (fixed, 1.4.0), the `BankPubKeyDigests` divergence (watch-item above), and one
comment upgraded from folklore to an XSD citation (HPB bare-key fallback). Everything else
was either already conformant, validated live, or out of scope (FTAM, A004, HAC, H3K —
H3K is explicitly unsupported in Switzerland per Swiss MPG 6.1).
