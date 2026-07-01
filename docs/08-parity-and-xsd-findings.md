# Offline verification: XSD validation + cross-implementation parity

Before touching a bank test platform we verified the handshake against three
**independent** oracles, so findings do not rest on any single source (in particular, not
on trusting another client as "golden"):

1. **The official H005 XSD schemas** (`ebics_*_H005.xsd`) — the authoritative structure.
2. **An independent canonicaliser** — Python's stdlib `xml.etree.ElementTree.canonicalize`
   (a different codebase from lxml/libxml2) — plus the W3C Canonical XML rules.
3. **ebics-client-php** — a production EBICS client — as a behavioural cross-check only.

Tooling lives in `tools/php-parity/` (see its README to regenerate fixtures); the golden
fixtures are committed under `tests/fixtures/parity/` and the checks run in
`tests/test_php_parity.py` and `tests/test_c14n_vectors.py` with no PHP needed in CI.

## Findings and corrections

### 1. Canonicalisation: inclusive C14N 1.0, not exclusive (CORRECTED)

EBICS mandates **inclusive Canonical XML 1.0** (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315`)
for both `CanonicalizationMethod` and the Reference `Transform` — confirmed by the EBICS
Common Implementation Guide and every reference client. Our initial implementation used
**exclusive** c14n; a bank would have rejected every signature. Now fixed.

While fixing it we found a real **lxml bug**: `tostring(method="c14n", exclusive=False)`
emits a spurious `xmlns=""` on descendants that share a default namespace declared on an
ancestor outside the canonicalised subtree. Two independent canonicalisers (stdlib and
libxml via PHP) and the W3C rules agree there must be no `xmlns=""`. The workaround
(`crypto.canonicalize`) rebuilds the node as its own document root with in-scope namespaces
materialised, which libxml canonicalises correctly. Verified byte-for-byte: our
`DigestValue` reproduces the reference client's, and our verifier accepts its signature.

### 2. `AdminOrderType`, not `OrderType`, for INI/HIA (CORRECTED)

The H005 XSD rejects `OrderType` in `OrderDetails`; H005 uses `AdminOrderType` for all
administrative orders (INI, HIA, HPB). All three request envelopes now validate against
`ebics_keymgmt_request_H005.xsd`.

### 3. Signature primitive: standard rsa-sha256 (CONFIRMED CORRECT)

The reference client's `SignatureValue` verifies with our own `verify_rsa_sha256` as
standard RSASSA-PKCS1-v1_5 over SHA-256. No change needed.

## Open item: EBICS 3.0 transmits public keys as X.509 certificates

The H005 `PubKeyInfoType` (in `ebics_types_H005.xsd`, and `SignaturePubKeyInfoType` in the
**S002** namespace `http://www.ebics.org/S002`) requires a `ds:X509Data` element. Our
current INI/HIA order data embeds a plain `ds:RSAKeyValue` (modulus/exponent), which the
XSD **rejects**. So EBICS 3.0 key management is certificate-based:

- INI `SignaturePubKeyOrderData` lives in the **S002** namespace (we currently build it in
  H005) and must carry the A006 key as `ds:X509Data`.
- HIA `AuthenticationPubKeyInfo` / `EncryptionPubKeyInfo` must carry X002/E002 as
  `ds:X509Data`.
- HPB response parsing must read the bank's keys from `ds:X509Data`.

This needs a design decision (self-signed X.509 certificate generation via `cryptography`,
no new dependency) and confirmation of ZKB's "mit Schlüsseln" expectation. Until then the
INI/HIA **order-data** payload is known-incomplete; the request **envelopes** and the
**AuthSignature** are correct and schema-valid.
