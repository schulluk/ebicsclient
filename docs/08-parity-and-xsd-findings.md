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

### 4. EBICS 3.0 transmits public keys as X.509 certificates (CORRECTED)

The H005 `PubKeyInfoType` (in `ebics_types_H005.xsd`, and `SignaturePubKeyInfoType` in the
**S002** namespace `http://www.ebics.org/S002`) requires a `ds:X509Data` element. Our
initial order data embedded a plain `ds:RSAKeyValue` (modulus/exponent), which the XSD
**rejects**. EBICS 3.0 key management is certificate-based, and this is now implemented:

- `keys.generate_self_signed_certificate` wraps each key (A006/X002/E002) in a self-signed
  X.509 certificate (the key-based "mit Schlüsseln" profile; no new dependency).
- INI `SignaturePubKeyOrderData` is built in the **S002** namespace with the A006 cert as
  `ds:X509Data`; HIA carries X002/E002 as `ds:X509Data`.
- HPB response parsing reads the bank's keys from `ds:X509Certificate` (with a defensive
  fallback to `ds:RSAKeyValue`).

Both order-data payloads now validate against `ebics_signature_S002.xsd` and
`ebics_orders_H005.xsd`. The public-key **hash** on the initialisation letter is unchanged
(it is taken over the key's modulus/exponent, not the certificate).

## Remaining for the bank test platform

The self-signed certificate's subject/validity and ZKB's exact "mit Schlüsseln"
expectation still need confirmation on the ZKB test platform; the *structure* is
XSD-valid. The canonicalisation, envelopes, and order-data schemas are all verified
offline — the test platform is the final end-to-end check (see docs/07).
