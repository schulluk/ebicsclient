# Key vs certificate profiles ("mit Schlüsseln" / "mit Zertifikaten")

EBICS 3.0 (H005) transmits every public key inside an X.509 certificate (`ds:X509Data`), so
the two profiles a bank may require share the **same wire format** and differ only in where the
subscriber's certificate comes from and how the bank's certificate is trusted:

- **mit Schlüsseln** (key-based) — the certificate is **self-signed** by the key it carries.
  Identity is established out of band: the signed initialisation letter, or online activation.
  This is the default and what the ZKB validation used. The self-signed certificates are
  **deterministic** (fixed validity 2020-01-01 → 9999-12-31, key-derived serial, deterministic
  PKCS#1 v1.5 signature): regenerating one for the same key yields **byte-identical DER**. This
  matters because the EBICS 3.0 initialisation letters print the SHA-256 hash of the DER-encoded
  certificate (spec section 4.4.1.2.3) and the bank compares it against the certificate INI/HIA
  transmitted — determinism lets any later session reproduce that certificate from the keyring
  alone, without persisting certificates. (The Swiss Market Practice Guidelines section 6.1
  explicitly allow unlimited certificate validity.)
- **mit Zertifikaten** (certificate-based) — the certificate is **issued by a CA the bank
  trusts**, and the bank validates the chain. Common at German and French banks.

Because the envelope is identical, this is a **key-management choice, not a protocol change**.
The `ebicsclient.certificates` module is the seam.

## The seam

Two small interfaces, each with a default that reproduces the key-based behaviour:

| Interface | Default (mit Schlüsseln) | For mit Zertifikaten |
| --- | --- | --- |
| `CertificateProvider` — supplies the subscriber's cert per key | `SelfSignedCertificateProvider` | `MappingCertificateProvider`, or your own |
| `BankCertificateVerifier` — validates the bank's HPB cert | `None` (hash check only) | `TrustAnchorVerifier`, or your own |

Both are passed to `Client`; everything below the client stays profile-agnostic.

## mit Schlüsseln (default — nothing to configure)

```python
from ebicsclient import Client, Bank, User, generate_keyring

client = Client(bank, user, generate_keyring())   # self-signed certs, no bank-cert chain check
client.ini(); client.hia()                         # ... letter, activation ...
client.hpb()                                       # verify the printed hashes out of band
```

## mit Zertifikaten (caller supplies CA-issued certificates)

You obtain a certificate for each of the three keys from the CA the bank mandates, load them
however you like, and hand them to the client. The library never dictates where certificates are
stored — the provider *is* the storage/persistence seam: back it with files, a database, an HSM,
or a rotating store by implementing `CertificateProvider` yourself. `MappingCertificateProvider`
is the built-in "I already have the three certificates in memory" case.

```python
from ebicsclient import (
    Client, CertificateUsage, MappingCertificateProvider, TrustAnchorVerifier,
    load_certificate, generate_keyring,
)

# 1. Load the CA-issued certificates that certify your three keys.
certificates = {
    CertificateUsage.SIGNATURE:      load_certificate(open("a006.pem", "rb").read()),
    CertificateUsage.AUTHENTICATION: load_certificate(open("x002.pem", "rb").read()),
    CertificateUsage.ENCRYPTION:     load_certificate(open("e002.pem", "rb").read()),
}
provider = MappingCertificateProvider(certificates)

# 2. Trust the bank's certificate against the bank's CA certificate.
bank_ca = load_certificate(open("bank-ca.pem", "rb").read())
verifier = TrustAnchorVerifier([bank_ca])

client = Client(
    bank, user, generate_keyring(),          # the keyring holds the private keys those certs certify
    certificate_provider=provider,
    bank_certificate_verifier=verifier,
)
client.ini(); client.hia(); client.hpb()
```

`MappingCertificateProvider` checks that each certificate actually certifies the private key it
will be sent with (a mismatch raises `CertificateError` rather than letting the bank reject the
signature). `TrustAnchorVerifier` checks the bank certificate is within its validity period and
issued by one of the anchors, raising `BankCertificateError` otherwise.

## Scope of the built-in verifier

`TrustAnchorVerifier` is deliberately a **single-level** check: validity period plus a direct
issuer signature against the supplied anchors. It does **not** build multi-certificate paths or
check revocation (CRL/OCSP). For those, implement `BankCertificateVerifier` with a full
path-validation library and pass it instead — the client calls it for each bank certificate.

## What is still bank-specific

- The **CA and certificate requirements** (which CA, subject-DN constraints, extended key usage)
  vary per bank; obtain certificates that satisfy the target bank's rules.
- Only the **key-based** profile has been validated against a live bank (ZKB) so far. The
  certificate path is implemented and unit-tested but not yet exercised end to end against a bank
  that requires it.
