"""Onboard with CA-issued certificates — the "mit Zertifikaten" profile.

    Most subscribers use self-signed certificates: the library mints them from the keyring
    and the bank trusts the fingerprints on the signed initialisation letter. Some banks, and
    some corporate security policies, require the other profile instead — "mit Zertifikaten",
    where the three subscriber keys are wrapped in certificates issued by a certificate
    authority the bank already trusts. Ren's employer is one of those: their PKI team hands
    out X.509 certificates for the signature, authentication, and encryption keys, and the
    bank verifies them up the CA chain rather than off a letter.

The only thing that changes is *where the certificates come from*. Instead of the default
self-signed provider, this builds a :class:`~ebicsclient.MappingCertificateProvider` from
three PEM files (one per key usage) and hands it to the client; ``ini`` and ``hia`` then
present those certificates. Optionally, a :class:`~ebicsclient.TrustAnchorVerifier` built
from the bank's root certificate validates the bank's own certificates during HPB. The
private keys still live only in the keyring — the certificates just wrap the matching public
keys, and the provider checks that each certificate actually certifies its key.

Environment variables (in addition to the usual EBICS_* set — see _config.py):

    EBICS_CERT_SIGNATURE_PATH   PEM certificate for the A006 signature key
    EBICS_CERT_AUTH_PATH        PEM certificate for the X002 authentication key
    EBICS_CERT_ENC_PATH         PEM certificate for the E002 encryption key
    EBICS_BANK_TRUST_ANCHOR_PATH  (optional) PEM root/CA cert to validate the bank at HPB

Run it just like the handshake runner's ini/hia steps:

    uv run python examples/05_certificate_profile_onboarding.py
"""

import os
from pathlib import Path

from cryptography import x509

from ebicsclient import (
    BankCertificateVerifier,
    CertificateUsage,
    InitializationState,
    MappingCertificateProvider,
    TrustAnchorVerifier,
    load_certificate,
)

from _config import client_from_env, load_environment


def main() -> int:
    """Submit INI and HIA using CA-issued certificates instead of self-signed ones."""
    load_environment()

    provider = MappingCertificateProvider(
        {
            CertificateUsage.SIGNATURE: _load_cert("EBICS_CERT_SIGNATURE_PATH"),
            CertificateUsage.AUTHENTICATION: _load_cert("EBICS_CERT_AUTH_PATH"),
            CertificateUsage.ENCRYPTION: _load_cert("EBICS_CERT_ENC_PATH"),
        }
    )
    client = client_from_env(
        certificate_provider=provider,
        bank_certificate_verifier=_bank_verifier(),
    )

    _report("INI", client.ini(), "the signature certificate (A006)")
    _report("HIA", client.hia(), "the authentication and encryption certificates (X002, E002)")
    print(
        "\nNext: render and sign the initialisation letter (see zkb_handshake.py `letter`), "
        "then run HPB once the bank has activated you."
    )
    return 0


def _report(order: str, state: InitializationState, what: str) -> None:
    """Print whether an INI/HIA submission was newly delivered or already on file."""
    if state is InitializationState.ALREADY_INITIALISED:
        print(
            f"{order}: already initialised — {what} were NOT re-submitted "
            f"(a bank reset is needed to change them)."
        )
    else:
        print(f"{order} accepted: {what} were submitted.")


def _bank_verifier() -> BankCertificateVerifier | None:
    """Build a trust-anchor verifier from ``EBICS_BANK_TRUST_ANCHOR_PATH``, if it is set."""
    anchor_path = os.environ.get("EBICS_BANK_TRUST_ANCHOR_PATH")
    if anchor_path is None:
        return None
    return TrustAnchorVerifier([load_certificate(Path(anchor_path).read_bytes())])


def _load_cert(env_name: str) -> x509.Certificate:
    """Load the PEM certificate at the path named by ``env_name``."""
    return load_certificate(Path(os.environ[env_name]).read_bytes())


if __name__ == "__main__":
    raise SystemExit(main())
