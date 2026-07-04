"""Tests for ebicsclient.certificates: the mit-Schlüsseln / mit-Zertifikaten seam."""

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding

from crypto_helpers import issue_certificate as _issue
from crypto_helpers import make_ca as _make_ca
from ebicsclient import keys
from ebicsclient.certificates import (
    MappingCertificateProvider,
    SelfSignedCertificateProvider,
    TrustAnchorVerifier,
    load_certificate,
)
from ebicsclient.errors import BankCertificateError, CertificateError
from ebicsclient.keys import CertificateUsage
from ebicsclient.models import Keyring


@pytest.fixture(scope="module")
def keyring() -> Keyring:
    return keys.generate_keyring()


def test_self_signed_provider_certifies_the_key(keyring: Keyring) -> None:
    certificate = SelfSignedCertificateProvider().certificate(
        CertificateUsage.SIGNATURE, keyring.signature, "USER1"
    )
    assert certificate.issuer == certificate.subject  # self-signed
    certificate_key = certificate.public_key()
    assert isinstance(certificate_key, rsa.RSAPublicKey)
    assert certificate_key.public_numbers() == keyring.signature.public_key().public_numbers()


def test_mapping_provider_returns_the_supplied_certificate(keyring: Keyring) -> None:
    ca_key, ca_certificate = _make_ca()
    certificate = _issue(
        ca_key, ca_certificate, keyring.authentication.public_key(), CertificateUsage.AUTHENTICATION
    )
    provider = MappingCertificateProvider({CertificateUsage.AUTHENTICATION: certificate})
    returned = provider.certificate(
        CertificateUsage.AUTHENTICATION, keyring.authentication, "USER1"
    )
    assert returned is certificate
    assert returned.issuer == ca_certificate.subject  # CA-issued, not self-signed


def test_mapping_provider_raises_for_a_missing_usage(keyring: Keyring) -> None:
    provider = MappingCertificateProvider({})
    with pytest.raises(CertificateError):
        provider.certificate(CertificateUsage.SIGNATURE, keyring.signature, "USER1")


def test_mapping_provider_rejects_a_certificate_that_does_not_match_the_key(
    keyring: Keyring,
) -> None:
    ca_key, ca_certificate = _make_ca()
    other = keys.generate_keyring()
    # A certificate certifying a different key than the one it will be sent with.
    certificate = _issue(
        ca_key, ca_certificate, other.signature.public_key(), CertificateUsage.SIGNATURE
    )
    provider = MappingCertificateProvider({CertificateUsage.SIGNATURE: certificate})
    with pytest.raises(CertificateError):
        provider.certificate(CertificateUsage.SIGNATURE, keyring.signature, "USER1")


def test_load_certificate_reads_pem_and_der() -> None:
    _, certificate = _make_ca()
    assert load_certificate(certificate.public_bytes(Encoding.PEM)).serial_number == (
        certificate.serial_number
    )
    assert load_certificate(certificate.public_bytes(Encoding.DER)).serial_number == (
        certificate.serial_number
    )


def test_load_certificate_rejects_garbage() -> None:
    with pytest.raises(CertificateError):
        load_certificate(b"not a certificate")


def test_trust_anchor_verifier_accepts_a_certificate_from_the_anchor(keyring: Keyring) -> None:
    ca_key, ca_certificate = _make_ca()
    certificate = _issue(
        ca_key, ca_certificate, keyring.encryption.public_key(), CertificateUsage.ENCRYPTION
    )
    TrustAnchorVerifier([ca_certificate]).verify(certificate, CertificateUsage.ENCRYPTION)


def test_trust_anchor_verifier_rejects_an_untrusted_issuer(keyring: Keyring) -> None:
    ca_key, ca_certificate = _make_ca("Real CA")
    _, other_ca = _make_ca("Other CA")
    certificate = _issue(
        ca_key, ca_certificate, keyring.encryption.public_key(), CertificateUsage.ENCRYPTION
    )
    with pytest.raises(BankCertificateError):
        TrustAnchorVerifier([other_ca]).verify(certificate, CertificateUsage.ENCRYPTION)


def test_trust_anchor_verifier_rejects_an_expired_certificate(keyring: Keyring) -> None:
    ca_key, ca_certificate = _make_ca()
    certificate = _issue(
        ca_key,
        ca_certificate,
        keyring.encryption.public_key(),
        CertificateUsage.ENCRYPTION,
        valid=False,
    )
    with pytest.raises(BankCertificateError):
        TrustAnchorVerifier([ca_certificate]).verify(certificate, CertificateUsage.ENCRYPTION)


def test_trust_anchor_verifier_requires_at_least_one_anchor() -> None:
    with pytest.raises(BankCertificateError):
        TrustAnchorVerifier([])
