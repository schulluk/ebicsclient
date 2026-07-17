"""Certificate provisioning and bank-certificate verification for the two EBICS profiles.

EBICS 3.0 (H005) transmits every public key inside an X.509 certificate, so the two
profiles a bank may require share the same wire format and differ only in where the
subscriber's certificate comes from and how the bank's certificate is trusted:

- **"mit Schlüsseln"** (key-based): the certificate is self-signed by the key it carries;
  identity is established out of band (the signed initialisation letter or online activation).
- **"mit Zertifikaten"** (certificate-based): the certificate is issued by a CA the bank
  trusts, and the bank validates the certificate chain.

This module is the seam between them, so the protocol code stays profile-agnostic:

- :class:`CertificateProvider` supplies the subscriber's certificate for each EBICS key.
  :class:`SelfSignedCertificateProvider` (the default) mints self-signed certificates;
  :class:`MappingCertificateProvider` returns caller-supplied CA-issued certificates. A
  caller with its own PKI, HSM, or on-disk store implements the protocol directly — the
  library never forces certificate storage, exactly as it never forces key storage.
- :class:`BankCertificateVerifier` validates the bank's certificate from the HPB response.
  The default (``None``) trusts the key by its published hash only; :class:`TrustAnchorVerifier`
  additionally checks that the bank's certificate chains to a caller-supplied trust anchor.
"""

import datetime
from collections.abc import Iterable, Mapping
from typing import Protocol, runtime_checkable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from ebicsclient.errors import BankCertificateError, CertificateError
from ebicsclient.keys import CertificateUsage, generate_self_signed_certificate


@runtime_checkable
class CertificateProvider(Protocol):
    """Supplies the subscriber's X.509 certificate for one EBICS key.

    Implement this to control where certificates come from — a PKI, an HSM, or files on
    disk. The library calls it once per key while building INI/HIA.
    """

    def certificate(
        self, usage: CertificateUsage, private_key: rsa.RSAPrivateKey, subject_name: str
    ) -> x509.Certificate:
        """Return the certificate to transmit for the key identified by ``usage``.

        Args:
            usage: The EBICS role of the key (signature/authentication/encryption).
            private_key: The subscriber's private key for that role; the returned
                certificate must certify its public half.
            subject_name: A suggested subject common name (the subscriber's User ID),
                used by the self-signed provider and ignored by providers returning a
                fixed CA-issued certificate.

        Returns:
            The X.509 certificate to embed in the request.

        Raises:
            CertificateError: no certificate is available for ``usage``, or the certificate
                does not match ``private_key``.
        """
        ...


class SelfSignedCertificateProvider:
    """The default provider: a self-signed certificate per key (the "mit Schlüsseln" profile)."""

    def certificate(
        self, usage: CertificateUsage, private_key: rsa.RSAPrivateKey, subject_name: str
    ) -> x509.Certificate:
        """Mint a fresh self-signed certificate carrying ``private_key``'s public half."""
        return generate_self_signed_certificate(private_key, subject_name, usage)


class MappingCertificateProvider:
    """A basic caller-supplied provider for the "mit Zertifikaten" profile.

    Holds one CA-issued certificate per EBICS key. The caller obtains the certificates from
    whatever CA the bank mandates and loads them however it likes (see :func:`load_certificate`
    for a PEM/DER helper); this provider just hands the right one back and checks it matches
    the key it will be sent with. Callers needing dynamic lookup (an HSM, a rotating store)
    implement :class:`CertificateProvider` directly instead.
    """

    def __init__(self, certificates: Mapping[CertificateUsage, x509.Certificate]) -> None:
        """Store the certificates by EBICS role.

        Args:
            certificates: A mapping from each :class:`~ebicsclient.keys.CertificateUsage` to
                the CA-issued certificate certifying that key.

        Raises:
            TypeError: a mapping value is not an ``x509.Certificate``.
        """
        self._certificates = dict(certificates)
        for usage, certificate in self._certificates.items():
            if not isinstance(certificate, x509.Certificate):
                raise TypeError(
                    f"The {usage} certificate must be an x509.Certificate, got "
                    f"{type(certificate).__name__} — load PEM/DER bytes with "
                    f"load_certificate()"
                )

    def certificate(
        self, usage: CertificateUsage, private_key: rsa.RSAPrivateKey, subject_name: str
    ) -> x509.Certificate:
        """Return the stored certificate for ``usage`` after checking it matches the key."""
        certificate = self._certificates.get(usage)
        if certificate is None:
            raise CertificateError(f"No certificate was provided for the {usage.value} key")
        if not _certifies(certificate, private_key):
            raise CertificateError(
                f"The {usage.value} certificate does not certify the {usage.value} private key"
            )
        return certificate


@runtime_checkable
class BankCertificateVerifier(Protocol):
    """Validates the bank's certificate carried in the HPB response.

    Implement this to enforce a trust policy on the bank's certificate — chain building,
    validity, revocation. The library calls it for each bank certificate before extracting
    the public key.
    """

    def verify(self, certificate: x509.Certificate, usage: CertificateUsage) -> None:
        """Raise if the bank's certificate must not be trusted.

        Args:
            certificate: The bank's certificate from the HPB response.
            usage: The EBICS role the certificate is presented for.

        Raises:
            BankCertificateError: the certificate fails the trust policy.
        """
        ...


class TrustAnchorVerifier:
    """A basic verifier: the bank certificate must be valid now and issued by a trust anchor.

    Checks the certificate is within its validity period and directly signed by one of the
    caller-supplied trust anchors (the bank's CA certificate). This is deliberately a
    single-level check with no revocation: for intermediate chains, revocation (CRL/OCSP), or
    policy constraints, implement :class:`BankCertificateVerifier` with a full path-validation
    library instead.
    """

    def __init__(self, trust_anchors: Iterable[x509.Certificate]) -> None:
        """Store the trusted issuer certificates.

        Args:
            trust_anchors: The CA certificate(s) the bank's certificate must be issued by.

        Raises:
            BankCertificateError: no trust anchors were supplied.
        """
        self._anchors = list(trust_anchors)
        if not self._anchors:
            raise BankCertificateError("At least one trust anchor is required")
        for anchor in self._anchors:
            if not isinstance(anchor, x509.Certificate):
                raise TypeError(
                    f"Trust anchors must be x509.Certificate objects, got "
                    f"{type(anchor).__name__} — load PEM/DER bytes with load_certificate()"
                )

    def verify(self, certificate: x509.Certificate, usage: CertificateUsage) -> None:
        """Check the bank certificate's validity period and issuer against the anchors."""
        now = datetime.datetime.now(datetime.UTC)
        if not certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc:
            raise BankCertificateError(
                f"The bank {usage.value} certificate is outside its validity period"
            )
        if not any(_is_issued_by(certificate, anchor) for anchor in self._anchors):
            raise BankCertificateError(
                f"The bank {usage.value} certificate does not chain to a trusted anchor"
            )


def load_certificate(data: bytes) -> x509.Certificate:
    """Load an X.509 certificate from PEM or DER bytes (a convenience for callers).

    Args:
        data: The certificate encoded as PEM or DER.

    Returns:
        The parsed certificate.

    Raises:
        CertificateError: the data is not bytes or not a readable X.509 certificate.
    """
    if not isinstance(data, bytes | bytearray):
        raise CertificateError(
            f"Certificate data must be bytes, got {type(data).__name__} — read the "
            f"certificate file in binary mode ('rb')"
        )
    for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
        try:
            return loader(bytes(data))
        except ValueError:
            continue
    raise CertificateError("Data is not a readable PEM or DER X.509 certificate")


#: The default certificate provider — self-signed certificates (the "mit Schlüsseln" profile).
DEFAULT_CERTIFICATE_PROVIDER: CertificateProvider = SelfSignedCertificateProvider()


def _certifies(certificate: x509.Certificate, private_key: rsa.RSAPrivateKey) -> bool:
    certificate_key = certificate.public_key()
    if not isinstance(certificate_key, rsa.RSAPublicKey):
        return False
    return certificate_key.public_numbers() == private_key.public_key().public_numbers()


def _is_issued_by(certificate: x509.Certificate, issuer: x509.Certificate) -> bool:
    if certificate.issuer != issuer.subject:
        return False
    issuer_key = issuer.public_key()
    if not isinstance(issuer_key, rsa.RSAPublicKey):
        return False
    algorithm = certificate.signature_hash_algorithm
    if algorithm is None:
        return False
    try:
        issuer_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            _rsa_padding(certificate),
            algorithm,
        )
    except InvalidSignature:
        return False
    return True


def _rsa_padding(certificate: x509.Certificate) -> padding.AsymmetricPadding:
    parameters = certificate.signature_algorithm_parameters
    if isinstance(parameters, padding.PSS):
        return parameters
    return PKCS1v15()
