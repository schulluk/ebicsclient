"""Test-only helpers that synthesise EBICS ciphertext and HPB responses.

The library is download-only, so it never *encrypts* order data; these helpers do, to
build fixtures that exercise the decryption and HPB-parsing paths without a live bank.
They deliberately mirror ``crypto.decrypt_order_data`` (AES-CBC, null IV, PKCS#7) so a
round trip proves the two are inverses.
"""

import base64
import datetime
import os
import zlib
from collections.abc import Mapping

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from lxml import etree

from ebicsclient import keys as _keys
from ebicsclient.keys import CertificateUsage, generate_self_signed_certificate
from ebicsclient.models import Keyring
from ebicsclient.protocol import h005

_NULL_IV = b"\x00" * 16
_DS = "http://www.w3.org/2000/09/xmldsig#"


def make_ca(common_name: str = "Test CA") -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """Create a self-signed CA key pair and certificate for issuing subscriber/bank certs."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def issue_certificate(
    ca_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
    public_key: rsa.RSAPublicKey,
    usage: CertificateUsage,
    *,
    valid: bool = True,
) -> x509.Certificate:
    """Issue a CA-signed end-entity certificate for ``public_key`` with the EBICS Key Usage."""
    now = datetime.datetime.now(datetime.UTC)
    not_before, not_after = (
        (now - datetime.timedelta(days=1), now + datetime.timedelta(days=365))
        if valid
        else (now - datetime.timedelta(days=365), now - datetime.timedelta(days=1))
    )
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SUBSCRIBER")]))
        .issuer_name(ca_certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(_keys._key_usage(usage), critical=True)
        .sign(ca_key, hashes.SHA256())
    )


def encrypt_order_data(
    public_key: rsa.RSAPublicKey, order_data: bytes, *, key_size: int = 16
) -> tuple[bytes, bytes]:
    """Compress, AES-encrypt order data, and RSA-encrypt the transaction key.

    Returns the (RSA-encrypted transaction key, AES-encrypted order data) pair, matching
    what an EBICS response carries.
    """
    symmetric_key = os.urandom(key_size)
    compressed = zlib.compress(order_data)
    padder = symmetric_padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(compressed) + padder.finalize()
    encryptor = Cipher(algorithms.AES(symmetric_key), modes.CBC(_NULL_IV)).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    transaction_key = public_key.encrypt(symmetric_key, padding.PKCS1v15())
    return transaction_key, encrypted


def make_download_responses(
    subscriber_keyring: Keyring,
    order_data: bytes,
    *,
    num_segments: int = 1,
    transaction_id: str = "A" * 32,
) -> list[bytes]:
    """Build the response sequence for a full download of ``order_data``.

    Encrypts ``order_data`` the way a bank would, splits the base64 stream into
    ``num_segments`` pieces, and returns ``[initialisation, transfer..., receipt]`` — the
    responses a fake transport should hand back in order to exercise ``Client.download``.
    """
    transaction_key, encrypted = encrypt_order_data(
        subscriber_keyring.encryption.public_key(), order_data
    )
    stream = base64.b64encode(encrypted).decode("ascii")
    pieces = _split(stream, num_segments)
    encoded_key = base64.b64encode(transaction_key).decode("ascii")

    responses = [
        _download_response(
            phase="Initialisation",
            segment_number=1,
            last_segment=num_segments == 1,
            order_data=pieces[0],
            transaction_id=transaction_id,
            num_segments=num_segments,
            transaction_key=encoded_key,
        )
    ]
    for index in range(1, num_segments):
        responses.append(
            _download_response(
                phase="Transfer",
                segment_number=index + 1,
                last_segment=index + 1 == num_segments,
                order_data=pieces[index],
            )
        )
    responses.append(_receipt_response())
    return responses


def _split(stream: str, parts: int) -> list[str]:
    size = -(-len(stream) // parts)  # ceil division, so every piece but the last is full
    return [stream[index : index + size] for index in range(0, len(stream), size)] or [""]


def _download_response(
    *,
    phase: str,
    segment_number: int,
    last_segment: bool,
    order_data: str,
    transaction_id: str | None = None,
    num_segments: int | None = None,
    transaction_key: str | None = None,
) -> bytes:
    namespace = h005.NAMESPACE
    root = etree.Element(etree.QName(namespace, "ebicsResponse"), nsmap={None: namespace})
    root.set("Version", "H005")
    root.set("Revision", "1")
    header = etree.SubElement(root, etree.QName(namespace, "header"))
    header.set("authenticate", "true")
    static = etree.SubElement(header, etree.QName(namespace, "static"))
    if transaction_id is not None:
        etree.SubElement(static, etree.QName(namespace, "TransactionID")).text = transaction_id
    if num_segments is not None:
        etree.SubElement(static, etree.QName(namespace, "NumSegments")).text = str(num_segments)
    mutable = etree.SubElement(header, etree.QName(namespace, "mutable"))
    etree.SubElement(mutable, etree.QName(namespace, "TransactionPhase")).text = phase
    segment = etree.SubElement(mutable, etree.QName(namespace, "SegmentNumber"))
    segment.text = str(segment_number)
    segment.set("lastSegment", "true" if last_segment else "false")
    etree.SubElement(mutable, etree.QName(namespace, "ReturnCode")).text = "000000"
    etree.SubElement(mutable, etree.QName(namespace, "ReportText")).text = "[EBICS_OK] OK"
    body = etree.SubElement(root, etree.QName(namespace, "body"))
    data_transfer = etree.SubElement(body, etree.QName(namespace, "DataTransfer"))
    if transaction_key is not None:
        info = etree.SubElement(data_transfer, etree.QName(namespace, "DataEncryptionInfo"))
        digest = etree.SubElement(info, etree.QName(namespace, "EncryptionPubKeyDigest"))
        digest.set("Version", "E002")
        digest.text = base64.b64encode(b"digest").decode("ascii")
        etree.SubElement(info, etree.QName(namespace, "TransactionKey")).text = transaction_key
    etree.SubElement(data_transfer, etree.QName(namespace, "OrderData")).text = order_data
    etree.SubElement(body, etree.QName(namespace, "ReturnCode")).text = "000000"
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def _receipt_response() -> bytes:
    # A real bank acknowledges a positive receipt with 011000 EBICS_DOWNLOAD_POSTPROCESS_DONE
    # (validated live on ZKB), so the fixture mirrors that rather than 000000.
    namespace = h005.NAMESPACE
    root = etree.Element(etree.QName(namespace, "ebicsResponse"), nsmap={None: namespace})
    root.set("Version", "H005")
    root.set("Revision", "1")
    header = etree.SubElement(root, etree.QName(namespace, "header"))
    header.set("authenticate", "true")
    etree.SubElement(header, etree.QName(namespace, "static"))
    mutable = etree.SubElement(header, etree.QName(namespace, "mutable"))
    etree.SubElement(mutable, etree.QName(namespace, "TransactionPhase")).text = "Receipt"
    etree.SubElement(mutable, etree.QName(namespace, "ReturnCode")).text = "011000"
    etree.SubElement(mutable, etree.QName(namespace, "ReportText")).text = (
        "[EBICS_DOWNLOAD_POSTPROCESS_DONE] Positive acknowledgement received"
    )
    body = etree.SubElement(root, etree.QName(namespace, "body"))
    etree.SubElement(body, etree.QName(namespace, "ReturnCode")).text = "011000"
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def make_hpb_response(
    subscriber_keyring: Keyring,
    bank_keyring: Keyring,
    *,
    host_id: str = "ZKBKCHZZ",
    certificates: Mapping[CertificateUsage, x509.Certificate] | None = None,
) -> bytes:
    """Build an OK HPB response carrying the bank's keys, encrypted to the subscriber.

    By default the bank keys are wrapped in self-signed certificates (the "mit Schlüsseln"
    profile). Pass ``certificates`` (keyed by usage) to embed CA-issued certificates instead,
    to exercise the "mit Zertifikaten" verification path.
    """
    order_data = _hpb_order_data(bank_keyring, host_id, certificates)
    transaction_key, encrypted = encrypt_order_data(
        subscriber_keyring.encryption.public_key(), order_data
    )
    namespace = h005.NAMESPACE
    root = etree.Element(
        etree.QName(namespace, "ebicsKeyManagementResponse"), nsmap={None: namespace}
    )
    root.set("Version", "H005")
    root.set("Revision", "1")
    header = etree.SubElement(root, etree.QName(namespace, "header"))
    mutable = etree.SubElement(header, etree.QName(namespace, "mutable"))
    etree.SubElement(mutable, etree.QName(namespace, "ReturnCode")).text = "000000"
    etree.SubElement(mutable, etree.QName(namespace, "ReportText")).text = "[EBICS_OK] OK"
    body = etree.SubElement(root, etree.QName(namespace, "body"))
    data_transfer = etree.SubElement(body, etree.QName(namespace, "DataTransfer"))
    encryption_info = etree.SubElement(data_transfer, etree.QName(namespace, "DataEncryptionInfo"))
    etree.SubElement(encryption_info, etree.QName(namespace, "TransactionKey")).text = (
        base64.b64encode(transaction_key).decode("ascii")
    )
    etree.SubElement(data_transfer, etree.QName(namespace, "OrderData")).text = base64.b64encode(
        encrypted
    ).decode("ascii")
    etree.SubElement(body, etree.QName(namespace, "ReturnCode")).text = "000000"
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def _hpb_order_data(
    bank_keyring: Keyring,
    host_id: str,
    certificates: Mapping[CertificateUsage, x509.Certificate] | None,
) -> bytes:
    namespace = h005.NAMESPACE
    certificates = certificates or {}
    root = etree.Element(
        etree.QName(namespace, "HPBResponseOrderData"), nsmap={None: namespace, "ds": _DS}
    )
    _pub_key_info(
        root, "AuthenticationPubKeyInfo", "AuthenticationVersion", "X002",
        bank_keyring.authentication, CertificateUsage.AUTHENTICATION,
        certificates.get(CertificateUsage.AUTHENTICATION),
    )
    _pub_key_info(
        root, "EncryptionPubKeyInfo", "EncryptionVersion", "E002",
        bank_keyring.encryption, CertificateUsage.ENCRYPTION,
        certificates.get(CertificateUsage.ENCRYPTION),
    )
    etree.SubElement(root, etree.QName(namespace, "HostID")).text = host_id
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def _pub_key_info(
    parent: etree._Element,
    info_tag: str,
    version_tag: str,
    version: str,
    private_key: rsa.RSAPrivateKey,
    usage: CertificateUsage,
    certificate: x509.Certificate | None = None,
) -> None:
    # H005 carries the bank key as an X.509 certificate, so the fixtures do too.
    namespace = h005.NAMESPACE
    if certificate is None:
        certificate = generate_self_signed_certificate(private_key, "BANK", usage)
    encoded = base64.b64encode(certificate.public_bytes(Encoding.DER)).decode("ascii")
    info = etree.SubElement(parent, etree.QName(namespace, info_tag))
    x509_data = etree.SubElement(info, etree.QName(_DS, "X509Data"))
    etree.SubElement(x509_data, etree.QName(_DS, "X509Certificate")).text = encoded
    etree.SubElement(info, etree.QName(namespace, version_tag)).text = version
