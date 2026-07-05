"""Tests for ebicsclient.protocol.h005: INI/HIA envelopes and response parsing.

These check structural consistency (the request is well-formed and the keys round-trip);
the exact H005 schema must still be validated against a bank test platform.
"""

import base64
import zlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from lxml import etree

from crypto_helpers import issue_certificate, make_ca, make_hpb_response
from ebicsclient import crypto, keys
from ebicsclient.certificates import MappingCertificateProvider, TrustAnchorVerifier
from ebicsclient.errors import BankCertificateError, ProtocolError, ReturnCodeError
from ebicsclient.keys import CertificateUsage
from ebicsclient.models import PAIN_001, Bank, BankKeys, Keyring, User
from ebicsclient.protocol import h005

_NS = h005.NAMESPACE
_S002 = h005.S002_NAMESPACE
_DS = "http://www.w3.org/2000/09/xmldsig#"

_OK_RESPONSE = (
    b'<?xml version="1.0"?>'
    b'<ebicsKeyManagementResponse xmlns="urn:org:ebics:H005" Version="H005" Revision="1">'
    b'<header authenticate="true"><mutable>'
    b"<ReturnCode>000000</ReturnCode><ReportText>[EBICS_OK] OK</ReportText>"
    b"</mutable></header><body><ReturnCode>000000</ReturnCode></body>"
    b"</ebicsKeyManagementResponse>"
)
_ERROR_RESPONSE = (
    b'<?xml version="1.0"?>'
    b'<ebicsKeyManagementResponse xmlns="urn:org:ebics:H005" Version="H005" Revision="1">'
    b'<header authenticate="true"><mutable>'
    b"<ReturnCode>091002</ReturnCode><ReportText>[EBICS_INVALID_USER_OR_USER_STATE]</ReportText>"
    b"</mutable></header><body><ReturnCode>091002</ReturnCode></body>"
    b"</ebicsKeyManagementResponse>"
)


@pytest.fixture(scope="module")
def bank() -> Bank:
    return Bank(host_id="ZKBKCHZZ", url="https://ebicsweb.example.com/ebicsweb")


@pytest.fixture(scope="module")
def user() -> User:
    return User(partner_id="PARTNER1", user_id="USER1")


@pytest.fixture(scope="module")
def keyring() -> Keyring:
    return keys.generate_keyring()


def _order_data(request_bytes: bytes) -> etree._Element:
    root = etree.fromstring(request_bytes)
    encoded = root.findtext(f".//{{{_NS}}}OrderData")
    assert encoded is not None
    return etree.fromstring(zlib.decompress(base64.b64decode(encoded)))


def _certified_modulus(element: etree._Element, namespace: str, info_tag: str) -> int:
    info = element.find(f".//{{{namespace}}}{info_tag}")
    assert info is not None
    certificate_base64 = info.findtext(f".//{{{_DS}}}X509Certificate")
    assert certificate_base64 is not None
    certificate = x509.load_der_x509_certificate(base64.b64decode(certificate_base64))
    public_key = certificate.public_key()
    assert isinstance(public_key, rsa.RSAPublicKey)
    return public_key.public_numbers().n


def test_ini_request_carries_host_and_user_ids(bank: Bank, user: User, keyring: Keyring) -> None:
    root = etree.fromstring(h005.build_ini_request(bank, user, keyring))
    assert root.findtext(f".//{{{_NS}}}HostID") == bank.host_id
    assert root.findtext(f".//{{{_NS}}}PartnerID") == user.partner_id
    assert root.findtext(f".//{{{_NS}}}UserID") == user.user_id
    assert root.findtext(f".//{{{_NS}}}AdminOrderType") == "INI"


def test_ini_order_data_carries_the_a006_signature_certificate(
    bank: Bank, user: User, keyring: Keyring
) -> None:
    order_data = _order_data(h005.build_ini_request(bank, user, keyring))
    # H005 signature key order data lives in the S002 namespace and carries an X.509 cert.
    assert order_data.tag == f"{{{_S002}}}SignaturePubKeyOrderData"
    assert order_data.findtext(f".//{{{_S002}}}SignatureVersion") == "A006"
    expected = keyring.signature.public_key().public_numbers().n
    assert _certified_modulus(order_data, _S002, "SignaturePubKeyInfo") == expected


def test_hia_request_carries_both_auth_and_encryption_certificates(
    bank: Bank, user: User, keyring: Keyring
) -> None:
    root = etree.fromstring(h005.build_hia_request(bank, user, keyring))
    assert root.findtext(f".//{{{_NS}}}AdminOrderType") == "HIA"
    order_data = _order_data(h005.build_hia_request(bank, user, keyring))
    assert order_data.findtext(f".//{{{_NS}}}AuthenticationVersion") == "X002"
    assert order_data.findtext(f".//{{{_NS}}}EncryptionVersion") == "E002"
    assert _certified_modulus(order_data, _NS, "AuthenticationPubKeyInfo") == (
        keyring.authentication.public_key().public_numbers().n
    )
    assert _certified_modulus(order_data, _NS, "EncryptionPubKeyInfo") == (
        keyring.encryption.public_key().public_numbers().n
    )


def test_raise_for_return_code_accepts_ok() -> None:
    h005.raise_for_return_code(_OK_RESPONSE)  # does not raise


def test_raise_for_return_code_raises_on_error() -> None:
    with pytest.raises(ReturnCodeError) as caught:
        h005.raise_for_return_code(_ERROR_RESPONSE)
    assert caught.value.code == "091002"
    assert caught.value.text is not None


def test_raise_for_return_code_rejects_a_response_without_a_code() -> None:
    with pytest.raises(ProtocolError):
        h005.raise_for_return_code(b'<x xmlns="urn:org:ebics:H005"/>')


def test_hpb_request_is_signed_and_carries_the_admin_order_type(
    bank: Bank, user: User, keyring: Keyring
) -> None:
    root = etree.fromstring(h005.build_hpb_request(bank, user, keyring))
    assert root.tag == f"{{{_NS}}}ebicsNoPubKeyDigestsRequest"
    assert root.findtext(f".//{{{_NS}}}AdminOrderType") == "HPB"
    assert root.findtext(f".//{{{_NS}}}HostID") == bank.host_id
    assert root.find(f".//{{{_NS}}}Nonce") is not None
    assert root.find(f".//{{{_NS}}}Timestamp") is not None
    assert crypto.verify_auth_signature(root, keyring.authentication.public_key())


def test_parse_hpb_response_recovers_the_bank_public_keys(keyring: Keyring) -> None:
    bank_keyring = keys.generate_keyring()
    response = make_hpb_response(keyring, bank_keyring)
    authentication, encryption = h005.parse_hpb_response(response, keyring)
    expected_authentication = bank_keyring.authentication.public_key().public_numbers()
    expected_encryption = bank_keyring.encryption.public_key().public_numbers()
    assert authentication.public_numbers() == expected_authentication
    assert encryption.public_numbers() == expected_encryption


def test_parse_hpb_response_raises_on_a_non_ok_return_code(keyring: Keyring) -> None:
    with pytest.raises(ReturnCodeError):
        h005.parse_hpb_response(_ERROR_RESPONSE, keyring)


def test_ini_request_embeds_a_ca_issued_certificate_from_the_provider(
    bank: Bank, user: User, keyring: Keyring
) -> None:
    ca_key, ca_certificate = make_ca()
    provider = MappingCertificateProvider(
        {
            CertificateUsage.SIGNATURE: issue_certificate(
                ca_key, ca_certificate, keyring.signature.public_key(), CertificateUsage.SIGNATURE
            )
        }
    )
    order_data = _order_data(h005.build_ini_request(bank, user, keyring, provider))
    certificate_base64 = order_data.findtext(f".//{{{_DS}}}X509Certificate")
    assert certificate_base64 is not None
    certificate = x509.load_der_x509_certificate(base64.b64decode(certificate_base64))
    # The transmitted certificate is the CA-issued one, not a self-signed cert.
    assert certificate.issuer == ca_certificate.subject


def test_parse_hpb_response_verifies_bank_certificates_against_a_trust_anchor(
    keyring: Keyring,
) -> None:
    bank_keyring = keys.generate_keyring()
    ca_key, ca_certificate = make_ca("Bank CA")
    certificates = {
        CertificateUsage.AUTHENTICATION: issue_certificate(
            ca_key, ca_certificate, bank_keyring.authentication.public_key(),
            CertificateUsage.AUTHENTICATION,
        ),
        CertificateUsage.ENCRYPTION: issue_certificate(
            ca_key, ca_certificate, bank_keyring.encryption.public_key(),
            CertificateUsage.ENCRYPTION,
        ),
    }
    response = make_hpb_response(keyring, bank_keyring, certificates=certificates)
    verifier = TrustAnchorVerifier([ca_certificate])
    authentication, encryption = h005.parse_hpb_response(response, keyring, verifier)
    assert authentication.public_numbers() == (
        bank_keyring.authentication.public_key().public_numbers()
    )
    assert encryption.public_numbers() == bank_keyring.encryption.public_key().public_numbers()


def test_parse_hpb_response_rejects_bank_certificates_from_an_untrusted_anchor(
    keyring: Keyring,
) -> None:
    bank_keyring = keys.generate_keyring()
    ca_key, ca_certificate = make_ca("Bank CA")
    _, untrusted = make_ca("Untrusted CA")
    certificates = {
        CertificateUsage.AUTHENTICATION: issue_certificate(
            ca_key, ca_certificate, bank_keyring.authentication.public_key(),
            CertificateUsage.AUTHENTICATION,
        ),
        CertificateUsage.ENCRYPTION: issue_certificate(
            ca_key, ca_certificate, bank_keyring.encryption.public_key(),
            CertificateUsage.ENCRYPTION,
        ),
    }
    response = make_hpb_response(keyring, bank_keyring, certificates=certificates)
    with pytest.raises(BankCertificateError):
        h005.parse_hpb_response(response, keyring, TrustAnchorVerifier([untrusted]))


def test_parse_hpb_response_verifier_rejects_a_self_signed_bank_certificate(
    keyring: Keyring,
) -> None:
    # A "mit Schlüsseln" bank sends self-signed certs; a trust-anchor verifier rejects them
    # because they do not chain to the caller's anchor.
    bank_keyring = keys.generate_keyring()
    response = make_hpb_response(keyring, bank_keyring)
    _, ca_certificate = make_ca()
    with pytest.raises(BankCertificateError):
        h005.parse_hpb_response(response, keyring, TrustAnchorVerifier([ca_certificate]))


def test_public_key_from_info_falls_back_to_rsa_key_value(keyring: Keyring) -> None:
    # A bank that sends a legacy RSAKeyValue instead of an X.509 certificate is still read.
    numbers = keyring.authentication.public_key().public_numbers()
    root = etree.Element(f"{{{_NS}}}HPBResponseOrderData", nsmap={None: _NS, "ds": _DS})
    info = etree.SubElement(root, f"{{{_NS}}}AuthenticationPubKeyInfo")
    rsa_key_value = etree.SubElement(
        etree.SubElement(info, f"{{{_NS}}}PubKeyValue"), f"{{{_DS}}}RSAKeyValue"
    )
    etree.SubElement(rsa_key_value, f"{{{_DS}}}Modulus").text = _b64_int(numbers.n)
    etree.SubElement(rsa_key_value, f"{{{_DS}}}Exponent").text = _b64_int(numbers.e)
    recovered = h005._public_key_from_info(
        root, "AuthenticationPubKeyInfo", keys.CertificateUsage.AUTHENTICATION, None
    )
    assert recovered.public_numbers() == numbers


def _b64_int(value: int) -> str:
    return base64.b64encode(value.to_bytes((value.bit_length() + 7) // 8, "big")).decode("ascii")


def _bank_keys_from(bank_keyring: Keyring) -> BankKeys:
    return BankKeys(
        authentication=bank_keyring.authentication.public_key(),
        encryption=bank_keyring.encryption.public_key(),
    )


def test_upload_initialisation_request_is_signed_and_carries_the_btu_details(
    bank: Bank, user: User, keyring: Keyring
) -> None:
    bank_keyring = keys.generate_keyring()
    bank_keys = _bank_keys_from(bank_keyring)
    payload = h005.prepare_upload(user, keyring, bank_keys, b"<Document>pay</Document>")
    root = etree.fromstring(
        h005.build_upload_initialisation_request(
            bank, user, keyring, bank_keys, PAIN_001, payload
        )
    )
    assert root.findtext(f".//{{{_NS}}}AdminOrderType") == "BTU"
    assert root.findtext(f".//{{{_NS}}}ServiceName") == "MCT"
    assert root.findtext(f".//{{{_NS}}}MsgName") == "pain.001"
    assert root.findtext(f".//{{{_NS}}}NumSegments") == "1"
    assert root.findtext(f".//{{{_NS}}}SignatureFlag") == "true"
    data_digest = root.find(f".//{{{_NS}}}DataDigest")
    assert data_digest is not None
    assert data_digest.get("SignatureVersion") == "A006"
    assert crypto.verify_auth_signature(root, keyring.authentication.public_key())


def test_upload_transfer_request_is_signed_and_carries_the_segment(
    bank: Bank, keyring: Keyring
) -> None:
    root = etree.fromstring(
        h005.build_upload_transfer_request(
            bank, keyring, "A" * 32, 1, "c2VnbWVudA==", last_segment=True
        )
    )
    assert root.findtext(f".//{{{_NS}}}TransactionPhase") == "Transfer"
    assert root.findtext(f".//{{{_NS}}}OrderData") == "c2VnbWVudA=="
    segment = root.find(f".//{{{_NS}}}SegmentNumber")
    assert segment is not None and segment.get("lastSegment") == "true"
    assert crypto.verify_auth_signature(root, keyring.authentication.public_key())


def test_prepare_upload_round_trips_through_the_bank_side_crypto(
    user: User, keyring: Keyring
) -> None:
    order_data = b"<Document>a payment instruction</Document>"
    bank_keyring = keys.generate_keyring()
    payload = h005.prepare_upload(user, keyring, _bank_keys_from(bank_keyring), order_data)

    # The bank unwraps the transaction key with its E002 key and decrypts the order data.
    encrypted_order_data = base64.b64decode("".join(payload.order_data_segments))
    recovered = crypto.decrypt_order_data(
        bank_keyring.encryption, payload.wrapped_transaction_key, encrypted_order_data
    )
    assert recovered == order_data
    assert payload.data_digest == crypto.order_data_digest(order_data)

    # The bank decrypts the SignatureData, reads the A006 signature, and verifies it.
    signature_xml = crypto.decrypt_order_data(
        bank_keyring.encryption,
        payload.wrapped_transaction_key,
        base64.b64decode(payload.signature_data),
    )
    signature_root = etree.fromstring(signature_xml)
    assert signature_root.findtext(f".//{{{_S002}}}SignatureVersion") == "A006"
    assert signature_root.findtext(f".//{{{_S002}}}UserID") == user.user_id
    signature_value = signature_root.findtext(f".//{{{_S002}}}SignatureValue")
    assert signature_value is not None
    keyring.signature.public_key().verify(
        base64.b64decode(signature_value),
        order_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
        hashes.SHA256(),
    )


def _receipt_response(code: str, report: str) -> bytes:
    return (
        f'<ebicsResponse xmlns="{_NS}"><header authenticate="true"><static/><mutable>'
        f"<TransactionPhase>Receipt</TransactionPhase><ReturnCode>{code}</ReturnCode>"
        f"<ReportText>{report}</ReportText></mutable></header>"
        f"<body><ReturnCode>{code}</ReturnCode></body></ebicsResponse>"
    ).encode()


def test_parse_download_receipt_response_accepts_the_positive_acknowledgement() -> None:
    # A real bank answers a positive receipt with 011000 (validated live on ZKB).
    h005.parse_download_receipt_response(
        _receipt_response("011000", "[EBICS_DOWNLOAD_POSTPROCESS_DONE] Positive acknowledgement")
    )  # does not raise


def test_parse_download_receipt_response_accepts_plain_ok() -> None:
    h005.parse_download_receipt_response(_receipt_response("000000", "[EBICS_OK] OK"))


def test_parse_download_receipt_response_raises_on_a_genuine_error() -> None:
    with pytest.raises(ReturnCodeError) as caught:
        h005.parse_download_receipt_response(
            _receipt_response("091010", "[EBICS_TX_UNKNOWN_TXID] Transaction unknown")
        )
    assert caught.value.code == "091010"


def test_parse_upload_initialisation_response_returns_the_transaction_id() -> None:
    response = (
        f'<ebicsResponse xmlns="{_NS}"><header authenticate="true"><static>'
        f"<TransactionID>{'D' * 32}</TransactionID></static><mutable>"
        "<TransactionPhase>Initialisation</TransactionPhase><ReturnCode>000000</ReturnCode>"
        "</mutable></header><body><ReturnCode>000000</ReturnCode></body></ebicsResponse>"
    ).encode()
    assert h005.parse_upload_initialisation_response(response) == "D" * 32


def test_parse_upload_transfer_response_raises_on_error() -> None:
    response = (
        f'<ebicsResponse xmlns="{_NS}"><header authenticate="true"><static/><mutable>'
        "<TransactionPhase>Transfer</TransactionPhase><ReturnCode>091001</ReturnCode>"
        "</mutable></header><body><ReturnCode>091001</ReturnCode></body></ebicsResponse>"
    ).encode()
    with pytest.raises(ReturnCodeError):
        h005.parse_upload_transfer_response(response)


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
    root = etree.Element(f"{{{_NS}}}ebicsResponse", nsmap={None: _NS})
    root.set("Version", "H005")
    root.set("Revision", "1")
    header = etree.SubElement(root, f"{{{_NS}}}header")
    header.set("authenticate", "true")
    static = etree.SubElement(header, f"{{{_NS}}}static")
    if transaction_id is not None:
        etree.SubElement(static, f"{{{_NS}}}TransactionID").text = transaction_id
    if num_segments is not None:
        etree.SubElement(static, f"{{{_NS}}}NumSegments").text = str(num_segments)
    mutable = etree.SubElement(header, f"{{{_NS}}}mutable")
    etree.SubElement(mutable, f"{{{_NS}}}TransactionPhase").text = phase
    segment = etree.SubElement(mutable, f"{{{_NS}}}SegmentNumber")
    segment.text = str(segment_number)
    segment.set("lastSegment", "true" if last_segment else "false")
    etree.SubElement(mutable, f"{{{_NS}}}ReturnCode").text = "000000"
    etree.SubElement(mutable, f"{{{_NS}}}ReportText").text = "[EBICS_OK] OK"
    body = etree.SubElement(root, f"{{{_NS}}}body")
    data_transfer = etree.SubElement(body, f"{{{_NS}}}DataTransfer")
    if transaction_key is not None:
        info = etree.SubElement(data_transfer, f"{{{_NS}}}DataEncryptionInfo")
        digest = etree.SubElement(info, f"{{{_NS}}}EncryptionPubKeyDigest")
        digest.set("Version", "E002")
        digest.text = base64.b64encode(b"digest").decode("ascii")
        etree.SubElement(info, f"{{{_NS}}}TransactionKey").text = transaction_key
    etree.SubElement(data_transfer, f"{{{_NS}}}OrderData").text = order_data
    etree.SubElement(body, f"{{{_NS}}}ReturnCode").text = "000000"
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


def test_parse_download_initialisation_response_extracts_the_transaction() -> None:
    transaction_key = base64.b64encode(b"encrypted-key").decode("ascii")
    response = _download_response(
        phase="Initialisation",
        segment_number=1,
        last_segment=False,
        order_data="c2VnbWVudC1vbmU=",
        transaction_id="A" * 32,
        num_segments=3,
        transaction_key=transaction_key,
    )
    result = h005.parse_download_initialisation_response(response)
    assert result.transaction_id == "A" * 32
    assert result.num_segments == 3
    assert result.transaction_key == b"encrypted-key"
    assert result.segment_number == 1
    assert result.last_segment is False
    assert result.order_data_segment == "c2VnbWVudC1vbmU="


def test_parse_download_initialisation_response_marks_a_single_segment_as_last() -> None:
    response = _download_response(
        phase="Initialisation",
        segment_number=1,
        last_segment=True,
        order_data="b25seQ==",
        transaction_id="B" * 32,
        num_segments=1,
        transaction_key=base64.b64encode(b"k").decode("ascii"),
    )
    result = h005.parse_download_initialisation_response(response)
    assert result.num_segments == 1
    assert result.last_segment is True


def test_parse_download_initialisation_response_raises_on_a_non_ok_return_code() -> None:
    with pytest.raises(ReturnCodeError):
        h005.parse_download_initialisation_response(_ERROR_RESPONSE)


def test_parse_download_initialisation_response_rejects_a_missing_transaction_key() -> None:
    response = _download_response(
        phase="Initialisation",
        segment_number=1,
        last_segment=True,
        order_data="b25seQ==",
        transaction_id="C" * 32,
        num_segments=1,
    )
    with pytest.raises(ProtocolError):
        h005.parse_download_initialisation_response(response)


def test_parse_download_segment_response_extracts_the_segment() -> None:
    response = _download_response(
        phase="Transfer",
        segment_number=2,
        last_segment=True,
        order_data="c2Vjb25k",
    )
    result = h005.parse_download_segment_response(response)
    assert result.segment_number == 2
    assert result.last_segment is True
    assert result.order_data_segment == "c2Vjb25k"


def test_parse_download_segment_response_reads_a_non_final_segment() -> None:
    response = _download_response(
        phase="Transfer",
        segment_number=2,
        last_segment=False,
        order_data="bWlkZGxl",
    )
    result = h005.parse_download_segment_response(response)
    assert result.segment_number == 2
    assert result.last_segment is False


def test_parse_download_response_rejects_a_segment_number_without_last_segment_flag() -> None:
    root = etree.Element(f"{{{_NS}}}ebicsResponse", nsmap={None: _NS})
    header = etree.SubElement(root, f"{{{_NS}}}header")
    etree.SubElement(header, f"{{{_NS}}}static")
    mutable = etree.SubElement(header, f"{{{_NS}}}mutable")
    etree.SubElement(mutable, f"{{{_NS}}}SegmentNumber").text = "1"
    etree.SubElement(mutable, f"{{{_NS}}}ReturnCode").text = "000000"
    body = etree.SubElement(root, f"{{{_NS}}}body")
    etree.SubElement(body, f"{{{_NS}}}ReturnCode").text = "000000"
    with pytest.raises(ProtocolError):
        h005.parse_download_segment_response(etree.tostring(root))
