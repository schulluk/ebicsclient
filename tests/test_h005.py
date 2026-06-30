"""Tests for ebicsclient.protocol.h005: INI/HIA envelopes and response parsing.

These check structural consistency (the request is well-formed and the keys round-trip);
the exact H005 schema must still be validated against a bank test platform.
"""

import base64
import zlib

import pytest
from lxml import etree

from crypto_helpers import make_hpb_response
from ebicsclient import crypto, keys
from ebicsclient.errors import ProtocolError, ReturnCodeError
from ebicsclient.models import Bank, Keyring, User
from ebicsclient.protocol import h005

_NS = h005.NAMESPACE
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


def _modulus(element: etree._Element, info_tag: str) -> int:
    info = element.find(f".//{{{_NS}}}{info_tag}")
    assert info is not None
    encoded = info.findtext(f".//{{{_DS}}}Modulus")
    assert encoded is not None
    return int.from_bytes(base64.b64decode(encoded), "big")


def test_ini_request_carries_host_and_user_ids(bank: Bank, user: User, keyring: Keyring) -> None:
    root = etree.fromstring(h005.build_ini_request(bank, user, keyring))
    assert root.findtext(f".//{{{_NS}}}HostID") == bank.host_id
    assert root.findtext(f".//{{{_NS}}}PartnerID") == user.partner_id
    assert root.findtext(f".//{{{_NS}}}UserID") == user.user_id
    assert root.findtext(f".//{{{_NS}}}OrderType") == "INI"


def test_ini_order_data_carries_the_a006_signature_key(
    bank: Bank, user: User, keyring: Keyring
) -> None:
    order_data = _order_data(h005.build_ini_request(bank, user, keyring))
    assert order_data.tag == f"{{{_NS}}}SignaturePubKeyOrderData"
    assert order_data.findtext(f".//{{{_NS}}}SignatureVersion") == "A006"
    expected = keyring.signature.public_key().public_numbers().n
    assert _modulus(order_data, "SignaturePubKeyInfo") == expected


def test_hia_request_carries_both_auth_and_encryption_keys(
    bank: Bank, user: User, keyring: Keyring
) -> None:
    root = etree.fromstring(h005.build_hia_request(bank, user, keyring))
    assert root.findtext(f".//{{{_NS}}}OrderType") == "HIA"
    order_data = _order_data(h005.build_hia_request(bank, user, keyring))
    assert order_data.findtext(f".//{{{_NS}}}AuthenticationVersion") == "X002"
    assert order_data.findtext(f".//{{{_NS}}}EncryptionVersion") == "E002"
    assert _modulus(order_data, "AuthenticationPubKeyInfo") == (
        keyring.authentication.public_key().public_numbers().n
    )
    assert _modulus(order_data, "EncryptionPubKeyInfo") == (
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
