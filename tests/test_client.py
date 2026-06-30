"""Tests for ebicsclient.client: INI/HIA orchestration with a fake transport."""

import pytest
from lxml import etree

from crypto_helpers import make_hpb_response
from ebicsclient import keys
from ebicsclient.client import Client
from ebicsclient.errors import ReturnCodeError
from ebicsclient.models import Bank, Keyring, OutputFormat, User

_NS = "urn:org:ebics:H005"
_OK_RESPONSE = (
    b'<ebicsKeyManagementResponse xmlns="urn:org:ebics:H005">'
    b"<header><mutable><ReturnCode>000000</ReturnCode></mutable></header>"
    b"<body><ReturnCode>000000</ReturnCode></body></ebicsKeyManagementResponse>"
)
_ERROR_RESPONSE = (
    b'<ebicsKeyManagementResponse xmlns="urn:org:ebics:H005">'
    b"<header><mutable><ReturnCode>091002</ReturnCode></mutable></header>"
    b"<body><ReturnCode>091002</ReturnCode></body></ebicsKeyManagementResponse>"
)


class _FakeTransport:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.posted: bytes | None = None

    def post(self, body: bytes) -> bytes:
        self.posted = body
        return self.response


@pytest.fixture(scope="module")
def keyring() -> Keyring:
    return keys.generate_keyring()


def _client(response: bytes, keyring: Keyring) -> tuple[Client, _FakeTransport]:
    transport = _FakeTransport(response)
    client = Client(
        Bank(host_id="HOST", url="https://example.com/ebicsweb"),
        User(partner_id="PARTNER1", user_id="USER1"),
        keyring,
        transport=transport,  # type: ignore[arg-type]
    )
    return client, transport


def test_ini_posts_a_signature_key_request(keyring: Keyring) -> None:
    client, transport = _client(_OK_RESPONSE, keyring)
    client.ini()
    assert transport.posted is not None
    assert etree.fromstring(transport.posted).findtext(f".//{{{_NS}}}OrderType") == "INI"


def test_hia_posts_an_auth_and_encryption_request(keyring: Keyring) -> None:
    client, transport = _client(_OK_RESPONSE, keyring)
    client.hia()
    assert transport.posted is not None
    assert etree.fromstring(transport.posted).findtext(f".//{{{_NS}}}OrderType") == "HIA"


def test_ini_raises_when_the_bank_rejects(keyring: Keyring) -> None:
    client, _ = _client(_ERROR_RESPONSE, keyring)
    with pytest.raises(ReturnCodeError):
        client.ini()


def test_hpb_stores_and_returns_the_bank_keys(keyring: Keyring) -> None:
    bank_keyring = keys.generate_keyring()
    client, transport = _client(make_hpb_response(keyring, bank_keyring), keyring)
    bank_keys = client.hpb()
    assert transport.posted is not None
    posted = etree.fromstring(transport.posted)
    assert posted.findtext(f".//{{{_NS}}}AdminOrderType") == "HPB"
    expected = bank_keyring.encryption.public_key().public_numbers()
    assert bank_keys.encryption.public_numbers() == expected
    assert client.bank_keys is bank_keys


def test_make_ini_letter_renders_html(keyring: Keyring) -> None:
    client, _ = _client(_OK_RESPONSE, keyring)
    letter = client.make_ini_letter(output_format=OutputFormat.HTML)
    assert letter.output_format is OutputFormat.HTML
    assert b"EBICS Initialisation Letter" in letter.content
