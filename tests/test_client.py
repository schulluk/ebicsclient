"""Tests for ebicsclient.client: INI/HIA orchestration with a fake transport."""

import pytest
from lxml import etree

from ebicsclient import keys
from ebicsclient.client import Client
from ebicsclient.errors import ReturnCodeError
from ebicsclient.models import Bank, Keyring, User

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
