"""Tests for ebicsclient.client: INI/HIA orchestration with a fake transport."""

import pytest
from lxml import etree

from crypto_helpers import make_download_responses, make_hpb_response
from ebicsclient import keys
from ebicsclient.client import Client
from ebicsclient.errors import ClientStateError, ReturnCodeError
from ebicsclient.models import (
    CAMT_053,
    Bank,
    BankKeys,
    InitializationState,
    Keyring,
    OutputFormat,
    User,
)

_NS = "urn:org:ebics:H005"
_OK_RESPONSE = (
    b'<ebicsKeyManagementResponse xmlns="urn:org:ebics:H005">'
    b"<header><mutable><ReturnCode>000000</ReturnCode></mutable></header>"
    b"<body><ReturnCode>000000</ReturnCode></body></ebicsKeyManagementResponse>"
)
# 061099 EBICS_INTERNAL_ERROR — a genuine hard rejection.
_ERROR_RESPONSE = (
    b'<ebicsKeyManagementResponse xmlns="urn:org:ebics:H005">'
    b"<header><mutable><ReturnCode>061099</ReturnCode></mutable></header>"
    b"<body><ReturnCode>061099</ReturnCode></body></ebicsKeyManagementResponse>"
)
# 091002 EBICS_INVALID_USER_OR_USER_STATE — a re-run of an already-initialised subscriber.
_ALREADY_INITIALISED_RESPONSE = (
    b'<ebicsKeyManagementResponse xmlns="urn:org:ebics:H005">'
    b"<header><mutable><ReturnCode>091002</ReturnCode>"
    b"<ReportText>[EBICS_INVALID_USER_OR_USER_STATE]</ReportText></mutable></header>"
    b"<body><ReturnCode>000000</ReturnCode></body></ebicsKeyManagementResponse>"
)


class _FakeTransport:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.posted: bytes | None = None

    def post(self, body: bytes) -> bytes:
        self.posted = body
        return self.response


class _QueueTransport:
    """Returns queued responses in order and records every request posted."""

    def __init__(self, responses: list[bytes]) -> None:
        self._responses = list(responses)
        self.posts: list[bytes] = []

    def post(self, body: bytes) -> bytes:
        self.posts.append(body)
        return self._responses.pop(0)


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
    assert client.ini() is InitializationState.SUBMITTED
    assert transport.posted is not None
    assert etree.fromstring(transport.posted).findtext(f".//{{{_NS}}}AdminOrderType") == "INI"


def test_ini_reports_already_initialised_without_raising(keyring: Keyring) -> None:
    client, _ = _client(_ALREADY_INITIALISED_RESPONSE, keyring)
    assert client.ini() is InitializationState.ALREADY_INITIALISED


def test_hia_reports_already_initialised_without_raising(keyring: Keyring) -> None:
    client, _ = _client(_ALREADY_INITIALISED_RESPONSE, keyring)
    assert client.hia() is InitializationState.ALREADY_INITIALISED


def test_hia_posts_an_auth_and_encryption_request(keyring: Keyring) -> None:
    client, transport = _client(_OK_RESPONSE, keyring)
    client.hia()
    assert transport.posted is not None
    assert etree.fromstring(transport.posted).findtext(f".//{{{_NS}}}AdminOrderType") == "HIA"


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


def _download_client(
    responses: list[bytes], keyring: Keyring, bank_keys: BankKeys
) -> tuple[Client, _QueueTransport]:
    transport = _QueueTransport(responses)
    client = Client(
        Bank(host_id="HOST", url="https://example.com/ebicsweb"),
        User(partner_id="PARTNER1", user_id="USER1"),
        keyring,
        transport=transport,  # type: ignore[arg-type]
    )
    client._bank_keys = bank_keys  # HPB already ran; wire the keys the download needs.
    return client, transport


def _bank_keys(bank_keyring: Keyring) -> BankKeys:
    return BankKeys(
        authentication=bank_keyring.authentication.public_key(),
        encryption=bank_keyring.encryption.public_key(),
    )


def test_download_requires_hpb_first(keyring: Keyring) -> None:
    client, _ = _client(_OK_RESPONSE, keyring)
    with pytest.raises(ClientStateError):
        client.download(CAMT_053)


def test_download_returns_the_decrypted_order_data_single_segment(keyring: Keyring) -> None:
    order_data = b"<Document>a single-segment statement</Document>"
    responses = make_download_responses(keyring, order_data, num_segments=1)
    client, transport = _download_client(responses, keyring, _bank_keys(keys.generate_keyring()))
    assert client.download(CAMT_053) == order_data
    # Initialisation + receipt only (no transfer): the first request opens, the last receipts.
    assert len(transport.posts) == 2
    opened = etree.fromstring(transport.posts[0])
    assert opened.findtext(f".//{{{_NS}}}AdminOrderType") == "BTD"
    assert opened.findtext(f".//{{{_NS}}}ServiceName") == "EOP"


def test_download_reassembles_multiple_segments(keyring: Keyring) -> None:
    order_data = b"<Document>" + b"x" * 5000 + b"</Document>"
    responses = make_download_responses(keyring, order_data, num_segments=3)
    client, transport = _download_client(responses, keyring, _bank_keys(keys.generate_keyring()))
    assert client.download(CAMT_053) == order_data
    # Initialisation + two transfers + receipt.
    assert len(transport.posts) == 4
    phases = [
        etree.fromstring(post).findtext(f".//{{{_NS}}}TransactionPhase") for post in transport.posts
    ]
    assert phases == ["Initialisation", "Transfer", "Transfer", "Receipt"]


def test_download_raises_when_the_bank_reports_an_error(keyring: Keyring) -> None:
    error = (
        b'<ebicsResponse xmlns="urn:org:ebics:H005">'
        b"<header><static/><mutable><TransactionPhase>Initialisation</TransactionPhase>"
        b"<ReturnCode>090005</ReturnCode></mutable></header>"
        b"<body><ReturnCode>090005</ReturnCode></body></ebicsResponse>"
    )
    client, _ = _download_client([error], keyring, _bank_keys(keys.generate_keyring()))
    with pytest.raises(ReturnCodeError) as caught:
        client.download(CAMT_053)
    assert caught.value.code == "090005"


def test_make_ini_letter_renders_html(keyring: Keyring) -> None:
    client, _ = _client(_OK_RESPONSE, keyring)
    letter = client.make_ini_letter(output_format=OutputFormat.HTML)
    assert letter.output_format is OutputFormat.HTML
    assert b"EBICS Initialisation Letter" in letter.content
