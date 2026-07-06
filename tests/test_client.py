"""Tests for ebicsclient.client: INI/HIA orchestration with a fake transport."""

import io
import zipfile
from decimal import Decimal
from pathlib import Path

import pytest
from lxml import etree

from crypto_helpers import make_download_responses, make_hpb_response, sign_response
from ebicsclient import keys
from ebicsclient.client import Client
from ebicsclient.errors import (
    BankKeyMismatchError,
    ClientStateError,
    ResponseAuthenticationError,
    ReturnCodeError,
)
from ebicsclient.models import (
    CAMT_053,
    PAIN_001,
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


@pytest.fixture(scope="module")
def bank_keyring() -> Keyring:
    return keys.generate_keyring()


def test_download_returns_the_decrypted_order_data_single_segment(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    order_data = b"<Document>a single-segment statement</Document>"
    responses = make_download_responses(
        keyring, order_data, bank_keyring=bank_keyring, num_segments=1
    )
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    assert client.download(CAMT_053) == order_data
    # Initialisation + receipt only (no transfer): the first request opens, the last receipts.
    assert len(transport.posts) == 2
    opened = etree.fromstring(transport.posts[0])
    assert opened.findtext(f".//{{{_NS}}}AdminOrderType") == "BTD"
    assert opened.findtext(f".//{{{_NS}}}ServiceName") == "EOP"


def test_download_reassembles_multiple_segments(keyring: Keyring, bank_keyring: Keyring) -> None:
    order_data = b"<Document>" + b"x" * 5000 + b"</Document>"
    responses = make_download_responses(
        keyring, order_data, bank_keyring=bank_keyring, num_segments=3
    )
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    assert client.download(CAMT_053) == order_data
    # Initialisation + two transfers + receipt.
    assert len(transport.posts) == 4
    phases = [
        etree.fromstring(post).findtext(f".//{{{_NS}}}TransactionPhase") for post in transport.posts
    ]
    assert phases == ["Initialisation", "Transfer", "Transfer", "Receipt"]


def test_download_rejects_an_unsigned_response(keyring: Keyring, bank_keyring: Keyring) -> None:
    # Strip the bank's AuthSignature off an otherwise valid response: the client must
    # refuse it before looking at anything else — including the return code.
    responses = make_download_responses(
        keyring, b"<Document/>", bank_keyring=bank_keyring, num_segments=1
    )
    root = etree.fromstring(responses[0])
    signature = root.find(f"{{{_NS}}}AuthSignature")
    assert signature is not None
    root.remove(signature)
    client, _ = _download_client([etree.tostring(root)], keyring, _bank_keys(bank_keyring))
    with pytest.raises(ResponseAuthenticationError):
        client.download(CAMT_053)


def test_download_rejects_a_response_signed_by_the_wrong_key(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    imposter = keys.generate_keyring()
    responses = make_download_responses(
        keyring, b"<Document/>", bank_keyring=imposter, num_segments=1
    )
    client, _ = _download_client(responses, keyring, _bank_keys(bank_keyring))
    with pytest.raises(ResponseAuthenticationError):
        client.download(CAMT_053)


def test_download_statements_parses_a_camt053_zip(keyring: Keyring, bank_keyring: Keyring) -> None:
    document = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.053.001.08"><BkToCstmrStmt>'
        b"<Stmt><Id>STMT-1</Id>"
        b"<Acct><Id><IBAN>CH9300762011623852957</IBAN></Id></Acct>"
        b"<Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp>"
        b'<Amt Ccy="CHF">42.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><Dt>2026-06-30</Dt></Dt></Bal>'
        b"</Stmt></BkToCstmrStmt></Document>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("statement.xml", document)
    responses = make_download_responses(
        keyring, buffer.getvalue(), bank_keyring=bank_keyring, num_segments=1
    )
    client, _ = _download_client(responses, keyring, _bank_keys(bank_keyring))
    (statement,) = client.download_statements()
    assert statement.identification == "STMT-1"
    assert statement.closing_balance is not None
    assert statement.closing_balance.amount == Decimal("42.00")


def _upload_response(
    phase: str, bank_keyring: Keyring, *, transaction_id: str | None = None
) -> bytes:
    static = f"<TransactionID>{transaction_id}</TransactionID>" if transaction_id else ""
    response = (
        f'<ebicsResponse xmlns="urn:org:ebics:H005"><header authenticate="true">'
        f"<static>{static}</static><mutable><TransactionPhase>{phase}</TransactionPhase>"
        "<ReturnCode>000000</ReturnCode></mutable></header>"
        "<body><ReturnCode>000000</ReturnCode></body></ebicsResponse>"
    ).encode()
    return sign_response(response, bank_keyring)


def test_download_payment_status_reports_parses_a_pain002_zip(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    document = (Path(__file__).parent / "data" / "pain002_part.xml").read_bytes()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("report.xml", document)
    responses = make_download_responses(
        keyring, buffer.getvalue(), bank_keyring=bank_keyring, num_segments=1
    )
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    (report,) = client.download_payment_status_reports()
    assert report.group_status == "PART"
    assert len(report.rejected_transactions) == 2
    opened = etree.fromstring(transport.posts[0])
    assert opened.findtext(f".//{{{_NS}}}ServiceName") == "PSR"


def test_upload_requires_hpb_first(keyring: Keyring) -> None:
    client, _ = _client(_OK_RESPONSE, keyring)
    with pytest.raises(ClientStateError):
        client.upload(PAIN_001, b"<Document/>")


def test_upload_signs_encrypts_and_sends_init_then_transfer(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    responses = [
        _upload_response("Initialisation", bank_keyring, transaction_id="E" * 32),
        _upload_response("Transfer", bank_keyring),
    ]
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    assert client.upload(PAIN_001, b"<Document>pay</Document>") == "E" * 32
    # Initialisation opens the transaction (BTU); the transfer sends the single segment.
    assert len(transport.posts) == 2
    opened = etree.fromstring(transport.posts[0])
    assert opened.findtext(f".//{{{_NS}}}AdminOrderType") == "BTU"
    assert opened.findtext(f".//{{{_NS}}}MsgName") == "pain.001"
    transferred = etree.fromstring(transport.posts[1])
    assert transferred.findtext(f".//{{{_NS}}}TransactionPhase") == "Transfer"
    assert transferred.find(f".//{{{_NS}}}OrderData") is not None


def test_upload_raises_when_the_bank_rejects_the_signature(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    reject = sign_response(
        b'<ebicsResponse xmlns="urn:org:ebics:H005"><header authenticate="true"><static/>'
        b"<mutable><TransactionPhase>Initialisation</TransactionPhase>"
        b"<ReturnCode>091002</ReturnCode></mutable></header>"
        b"<body><ReturnCode>091002</ReturnCode></body></ebicsResponse>",
        bank_keyring,
    )
    client, _ = _download_client([reject], keyring, _bank_keys(bank_keyring))
    with pytest.raises(ReturnCodeError) as caught:
        client.upload(PAIN_001, b"<Document/>")
    assert caught.value.code == "091002"


def test_download_raises_when_the_bank_reports_an_error(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    error = sign_response(
        b'<ebicsResponse xmlns="urn:org:ebics:H005">'
        b'<header authenticate="true"><static/>'
        b"<mutable><TransactionPhase>Initialisation</TransactionPhase>"
        b"<ReturnCode>090005</ReturnCode></mutable></header>"
        b"<body><ReturnCode>090005</ReturnCode></body></ebicsResponse>",
        bank_keyring,
    )
    client, _ = _download_client([error], keyring, _bank_keys(bank_keyring))
    with pytest.raises(ReturnCodeError) as caught:
        client.download(CAMT_053)
    assert caught.value.code == "090005"


def test_subscriber_info_runs_the_htd_admin_download(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    order_data = (Path(__file__).parent / "data" / "htd_zkb_sample.xml").read_bytes()
    responses = make_download_responses(
        keyring, order_data, bank_keyring=bank_keyring, num_segments=1
    )
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    info = client.subscriber_info()
    assert info.user_id == "USER1"
    opened = etree.fromstring(transport.posts[0])
    assert opened.findtext(f".//{{{_NS}}}AdminOrderType") == "HTD"
    assert opened.find(f".//{{{_NS}}}StandardOrderParams") is not None


def test_available_order_types_runs_the_haa_admin_download(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    order_data = f'<HAAResponseOrderData xmlns="{_NS}"/>'.encode()
    responses = make_download_responses(
        keyring, order_data, bank_keyring=bank_keyring, num_segments=1
    )
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    assert client.available_order_types() == []
    opened = etree.fromstring(transport.posts[0])
    assert opened.findtext(f".//{{{_NS}}}AdminOrderType") == "HAA"


def test_hpb_pinning_accepts_matching_bank_keys(keyring: Keyring) -> None:
    bank_keyring = keys.generate_keyring()
    client, _ = _client(make_hpb_response(keyring, bank_keyring), keyring)
    # Pin to the correct hashes (as a caller would after a first, trusted HPB).
    pinned = keys.bank_key_hashes(
        BankKeys(
            authentication=bank_keyring.authentication.public_key(),
            encryption=bank_keyring.encryption.public_key(),
        )
    )
    assert client.hpb(pinned=pinned).encryption.public_numbers() == (
        bank_keyring.encryption.public_key().public_numbers()
    )


def test_hpb_pinning_rejects_changed_bank_keys(keyring: Keyring) -> None:
    bank_keyring = keys.generate_keyring()
    client, _ = _client(make_hpb_response(keyring, bank_keyring), keyring)
    # Pin to a different bank's hashes — the downloaded keys must not be trusted.
    other = keys.generate_keyring()
    pinned = keys.bank_key_hashes(
        BankKeys(
            authentication=other.authentication.public_key(),
            encryption=other.encryption.public_key(),
        )
    )
    with pytest.raises(BankKeyMismatchError):
        client.hpb(pinned=pinned)
    assert client.bank_keys is None  # a mismatch never caches the keys


def test_make_ini_letter_renders_html(keyring: Keyring) -> None:
    client, _ = _client(_OK_RESPONSE, keyring)
    letter = client.make_ini_letter(output_format=OutputFormat.HTML)
    assert letter.output_format is OutputFormat.HTML
    assert b"EBICS Initialisation Letter" in letter.content
