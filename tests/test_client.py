"""Tests for ebicsclient.client: INI/HIA orchestration with a fake transport."""

import datetime
import io
import logging
import zipfile
from decimal import Decimal
from pathlib import Path

import pytest
from lxml import etree

from crypto_helpers import (
    issue_certificate,
    make_ca,
    make_download_responses,
    make_hpb_response,
    sign_response,
)
from ebicsclient import crypto, keys
from ebicsclient.certificates import MappingCertificateProvider
from ebicsclient.client import Client
from ebicsclient.errors import (
    BankKeyMismatchError,
    ClientStateError,
    CryptoError,
    DateRangeMismatchError,
    KeyChangeUnconfirmedError,
    MessageFormatError,
    MessageVersionMismatchError,
    ResponseAuthenticationError,
    ReturnCodeError,
    TransportError,
)
from ebicsclient.keys import CertificateUsage
from ebicsclient.models import (
    CAMT_053,
    PAIN_001,
    Bank,
    BankKeys,
    BusinessTransactionFormat,
    DateRange,
    InitializationState,
    Keyring,
    KeyRotation,
    OutputFormat,
    ReceiptPolicy,
    User,
    VersionPolicy,
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
    """Returns queued responses in order and records every request posted.

    A queued exception is raised instead of returned, to simulate a failed exchange.
    """

    def __init__(self, responses: list[bytes | Exception]) -> None:
        self._responses = list(responses)
        self.posts: list[bytes] = []

    def post(self, body: bytes) -> bytes:
        self.posts.append(body)
        response = self._responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


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
    responses: list[bytes | Exception],
    keyring: Keyring,
    bank_keys: BankKeys,
    *,
    version_policy: VersionPolicy = VersionPolicy.ACCEPT_ANY,
) -> tuple[Client, _QueueTransport]:
    transport = _QueueTransport(responses)
    client = Client(
        Bank(host_id="HOST", url="https://example.com/ebicsweb"),
        User(partner_id="PARTNER1", user_id="USER1"),
        keyring,
        transport=transport,  # type: ignore[arg-type]
        version_policy=version_policy,
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


def _receipt_code(post: bytes) -> str | None:
    return etree.fromstring(post).findtext(f".//{{{_NS}}}ReceiptCode")


def test_default_download_sends_a_positive_receipt(keyring: Keyring, bank_keyring: Keyring) -> None:
    responses = make_download_responses(
        keyring, b"<Document/>", bank_keyring=bank_keyring, num_segments=1
    )
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    client.download(CAMT_053)
    # The last post is the receipt; ReceiptCode 0 = positive (consume).
    assert _receipt_code(transport.posts[-1]) == "0"


def test_keep_policy_sends_a_negative_receipt_but_returns_the_data(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    order_data = b"<Document>peek</Document>"
    responses = make_download_responses(
        keyring, order_data, bank_keyring=bank_keyring, num_segments=1
    )
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    # KEEP: the caller reads the data but the bank must not consume it.
    assert client.download(CAMT_053, receipt_policy=ReceiptPolicy.KEEP) == order_data
    assert _receipt_code(transport.posts[-1]) == "1"  # negative = keep


def test_a_validation_failure_sends_a_negative_receipt_and_raises(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    responses = make_download_responses(
        keyring, b"<Document/>", bank_keyring=bank_keyring, num_segments=1
    )
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))

    def _reject(_data: bytes) -> None:
        raise ValueError("nope")

    with pytest.raises(ValueError):
        client.download(CAMT_053, validate=_reject)
    # Data must NOT be consumed when validation fails: a negative receipt was sent.
    assert _receipt_code(transport.posts[-1]) == "1"


def test_a_decrypt_failure_sends_a_negative_receipt_and_raises(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    # Encrypt the data to a DIFFERENT subscriber key than the client holds, so RSA-unwrap of
    # the transaction key fails. The data must not be consumed — this is the pre-existing
    # data-loss bug (positive-ack-before-decrypt) the reorder fixes.
    other_keyring = keys.generate_keyring()
    responses = make_download_responses(
        other_keyring, b"<Document/>", bank_keyring=bank_keyring, num_segments=1
    )
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    with pytest.raises(CryptoError):
        client.download(CAMT_053)
    assert _receipt_code(transport.posts[-1]) == "1"  # negative = data preserved


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


def _camt053_zip_with_booking_date(booking_date: str) -> bytes:
    document = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.053.001.08"><BkToCstmrStmt>'
        b"<Stmt><Id>STMT-1</Id>"
        b"<Acct><Id><IBAN>CH9300762011623852957</IBAN></Id></Acct>"
        b'<Ntry><Amt Ccy="CHF">10.00</Amt><CdtDbtInd>CRDT</CdtDbtInd>'
        b"<Sts><Cd>BOOK</Cd></Sts>"
        b"<BookgDt><Dt>" + booking_date.encode("ascii") + b"</Dt></BookgDt></Ntry>"
        b"</Stmt></BkToCstmrStmt></Document>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("statement.xml", document)
    return buffer.getvalue()


_JUNE = DateRange(datetime.date(2026, 6, 1), datetime.date(2026, 6, 30))


@pytest.mark.parametrize(
    ("booking", "accepted"),
    [
        ("2026-05-31", False),  # day before start → rejected
        ("2026-06-01", True),   # start — INCLUSIVE, accepted
        ("2026-06-15", True),   # mid-range
        ("2026-06-30", True),   # end (B) — INCLUSIVE, accepted (the "is B included?" case)
        ("2026-07-01", False),  # day after end → rejected
    ],
)
def test_dated_download_bounds_are_inclusive_on_both_ends(
    booking: str, accepted: bool, keyring: Keyring, bank_keyring: Keyring
) -> None:
    # DateRange is inclusive of Start and End (EBICS DateRangeType); pin the exact edges so a
    # `<=`→`<` slip on either bound is caught. An accepted download is consumed (positive
    # receipt); a rejected one fails closed and is NOT consumed (negative receipt).
    responses = make_download_responses(
        keyring, _camt053_zip_with_booking_date(booking), bank_keyring=bank_keyring
    )
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    if accepted:
        assert len(client.download_statements(date_range=_JUNE)) == 1
        assert _receipt_code(transport.posts[-1]) == "0"
    else:
        with pytest.raises(DateRangeMismatchError):
            client.download_statements(date_range=_JUNE)
        assert _receipt_code(transport.posts[-1]) == "1"


def test_dated_download_is_date_only_and_ignores_time_of_day(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    # An entry timestamped early on the start day (a <DtTm>, not a bare <Dt>) is still that
    # calendar date: the range is date-only (DateRange rejects datetimes; camt DtTm is
    # truncated to its date), so "same day but earlier" is included, never excluded.
    document = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.053.001.08"><BkToCstmrStmt>'
        b"<Stmt><Id>STMT-1</Id>"
        b"<Acct><Id><IBAN>CH9300762011623852957</IBAN></Id></Acct>"
        b'<Ntry><Amt Ccy="CHF">10.00</Amt><CdtDbtInd>CRDT</CdtDbtInd>'
        b"<Sts><Cd>BOOK</Cd></Sts>"
        b"<BookgDt><DtTm>2026-06-01T00:01:00</DtTm></BookgDt></Ntry>"
        b"</Stmt></BkToCstmrStmt></Document>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("statement.xml", document)
    responses = make_download_responses(keyring, buffer.getvalue(), bank_keyring=bank_keyring)
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    assert len(client.download_statements(date_range=_JUNE)) == 1
    assert _receipt_code(transport.posts[-1]) == "0"  # start-day, early time → included


@pytest.mark.parametrize(
    "method",
    [
        "download_statements",
        "download_intraday_statements",
        "download_booking_advices",
        "download_payment_status_reports",
    ],
)
def test_undated_typed_download_parses_before_the_receipt(
    method: str, keyring: Keyring, bank_keyring: Keyring
) -> None:
    # Without a date range there is no range check, but the parse itself must still run
    # before the receipt: data the parser rejects stays at the bank (negative receipt)
    # instead of being consumed by a positive receipt sent ahead of the parse.
    responses = make_download_responses(
        keyring, b"not a camt or pain document", bank_keyring=bank_keyring
    )
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    with pytest.raises(MessageFormatError):
        getattr(client, method)()
    assert _receipt_code(transport.posts[-1]) == "1"


def _statement_zip(namespace: str | None) -> bytes:
    declaration = f' xmlns="{namespace}"' if namespace is not None else ""
    document = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f"<Document{declaration}><BkToCstmrStmt>"
        "<Stmt><Id>STMT-1</Id>"
        "<Acct><Id><IBAN>CH9300762011623852957</IBAN></Id></Acct>"
        "</Stmt></BkToCstmrStmt></Document>"
    ).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("statement.xml", document)
    return buffer.getvalue()


_ISO = "urn:iso:std:iso:20022:tech:xsd:"


def test_strict_download_accepts_the_requested_version(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    responses = make_download_responses(
        keyring, _statement_zip(f"{_ISO}camt.053.001.08"), bank_keyring=bank_keyring
    )
    client, transport = _download_client(
        responses, keyring, _bank_keys(bank_keyring), version_policy=VersionPolicy.STRICT
    )
    assert len(client.download_statements()) == 1
    assert _receipt_code(transport.posts[-1]) == "0"


def test_strict_download_rejects_another_version_before_the_receipt(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    # The content parses either way; under STRICT the version itself is the discrepancy.
    responses = make_download_responses(
        keyring, _statement_zip(f"{_ISO}camt.053.001.04"), bank_keyring=bank_keyring
    )
    client, transport = _download_client(
        responses, keyring, _bank_keys(bank_keyring), version_policy=VersionPolicy.STRICT
    )
    with pytest.raises(MessageVersionMismatchError) as caught:
        client.download_statements()
    assert caught.value.requested == "camt.053 version 08"
    assert caught.value.delivered == "camt.053.001.04"
    assert _receipt_code(transport.posts[-1]) == "1"


@pytest.mark.parametrize(
    "namespace",
    [
        f"{_ISO}camt.054.001.08",  # another message at the requested version
        "urn:example:statement",  # not an ISO 20022 message namespace
        None,  # no namespace at all
    ],
)
def test_strict_download_rejects_a_document_that_does_not_name_the_request(
    namespace: str | None, keyring: Keyring, bank_keyring: Keyring
) -> None:
    responses = make_download_responses(
        keyring, _statement_zip(namespace), bank_keyring=bank_keyring
    )
    client, transport = _download_client(
        responses, keyring, _bank_keys(bank_keyring), version_policy=VersionPolicy.STRICT
    )
    with pytest.raises(MessageVersionMismatchError):
        client.download(CAMT_053)
    assert _receipt_code(transport.posts[-1]) == "1"


def test_strict_download_ignores_the_variant_the_request_cannot_name(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    # A BTF carries no variant (the library never sends the MsgName variant attribute), so
    # only the message name and version are compared.
    order_data = _statement_zip(f"{_ISO}camt.053.002.08")
    responses = make_download_responses(keyring, order_data, bank_keyring=bank_keyring)
    client, _ = _download_client(
        responses, keyring, _bank_keys(bank_keyring), version_policy=VersionPolicy.STRICT
    )
    assert client.download(CAMT_053) == order_data


def test_strict_download_checks_the_version_before_the_callers_validate(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    responses = make_download_responses(
        keyring, _statement_zip(f"{_ISO}camt.053.001.04"), bank_keyring=bank_keyring
    )
    client, transport = _download_client(
        responses, keyring, _bank_keys(bank_keyring), version_policy=VersionPolicy.STRICT
    )
    validated: list[bytes] = []
    with pytest.raises(MessageVersionMismatchError):
        client.download(CAMT_053, validate=validated.append)
    assert validated == []
    assert _receipt_code(transport.posts[-1]) == "1"


def test_strict_download_does_not_compare_a_btf_without_a_version(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    # Such a BTF requests no version (ZKB's OTH/msc result ZIP, say), so there is nothing
    # the delivery could contradict.
    unversioned = BusinessTransactionFormat(
        service_name="OTH", message_name="msc", scope="BIL", container="ZIP"
    )
    responses = make_download_responses(keyring, b"not XML", bank_keyring=bank_keyring)
    client, transport = _download_client(
        responses, keyring, _bank_keys(bank_keyring), version_policy=VersionPolicy.STRICT
    )
    assert client.download(unversioned) == b"not XML"
    assert _receipt_code(transport.posts[-1]) == "0"


def test_default_policy_returns_another_version_but_warns(
    keyring: Keyring, bank_keyring: Keyring, caplog: pytest.LogCaptureFixture
) -> None:
    responses = make_download_responses(
        keyring, _statement_zip(f"{_ISO}camt.053.001.04"), bank_keyring=bank_keyring
    )
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    with caplog.at_level(logging.WARNING, logger="ebicsclient.client"):
        assert len(client.download_statements()) == 1
    assert _receipt_code(transport.posts[-1]) == "0"
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    assert "requested camt.053 version 08, the bank delivered camt.053.001.04" in (
        record.getMessage()
    )


def test_default_policy_does_not_warn_when_the_version_matches(
    keyring: Keyring, bank_keyring: Keyring, caplog: pytest.LogCaptureFixture
) -> None:
    responses = make_download_responses(
        keyring, _statement_zip(f"{_ISO}camt.053.001.08"), bank_keyring=bank_keyring
    )
    client, _ = _download_client(responses, keyring, _bank_keys(bank_keyring))
    with caplog.at_level(logging.WARNING, logger="ebicsclient.client"):
        client.download_statements()
    assert caplog.records == []


def test_default_policy_never_fails_a_raw_download_it_cannot_compare(
    keyring: Keyring, bank_keyring: Keyring, caplog: pytest.LogCaptureFixture
) -> None:
    # The lenient check only reports: data that is not XML still comes back from a raw
    # download, and the warning carries no order data.
    responses = make_download_responses(keyring, b"secret not-XML bytes", bank_keyring=bank_keyring)
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    with caplog.at_level(logging.WARNING, logger="ebicsclient.client"):
        assert client.download(CAMT_053) == b"secret not-XML bytes"
    assert _receipt_code(transport.posts[-1]) == "0"
    (record,) = caplog.records
    assert "could not be compared" in record.getMessage()
    assert "secret" not in record.getMessage()


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


def test_customer_info_runs_the_hkd_admin_download(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    order_data = (Path(__file__).parent / "data" / "hkd_zkb_sample.xml").read_bytes()
    responses = make_download_responses(
        keyring, order_data, bank_keyring=bank_keyring, num_segments=1
    )
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    info = client.customer_info()
    assert [subscriber.user_id for subscriber in info.subscribers] == ["USER1"]
    opened = etree.fromstring(transport.posts[0])
    assert opened.findtext(f".//{{{_NS}}}AdminOrderType") == "HKD"
    assert opened.find(f".//{{{_NS}}}StandardOrderParams") is not None
    assert _receipt_code(transport.posts[-1]) == "0"


def test_bank_parameters_runs_the_hpd_admin_download(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    order_data = (Path(__file__).parent / "data" / "hpd_zkb_sample.xml").read_bytes()
    responses = make_download_responses(
        keyring, order_data, bank_keyring=bank_keyring, num_segments=1
    )
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    assert "H005" in client.bank_parameters().protocol_versions
    opened = etree.fromstring(transport.posts[0])
    assert opened.findtext(f".//{{{_NS}}}AdminOrderType") == "HPD"


@pytest.mark.parametrize("method", ["customer_info", "bank_parameters"])
def test_admin_downloads_require_hpb_first(method: str, keyring: Keyring) -> None:
    client, _ = _client(_OK_RESPONSE, keyring)
    with pytest.raises(ClientStateError):
        getattr(client, method)()


def _transfer_response(code: str, bank_keyring: Keyring) -> bytes:
    return sign_response(
        (
            f'<ebicsResponse xmlns="{_NS}"><header authenticate="true"><static/>'
            f"<mutable><TransactionPhase>Transfer</TransactionPhase>"
            f"<ReturnCode>{code}</ReturnCode></mutable></header>"
            f"<body><ReturnCode>{code}</ReturnCode></body></ebicsResponse>"
        ).encode(),
        bank_keyring,
    )


@pytest.mark.parametrize(
    ("rotation", "order_type"),
    [
        (KeyRotation.SIGNATURE, "PUB"),
        (KeyRotation.AUTHENTICATION_AND_ENCRYPTION, "HCA"),
        (KeyRotation.ALL, "HCS"),
    ],
)
def test_change_keys_sends_the_order_and_adopts_the_successor(
    rotation: KeyRotation, order_type: str, keyring: Keyring, bank_keyring: Keyring
) -> None:
    successor = keys.rotate_keyring(keyring, rotation)
    responses: list[bytes | Exception] = [
        _upload_response("Initialisation", bank_keyring, transaction_id="F" * 32),
        _upload_response("Transfer", bank_keyring),
    ]
    client, transport = _download_client(responses, keyring, _bank_keys(bank_keyring))
    assert client.change_keys(successor, rotation) == "F" * 32
    assert client.keyring is successor
    opened = etree.fromstring(transport.posts[0])
    assert opened.findtext(f".//{{{_NS}}}AdminOrderType") == order_type
    # Both phases are authenticated with the keys the bank holds BEFORE the change.
    for post in transport.posts:
        assert crypto.verify_auth_signature(
            etree.fromstring(post), keyring.authentication.public_key()
        )


def test_change_keys_keeps_the_current_keys_when_the_bank_rejects_the_change(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    successor = keys.rotate_keyring(keyring, KeyRotation.ALL)
    responses: list[bytes | Exception] = [
        _upload_response("Initialisation", bank_keyring, transaction_id="F" * 32),
        _transfer_response("091301", bank_keyring),  # EBICS_SIGNATURE_VERIFICATION_FAILED
    ]
    client, _ = _download_client(responses, keyring, _bank_keys(bank_keyring))
    with pytest.raises(ReturnCodeError) as caught:
        client.change_keys(successor, KeyRotation.ALL)
    assert caught.value.code == "091301"
    assert not isinstance(caught.value, KeyChangeUnconfirmedError)
    assert client.keyring is keyring


def test_change_keys_keeps_the_current_keys_when_the_initialisation_fails(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    # The order data travels only in the transfer phase: a lost initialisation is definite.
    successor = keys.rotate_keyring(keyring, KeyRotation.SIGNATURE)
    responses: list[bytes | Exception] = [TransportError("connection reset")]
    client, _ = _download_client(responses, keyring, _bank_keys(bank_keyring))
    with pytest.raises(TransportError):
        client.change_keys(successor, KeyRotation.SIGNATURE)
    assert client.keyring is keyring


@pytest.mark.parametrize(
    "final_response",
    ["lost", "unsigned", "unknown-code"],
)
def test_change_keys_reports_an_unconfirmed_outcome_after_the_final_segment(
    final_response: str, keyring: Keyring, bank_keyring: Keyring
) -> None:
    final: bytes | Exception
    if final_response == "lost":
        final = TransportError("timed out")
    elif final_response == "unsigned":
        final = (
            f'<ebicsResponse xmlns="{_NS}"><header authenticate="true"><static/>'
            "<mutable><ReturnCode>000000</ReturnCode></mutable></header>"
            "<body><ReturnCode>000000</ReturnCode></body></ebicsResponse>"
        ).encode()
    else:
        final = _transfer_response("099999", bank_keyring)
    successor = keys.rotate_keyring(keyring, KeyRotation.AUTHENTICATION_AND_ENCRYPTION)
    responses = [
        _upload_response("Initialisation", bank_keyring, transaction_id="F" * 32),
        final,
    ]
    client, _ = _download_client(responses, keyring, _bank_keys(bank_keyring))
    with pytest.raises(KeyChangeUnconfirmedError) as caught:
        client.change_keys(successor, KeyRotation.AUTHENTICATION_AND_ENCRYPTION)
    assert caught.value.order_type == "HCA"
    assert caught.value.transaction_id == "F" * 32
    # The client stays on the old keys; the caller must establish which set the bank holds.
    assert client.keyring is keyring


def test_change_keys_validates_the_successor_before_sending_anything(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    client, transport = _download_client([], keyring, _bank_keys(bank_keyring))
    with pytest.raises(ValueError):
        client.change_keys(keyring, KeyRotation.ALL)
    with pytest.raises(TypeError):
        client.change_keys(keys.rotate_keyring(keyring, KeyRotation.ALL), "all")  # type: ignore[arg-type]
    assert transport.posts == []


def test_change_keys_requires_hpb_first(keyring: Keyring) -> None:
    client, _ = _client(_OK_RESPONSE, keyring)
    with pytest.raises(ClientStateError):
        client.change_keys(keys.rotate_keyring(keyring, KeyRotation.ALL), KeyRotation.ALL)


def test_change_keys_adopts_a_new_certificate_provider_only_on_success(
    keyring: Keyring, bank_keyring: Keyring
) -> None:
    successor = keys.rotate_keyring(keyring, KeyRotation.SIGNATURE)
    ca_key, ca_certificate = make_ca()
    provider = MappingCertificateProvider(
        {
            CertificateUsage.SIGNATURE: issue_certificate(
                ca_key, ca_certificate, successor.signature.public_key(), CertificateUsage.SIGNATURE
            )
        }
    )
    responses: list[bytes | Exception] = [
        _upload_response("Initialisation", bank_keyring, transaction_id="F" * 32),
        _upload_response("Transfer", bank_keyring),
    ]
    client, _ = _download_client(responses, keyring, _bank_keys(bank_keyring))
    client.change_keys(successor, KeyRotation.SIGNATURE, certificate_provider=provider)
    assert client._certificate_provider is provider
