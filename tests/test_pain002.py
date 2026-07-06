"""Tests for ebicsclient.formats.pain002: parsing payment status reports.

The golden fixtures in tests/data/ are genuine pain.002.001.10 reports produced by the
ZKB test platform (no account data): the technical acceptance (ACTC), a full acceptance
(ACCP), a partial acceptance with two per-transaction rejects (PART), and a rejection
with a payment-level reason (RJCT).
"""

import io
import zipfile
from pathlib import Path

import pytest

from ebicsclient.errors import MessageFormatError
from ebicsclient.formats import pain002
from ebicsclient.models import (
    STATUS_ACCEPTED,
    STATUS_ACCEPTED_TECHNICAL,
    STATUS_PARTIALLY_ACCEPTED,
    STATUS_REJECTED,
)

_DATA = Path(__file__).parent / "data"


def _fixture(name: str) -> bytes:
    return (_DATA / name).read_bytes()


def test_parse_reads_a_technical_acceptance() -> None:
    (report,) = pain002.parse(_fixture("pain002_actc.xml"))
    assert report.group_status == STATUS_ACCEPTED_TECHNICAL
    assert report.original_message_id == "EBICSCLIENT-TEST-0004"
    assert report.original_message_name == "pain.001.001.09.ch.03"
    assert report.payments == ()
    assert report.rejected_transactions == ()


def test_parse_reads_a_full_acceptance() -> None:
    (report,) = pain002.parse(_fixture("pain002_accp.xml"))
    assert report.group_status == STATUS_ACCEPTED
    assert report.rejected_transactions == ()


def test_parse_reads_a_partial_acceptance_with_transaction_rejects() -> None:
    (report,) = pain002.parse(_fixture("pain002_part.xml"))
    assert report.group_status == STATUS_PARTIALLY_ACCEPTED
    (payment,) = report.payments
    assert payment.original_payment_information_id == "PMT-0004"
    assert payment.status == STATUS_PARTIALLY_ACCEPTED

    rejected = report.rejected_transactions
    assert [transaction.original_end_to_end_id for transaction in rejected] == [
        "E2E-0004-3",
        "E2E-0004-6",
    ]
    first, second = rejected
    assert first.original_instruction_id == "INSTR-0004-3"
    assert first.status == STATUS_REJECTED
    (reason,) = first.reasons
    assert reason.code == "RC05"  # invalid BIC
    assert reason.additional_information is not None
    assert "BIC" in reason.additional_information
    (reason,) = second.reasons
    assert reason.code == "AC01"  # invalid account number


def test_parse_reads_a_rejection_with_a_payment_level_reason() -> None:
    (report,) = pain002.parse(_fixture("pain002_rjct.xml"))
    assert report.group_status == STATUS_REJECTED
    (payment,) = report.payments
    assert payment.status == STATUS_REJECTED
    (reason,) = payment.reasons
    assert reason.code == "AGNT"
    assert reason.additional_information is not None
    assert "Multibanking" in reason.additional_information


def test_parse_extracts_every_report_from_a_zip_in_name_order() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("b-report.xml", _fixture("pain002_part.xml"))
        archive.writestr("a-report.xml", _fixture("pain002_actc.xml"))
    reports = pain002.parse(buffer.getvalue())
    assert [report.group_status for report in reports] == [
        STATUS_ACCEPTED_TECHNICAL,
        STATUS_PARTIALLY_ACCEPTED,
    ]


def test_parse_rejects_malformed_xml() -> None:
    with pytest.raises(MessageFormatError):
        pain002.parse(b"<Document><not-closed>")


def test_parse_rejects_a_wrong_root_element() -> None:
    with pytest.raises(MessageFormatError):
        pain002.parse(b'<Other xmlns="urn:iso:std:iso:20022:tech:xsd:pain.002.001.10"/>')


def test_parse_rejects_a_document_without_a_namespace() -> None:
    with pytest.raises(MessageFormatError):
        pain002.parse(b"<Document/>")


def test_parse_reads_a_proprietary_reason_code() -> None:
    document = _fixture("pain002_rjct.xml").replace(b"<Cd>AGNT</Cd>", b"<Prtry>X123</Prtry>")
    (report,) = pain002.parse(document)
    (payment,) = report.payments
    assert payment.reasons[0].code == "X123"
