"""Tests for ebicsclient.formats.camt052 and camt054: intraday reports and advices.

The golden fixtures in tests/data/ are genuine ZKB test-platform messages (account
identifiers scrubbed): a camt.052.001.08 intraday report with 16 entries, and three
camt.054.001.08 notifications (a credit advice, a debit advice, and the collective
booking of an initiated payment file).
"""

import io
import zipfile
from decimal import Decimal
from pathlib import Path

import pytest

from ebicsclient.errors import MessageFormatError
from ebicsclient.formats import camt052, camt054
from ebicsclient.models import CreditDebit

_DATA = Path(__file__).parent / "data"


def _fixture(name: str) -> bytes:
    return (_DATA / name).read_bytes()


def test_camt052_parses_the_real_intraday_report() -> None:
    (report,) = camt052.parse(_fixture("camt052_zkb_sample.xml"))
    assert report.identification == "3945731AGHG095204231474"
    assert report.iban == "CH4200000000000000000"
    assert len(report.entries) == 16
    # An intraday report has no opening/closing booked balances.
    assert report.opening_balance is None
    assert report.closing_balance is None
    # The parsed amounts and signs reconcile to the bank's own declared net total.
    net = sum(
        (entry.amount if entry.credit_debit is CreditDebit.CREDIT else -entry.amount)
        for entry in report.entries
    )
    assert net == Decimal("157508.47")


def test_camt052_reads_the_collective_booking_of_the_initiated_payments() -> None:
    (report,) = camt052.parse(_fixture("camt052_zkb_sample.xml"))
    first = report.entries[0]
    # The four accepted payments of the submitted pain.001, booked as one batch debit.
    assert first.amount == Decimal("1596.45")
    assert first.credit_debit is CreditDebit.DEBIT
    assert first.status == "BOOK"


def test_camt054_parses_a_credit_advice() -> None:
    (notification,) = camt054.parse(_fixture("camt054_credit_zkb_sample.xml"))
    assert notification.identification == "3945731AGHG095204231511"
    assert notification.iban == "CH4200000000000000000"
    (entry,) = notification.entries
    assert entry.amount == Decimal("4000")
    assert entry.credit_debit is CreditDebit.CREDIT


def test_camt054_parses_a_debit_advice() -> None:
    (notification,) = camt054.parse(_fixture("camt054_debit_zkb_sample.xml"))
    (entry,) = notification.entries
    assert entry.amount == Decimal("12")
    assert entry.credit_debit is CreditDebit.DEBIT


def test_camt054_parses_the_collective_payment_booking() -> None:
    (notification,) = camt054.parse(_fixture("camt054_collective_zkb_sample.xml"))
    (entry,) = notification.entries
    assert entry.amount == Decimal("1596.45")
    assert entry.credit_debit is CreditDebit.DEBIT


def test_camt054_extracts_every_notification_from_a_zip_in_name_order() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("b.xml", _fixture("camt054_debit_zkb_sample.xml"))
        archive.writestr("a.xml", _fixture("camt054_credit_zkb_sample.xml"))
    notifications = camt054.parse(buffer.getvalue())
    assert [n.entries[0].credit_debit for n in notifications] == [
        CreditDebit.CREDIT,
        CreditDebit.DEBIT,
    ]


def test_camt052_rejects_a_camt053_document() -> None:
    # A camt.053 statement is not an intraday report — the wrapper element differs.
    with pytest.raises(MessageFormatError):
        camt052.parse(_fixture("camt053_zkb_sample.xml"))


def test_camt054_rejects_malformed_xml() -> None:
    with pytest.raises(MessageFormatError):
        camt054.parse(b"<Document><not-closed>")
