"""Tests for ebicsclient.formats.camt053: parsing camt.053 statements."""

import datetime
import io
import zipfile
from decimal import Decimal

import pytest

from ebicsclient.errors import MessageFormatError
from ebicsclient.formats import camt053
from ebicsclient.models import CreditDebit

_NS = "urn:iso:std:iso:20022:tech:xsd:camt.053.001.08"


def _document(*, identification: str = "STMT-2026-001") -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="{_NS}">
  <BkToCstmrStmt>
    <GrpHdr><MsgId>MSG1</MsgId><CreDtTm>2026-06-30T08:00:00</CreDtTm></GrpHdr>
    <Stmt>
      <Id>{identification}</Id>
      <Acct><Id><IBAN>CH9300762011623852957</IBAN></Id><Ccy>CHF</Ccy></Acct>
      <Bal>
        <Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp>
        <Amt Ccy="CHF">1000.00</Amt>
        <CdtDbtInd>CRDT</CdtDbtInd>
        <Dt><Dt>2026-06-29</Dt></Dt>
      </Bal>
      <Bal>
        <Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp>
        <Amt Ccy="CHF">1250.50</Amt>
        <CdtDbtInd>CRDT</CdtDbtInd>
        <Dt><Dt>2026-06-30</Dt></Dt>
      </Bal>
      <Ntry>
        <Amt Ccy="CHF">250.50</Amt>
        <CdtDbtInd>CRDT</CdtDbtInd>
        <Sts><Cd>BOOK</Cd></Sts>
        <BookgDt><Dt>2026-06-30</Dt></BookgDt>
        <ValDt><Dt>2026-06-30</Dt></ValDt>
        <AcctSvcrRef>REF-001</AcctSvcrRef>
      </Ntry>
    </Stmt>
  </BkToCstmrStmt>
</Document>""".encode()


def test_parse_reads_identification_account_and_balances() -> None:
    (statement,) = camt053.parse(_document())
    assert statement.identification == "STMT-2026-001"
    assert statement.iban == "CH9300762011623852957"
    assert statement.opening_balance is not None
    assert statement.opening_balance.amount == Decimal("1000.00")
    assert statement.closing_balance is not None
    assert statement.closing_balance.code == "CLBD"
    assert statement.closing_balance.amount == Decimal("1250.50")
    assert statement.closing_balance.currency == "CHF"
    assert statement.closing_balance.credit_debit is CreditDebit.CREDIT
    assert statement.closing_balance.date == datetime.date(2026, 6, 30)
    assert len(statement.balances) == 2


def test_parse_reads_entries() -> None:
    (statement,) = camt053.parse(_document())
    (entry,) = statement.entries
    assert entry.amount == Decimal("250.50")
    assert entry.currency == "CHF"
    assert entry.credit_debit is CreditDebit.CREDIT
    assert entry.status == "BOOK"
    assert entry.booking_date == datetime.date(2026, 6, 30)
    assert entry.value_date == datetime.date(2026, 6, 30)
    assert entry.reference == "REF-001"


def test_parse_extracts_every_document_from_a_zip_in_name_order() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("statement-b.xml", _document(identification="SECOND"))
        archive.writestr("statement-a.xml", _document(identification="FIRST"))
    statements = camt053.parse(buffer.getvalue())
    assert [statement.identification for statement in statements] == ["FIRST", "SECOND"]


def test_parse_accepts_a_date_time_choice_for_entry_dates() -> None:
    document = _document().replace(
        b"<BookgDt><Dt>2026-06-30</Dt></BookgDt>",
        b"<BookgDt><DtTm>2026-06-30T14:30:00+02:00</DtTm></BookgDt>",
    )
    (statement,) = camt053.parse(document)
    (entry,) = statement.entries
    assert entry.booking_date == datetime.date(2026, 6, 30)


def test_parse_accepts_a_legacy_plain_status_code() -> None:
    document = _document().replace(b"<Sts><Cd>BOOK</Cd></Sts>", b"<Sts>BOOK</Sts>")
    (statement,) = camt053.parse(document)
    assert statement.entries[0].status == "BOOK"


def test_parse_rejects_malformed_xml() -> None:
    with pytest.raises(MessageFormatError):
        camt053.parse(b"<Document><not-closed>")


def test_parse_rejects_a_wrong_root_element() -> None:
    with pytest.raises(MessageFormatError):
        camt053.parse(f'<Other xmlns="{_NS}"/>'.encode())


def test_parse_rejects_an_amount_without_a_currency() -> None:
    document = _document().replace(b'<Amt Ccy="CHF">1250.50</Amt>', b"<Amt>1250.50</Amt>")
    with pytest.raises(MessageFormatError):
        camt053.parse(document)


def test_parse_rejects_a_non_decimal_amount() -> None:
    document = _document().replace(b"<Amt Ccy=\"CHF\">1250.50</Amt>", b'<Amt Ccy="CHF">lots</Amt>')
    with pytest.raises(MessageFormatError):
        camt053.parse(document)


def test_parse_rejects_a_bad_credit_debit_indicator() -> None:
    document = _document().replace(
        b"<CdtDbtInd>CRDT</CdtDbtInd>\n        <Dt><Dt>2026-06-30</Dt></Dt>",
        b"<CdtDbtInd>SIDEWAYS</CdtDbtInd>\n        <Dt><Dt>2026-06-30</Dt></Dt>",
    )
    with pytest.raises(MessageFormatError):
        camt053.parse(document)
