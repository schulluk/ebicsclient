"""Tests for the single transactions of camt booking entries (``NtryDtls/TxDtls``).

The golden fixtures are genuine ZKB test-platform messages (account identifiers scrubbed),
and the expected values are what went in, not what this library produced:

- ``camt054_qrr/scor/lsv/unreferenced_credit_zkb_sample.xml`` (camt.054.001.04) answer one
  run of ``tools/zkb-incoming-payments.py``: the platform simulated the credits of a CSV file
  whose references, amounts, payer names and remittance texts are pinned below.
- ``camt054_collective_zkb_sample.xml`` (camt.054.001.08) is the batch debit of a submitted
  pain.001 whose message, payment, instruction and end-to-end IDs, creditors and remittance
  texts are pinned below.

Every fixture validates against the ISO 20022 schema of its version. The hand-written
documents at the end cover the schema's other shapes, which ZKB has not delivered.
"""

from decimal import Decimal
from pathlib import Path

import pytest

from ebicsclient.errors import MessageFormatError
from ebicsclient.formats import camt052, camt053, camt054
from ebicsclient.models import (
    CREDITOR_REFERENCE_TYPE_ISR,
    CREDITOR_REFERENCE_TYPE_QR,
    CREDITOR_REFERENCE_TYPE_SCOR,
    CreditDebit,
    CreditorReference,
    Entry,
)

_DATA = Path(__file__).parent / "data"


def _only_entry(name: str) -> Entry:
    (notification,) = camt054.parse((_DATA / name).read_bytes())
    (entry,) = notification.entries
    return entry


def test_collective_qr_credit_resolves_into_the_simulated_payments() -> None:
    entry = _only_entry("camt054_qrr_zkb_sample.xml")
    assert entry.amount == Decimal("1325.75")
    # The three QRR rows of the simulation CSV: reference, amount, payer, remittance text.
    sent = [
        ("202610261213420100000000010", Decimal("1000.00"), "Anna Beispiel", ("Rechnung 1",)),
        ("202610261213420100000000021", Decimal("250.50"), "Beat Exempel", ("Rechnung 2",)),
        ("202610261213420100000000036", Decimal("75.25"), "Carla Probst", ()),
    ]
    assert len(entry.transactions) == len(sent)
    for transaction, (reference, amount, payer, remittance) in zip(
        entry.transactions, sent, strict=True
    ):
        assert transaction.creditor_references == (
            CreditorReference(
                reference=reference, type_code=None, proprietary_type=CREDITOR_REFERENCE_TYPE_QR
            ),
        )
        assert transaction.amount == amount
        assert transaction.currency == "CHF"
        assert transaction.credit_debit is CreditDebit.CREDIT
        assert transaction.debtor_name == payer
        assert transaction.additional_remittance_information == remittance
        assert transaction.remittance_information == ()
    # The single transactions add up to the collective booking.
    assert sum(transaction.amount or Decimal("0") for transaction in entry.transactions) == (
        entry.amount
    )


def test_collective_scor_credit_carries_the_iso_11649_references() -> None:
    entry = _only_entry("camt054_scor_zkb_sample.xml")
    assert [transaction.creditor_references for transaction in entry.transactions] == [
        (CreditorReference("RF36EBICS2026102612134201", CREDITOR_REFERENCE_TYPE_SCOR, None),),
        (CreditorReference("RF09EBICS2026102612134202", CREDITOR_REFERENCE_TYPE_SCOR, None),),
    ]
    assert [transaction.amount for transaction in entry.transactions] == [
        Decimal("300.00"),
        Decimal("120.75"),
    ]
    assert [transaction.debtor_name for transaction in entry.transactions] == [
        "Anna Beispiel",
        "Beat Exempel",
    ]


def test_collective_lsv_credit_carries_the_esr_references() -> None:
    entry = _only_entry("camt054_lsv_zkb_sample.xml")
    sent = [
        ("202610261213420200000000018", Decimal("500.00")),
        ("202610261213420200000000023", Decimal("89.90")),
    ]
    for transaction, (reference, amount) in zip(entry.transactions, sent, strict=True):
        assert transaction.creditor_references == (
            CreditorReference(reference, None, CREDITOR_REFERENCE_TYPE_ISR),
        )
        assert transaction.amount == amount
        assert transaction.credit_debit is CreditDebit.CREDIT


def test_unreferenced_credit_carries_the_unstructured_remittance_text() -> None:
    entry = _only_entry("camt054_unreferenced_credit_zkb_sample.xml")
    (transaction,) = entry.transactions
    assert transaction.amount == Decimal("42.10")
    assert transaction.debtor_name == "Carla Probst"
    assert transaction.creditor_references == ()
    assert transaction.remittance_information == ("Spende",)


def test_version_08_batch_debit_resolves_into_the_submitted_payments() -> None:
    entry = _only_entry("camt054_collective_zkb_sample.xml")
    # The four accepted transactions of the submitted pain.001 (the third was rejected).
    sent = [
        ("1", Decimal("100"), "Creditor Eins GmbH", "CH9300762011623852957"),
        ("2", Decimal("250.50"), "Creditor Zwei AG", "CH9300762011623852957"),
        ("4", Decimal("1200"), "Creditor Four Ltd", "GB29NWBK60161331926819"),
        ("5", Decimal("45.95"), "Creditor Fuenf GmbH", "CH9300762011623852957"),
    ]
    for transaction, (number, amount, creditor, iban) in zip(entry.transactions, sent, strict=True):
        assert transaction.message_id == "EBICSCLIENT-TEST-0004"
        assert transaction.payment_information_id == "PMT-0004"
        assert transaction.instruction_id == f"INSTR-0004-{number}"
        assert transaction.end_to_end_id == f"E2E-0004-{number}"
        assert transaction.amount == amount
        assert transaction.credit_debit is CreditDebit.DEBIT
        # Version 08 wraps each party in <Pty>; the name is read through it.
        assert transaction.debtor_name == "Privatperson"
        assert transaction.creditor_name == creditor
        assert transaction.creditor_iban == iban
        assert transaction.remittance_information == (f"ebicsClient test payment 0004-{number}",)
    assert sum(transaction.amount or Decimal("0") for transaction in entry.transactions) == (
        entry.amount
    )


def test_statements_and_intraday_reports_carry_transaction_details_too() -> None:
    (statement,) = camt053.parse((_DATA / "camt053_zkb_sample.xml").read_bytes())
    (transaction,) = statement.entries[0].transactions
    assert transaction.end_to_end_id == "E2E-0002"
    assert transaction.creditor_name == "Creditor Test GmbH"
    (report,) = camt052.parse((_DATA / "camt052_zkb_sample.xml").read_bytes())
    assert [transaction.end_to_end_id for transaction in report.entries[0].transactions] == [
        "E2E-0004-1",
        "E2E-0004-2",
        "E2E-0004-4",
        "E2E-0004-5",
    ]


def test_an_entry_without_details_has_no_transactions() -> None:
    assert _only_entry("camt054_debit_zkb_sample.xml").transactions == ()


def test_a_foreign_currency_transaction_keeps_its_own_currency() -> None:
    (statement,) = camt053.parse((_DATA / "camt053_zkb_sample.xml").read_bytes())
    entry = next(entry for entry in statement.entries if entry.amount == Decimal("170.8"))
    (transaction,) = entry.transactions
    assert (entry.currency, transaction.currency) == ("CHF", "USD")
    assert transaction.amount == Decimal("167.51")


# ---------------------------------------------------------------------------------------
# Hand-written camt.054.001.08 documents for shapes the schema allows and ZKB has not sent.
# Each was checked against the ISO 20022 camt.054.001.08 schema when it was written.
# ---------------------------------------------------------------------------------------

_HEADER = (
    '<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.054.001.08"><BkToCstmrDbtCdtNtfctn>'
    "<GrpHdr><MsgId>M1</MsgId><CreDtTm>2026-10-26T12:00:00</CreDtTm></GrpHdr>"
    "<Ntfctn><Id>N1</Id><Acct><Id><IBAN>CH4200000000000000000</IBAN></Id></Acct>"
    '<Ntry><Amt Ccy="CHF">10.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts><Cd>BOOK</Cd></Sts>'
    "<BkTxCd><Domn><Cd>PMNT</Cd><Fmly><Cd>RCDT</Cd><SubFmlyCd>DMCT</SubFmlyCd></Fmly></Domn>"
    "</BkTxCd>"
)
_FOOTER = "</Ntry></Ntfctn></BkToCstmrDbtCdtNtfctn></Document>"


def _entry_from(entry_details: str) -> Entry:
    (notification,) = camt054.parse((_HEADER + entry_details + _FOOTER).encode())
    (entry,) = notification.entries
    return entry


def test_transaction_without_amount_or_indicator_reads_as_none() -> None:
    # EntryTransaction10 makes Amt and CdtDbtInd optional.
    entry = _entry_from(
        "<NtryDtls><TxDtls><Refs><EndToEndId>E1</EndToEndId></Refs></TxDtls></NtryDtls>"
    )
    (transaction,) = entry.transactions
    assert (transaction.amount, transaction.currency, transaction.credit_debit) == (
        None,
        None,
        None,
    )
    assert transaction.end_to_end_id == "E1"


def test_party_that_is_a_financial_institution_is_named_from_its_identification() -> None:
    entry = _entry_from(
        "<NtryDtls><TxDtls><RltdPties>"
        "<Dbtr><Agt><FinInstnId><BICFI>ZKBKCHZZ80A</BICFI><Nm>Example Bank</Nm></FinInstnId>"
        "</Agt></Dbtr>"
        "<DbtrAcct><Id><IBAN>CH9300762011623852957</IBAN></Id></DbtrAcct>"
        "<Cdtr><Pty><Nm>Payee AG</Nm></Pty></Cdtr>"
        "<CdtrAcct><Id><Othr><Id>12345</Id></Othr></Id></CdtrAcct>"
        "</RltdPties></TxDtls></NtryDtls>"
    )
    (transaction,) = entry.transactions
    assert transaction.debtor_name == "Example Bank"
    assert transaction.debtor_iban == "CH9300762011623852957"
    assert transaction.creditor_name == "Payee AG"
    # An account identified by something other than an IBAN has no IBAN to report.
    assert transaction.creditor_iban is None


def test_every_structured_block_and_entry_details_block_is_read_in_order() -> None:
    entry = _entry_from(
        "<NtryDtls><TxDtls><RmtInf><Ustrd>line 1</Ustrd><Ustrd>line 2</Ustrd>"
        "<Strd><CdtrRefInf><Ref>untyped</Ref></CdtrRefInf><AddtlRmtInf>a</AddtlRmtInf>"
        "<AddtlRmtInf>b</AddtlRmtInf></Strd>"
        "<Strd><CdtrRefInf><Tp><CdOrPrtry><Cd>SCOR</Cd></CdOrPrtry></Tp></CdtrRefInf></Strd>"
        "</RmtInf></TxDtls></NtryDtls>"
        "<NtryDtls><TxDtls><Refs><EndToEndId>second</EndToEndId></Refs></TxDtls></NtryDtls>"
    )
    first, second = entry.transactions
    assert first.remittance_information == ("line 1", "line 2")
    assert first.creditor_references == (
        CreditorReference(reference="untyped", type_code=None, proprietary_type=None),
        CreditorReference(reference=None, type_code="SCOR", proprietary_type=None),
    )
    assert first.additional_remittance_information == ("a", "b")
    assert second.end_to_end_id == "second"


@pytest.mark.parametrize(
    "transaction",
    [
        '<TxDtls><Amt Ccy="CHF">ten</Amt></TxDtls>',
        "<TxDtls><Amt>10.00</Amt></TxDtls>",
        "<TxDtls><CdtDbtInd>BOTH</CdtDbtInd></TxDtls>",
        "<TxDtls><RmtInf><Ustrd></Ustrd></RmtInf></TxDtls>",
        "<TxDtls><RltdPties><Dbtr><Agt><BrnchId/></Agt></Dbtr></RltdPties></TxDtls>",
    ],
)
def test_malformed_transaction_details_fail_closed(transaction: str) -> None:
    with pytest.raises(MessageFormatError):
        _entry_from(f"<NtryDtls>{transaction}</NtryDtls>")
