"""Tests for tools/zkb-incoming-payments.py: the CSV it submits and how it reconciles.

The reference check digits are pinned to published examples rather than to the tool's own
output: the SIX QR-bill guidelines' QR reference, the ISO 11649 creditor reference, the
IBAN registry's Swiss example IBAN, and the LSV and QRR references in the ZKB
test-platform manual (section 2.3.1). The transaction reconciliation runs against the
genuine camt.054 messages the platform returned for one run of the tool.
"""

import dataclasses
import importlib.util
from decimal import Decimal
from pathlib import Path
from types import ModuleType

import pytest

from ebicsclient import BusinessTransactionFormat
from ebicsclient.formats import camt054

_TOOL_PATH = Path(__file__).resolve().parent.parent / "tools" / "zkb-incoming-payments.py"
_DATA = Path(__file__).resolve().parent / "data"
# The IBAN registry's example Swiss IBAN — fictitious, safe to use anywhere.
_EXAMPLE_IBAN = "CH9300762011623852957"


def _load_tool() -> ModuleType:
    specification = importlib.util.spec_from_file_location("zkb_incoming_payments", _TOOL_PATH)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


tool = _load_tool()


def test_qr_reference_check_digit_matches_the_six_example() -> None:
    # SIX, Swiss Implementation Guidelines QR-bill: 21 00000 00003 13947 14300 09017.
    assert tool.numeric_reference("21000000000313947143000901") == "210000000003139471430009017"


@pytest.mark.parametrize(
    "reference",
    ["444444444444444444444444444", "111111111111111111111111110"],
)
def test_reference_check_digit_matches_the_test_platform_manual(reference: str) -> None:
    # The manual's LSV and QRR CSV examples (section 2.3.1).
    assert tool.numeric_reference(reference[:26]) == reference


def test_creditor_reference_matches_the_iso_11649_example() -> None:
    assert tool.creditor_reference("539007547034") == "RF18539007547034"


@pytest.mark.parametrize("body", ["", "A" * 22, "rf12", "AB-12"])
def test_creditor_reference_rejects_a_malformed_body(body: str) -> None:
    with pytest.raises(ValueError):
        tool.creditor_reference(body)


@pytest.mark.parametrize("payload", ["1" * 25, "1" * 27, "1" * 25 + "x"])
def test_numeric_reference_rejects_a_malformed_payload(payload: str) -> None:
    with pytest.raises(ValueError):
        tool.numeric_reference(payload)


def test_validate_iban_accepts_the_registry_example_with_spaces() -> None:
    assert tool.validate_iban("CH93 0076 2011 6238 5295 7") == _EXAMPLE_IBAN


@pytest.mark.parametrize("iban", ["CH9300762011623852958", "CH93", "9300762011623852957CH"])
def test_validate_iban_rejects_a_wrong_or_malformed_iban(iban: str) -> None:
    with pytest.raises(ValueError):
        tool.validate_iban(iban)


def test_render_csv_writes_the_manual_header_and_one_row_per_payment() -> None:
    payments = tool.build_scenario("20261026120000")
    lines = tool.render_csv(_EXAMPLE_IBAN, payments).decode("utf-8").splitlines()
    assert lines[0].split(";")[:5] == ["Product", "Charges", "IBAN", "Amount", "Reference"]
    assert len(lines) == len(payments) + 1
    for line, payment in zip(lines[1:], payments, strict=True):
        fields = line.split(";")
        assert len(fields) == 18
        assert fields[0] == payment.product.value
        assert fields[2] == _EXAMPLE_IBAN
        assert Decimal(fields[3]) == payment.amount


def test_scenario_references_are_valid_for_their_product() -> None:
    for payment in tool.build_scenario("20261026120000"):
        if payment.product is tool.Product.WITHOUT_REFERENCE:
            assert payment.reference is None
        elif payment.product is tool.Product.CREDITOR_REFERENCE:
            assert payment.reference == tool.creditor_reference(payment.reference[4:])
        else:
            assert payment.reference == tool.numeric_reference(payment.reference[:26])


def test_render_csv_refuses_a_separator_inside_a_value() -> None:
    debtor = tool.Debtor("Name; with separator", "Weg", "1", "8000", "Zuerich", "CH")
    payment = tool.SimulatedPayment(tool.Product.WITHOUT_REFERENCE, Decimal("1.00"), None, debtor)
    with pytest.raises(ValueError):
        tool.render_csv(_EXAMPLE_IBAN, [payment])


def test_render_csv_refuses_a_reference_on_a_non_payment() -> None:
    debtor = tool.Debtor("Name", "Weg", "1", "8000", "Zuerich", "CH")
    payment = tool.SimulatedPayment(
        tool.Product.WITHOUT_REFERENCE, Decimal("1.00"), "RF18539007547034", debtor
    )
    with pytest.raises(ValueError):
        tool.render_csv(_EXAMPLE_IBAN, [payment])


# The run behind the camt054_*_zkb_sample.xml fixtures, as its manifest recorded it.
_SENT = (
    ("QRR", "1000.00", "202610261213420100000000010", "Anna Beispiel", "Rechnung 1"),
    ("QRR", "250.50", "202610261213420100000000021", "Beat Exempel", "Rechnung 2"),
    ("QRR", "75.25", "202610261213420100000000036", "Carla Probst", None),
    ("SCOR", "300.00", "RF36EBICS2026102612134201", "Anna Beispiel", None),
    ("SCOR", "120.75", "RF09EBICS2026102612134202", "Beat Exempel", None),
    ("NON", "42.10", None, "Carla Probst", "Spende"),
    ("LSV", "500.00", "202610261213420200000000018", "Anna Beispiel", None),
    ("LSV", "89.90", "202610261213420200000000023", "Beat Exempel", None),
)


def _manifest() -> list[object]:
    return [
        tool.ManifestPayment(tool.Product(product), Decimal(amount), reference, name, text)
        for product, amount, reference, name, text in _SENT
    ]


def _downloads() -> list[object]:
    downloads = []
    for fixture, option in (
        ("camt054_qrr_zkb_sample.xml", "XQRR"),
        ("camt054_scor_zkb_sample.xml", "XSCR"),
        ("camt054_unreferenced_credit_zkb_sample.xml", "XDCI"),
        ("camt054_lsv_zkb_sample.xml", "XDDD"),
    ):
        btf = BusinessTransactionFormat(
            service_name="REP",
            message_name="camt.054",
            scope="CH",
            message_version="04",
            container="ZIP",
            service_option=option,
        )
        notifications = tuple(camt054.parse((_DATA / fixture).read_bytes()))
        downloads.append(tool.Download(btf, _DATA / fixture, notifications=notifications))
    return downloads


def test_every_simulated_payment_matches_its_transaction_in_the_bank_reports() -> None:
    assert tool.reconcile_transactions(_manifest(), _downloads()) == 0


@pytest.mark.parametrize(
    "change",
    [
        {"amount": Decimal("1000.01")},
        {"debtor_name": "Someone Else"},
        {"remittance_information": "Rechnung 9"},
        {"product": tool.Product.CREDITOR_REFERENCE},
        {"reference": "202610261213420100000000999"},
    ],
)
def test_a_payment_that_differs_from_its_transaction_fails(change: dict[str, object]) -> None:
    payments = _manifest()
    payments[0] = dataclasses.replace(payments[0], **change)
    assert tool.reconcile_transactions(payments, _downloads()) == 1
