"""Tests for tools/zkb-incoming-payments.py: the references and the CSV it submits.

The reference check digits are pinned to published examples rather than to the tool's own
output: the SIX QR-bill guidelines' QR reference, the ISO 11649 creditor reference, the
IBAN registry's Swiss example IBAN, and the LSV and QRR references in the ZKB
test-platform manual (section 2.3.1).
"""

import importlib.util
from decimal import Decimal
from pathlib import Path
from types import ModuleType

import pytest

_TOOL_PATH = Path(__file__).resolve().parent.parent / "tools" / "zkb-incoming-payments.py"
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
