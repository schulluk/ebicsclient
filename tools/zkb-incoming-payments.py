"""Simulate incoming payments on the ZKB test platform and check the camt reports over EBICS.

The ZKB ISO 20022 test platform can simulate incoming credits from a semicolon-separated CSV
file: QR-bill payments with a QR reference (``QRR``) or an ISO 11649 creditor reference
(``SCOR``), payments without a reference (``NON``), and LSV+ direct-debit collections
(``LSV``). The file is submitted as the BTF ``OTH / BIL / CH004TPS / csv`` (ZKB order type
``XTC``; test-platform manual, section 2.3.1 and table 3). The platform books the credits and
reports them in camt.052, camt.053 and camt.054 — which makes this loop the live oracle for the
library's camt parsers: the amounts going in are known, the bank's reports coming out are not
produced by this library.

Steps:

    csv      print the CSV that ``upload`` would send, without sending it
    upload   build the CSV, upload it over EBICS, and record what was sent (manifest.json)
    fetch    list the order types with data waiting (HAA), download each one, store the raw
             order data, parse every camt/pain message, and reconcile the credits against
             the run's manifest

    uv run python tools/zkb-incoming-payments.py upload --iban CH..
    # ... the platform needs 10-30 seconds to process the file ...
    uv run python tools/zkb-incoming-payments.py fetch

This is a test tool for one bank's test platform, not part of the library: the CSV format and
its BTF exist only there. It is configured like the examples, through the ``EBICS_*``
environment variables (see ``examples/_config.py``), and never contains credentials. The
credit account's IBAN is passed with ``--iban`` (or ``EBICS_SIMULATION_IBAN``); it must be an
account registered on the platform. Runs are stored outside the repository, in
``../local/simulation-runs/`` by default, because the downloaded reports carry account data.
"""

import argparse
import datetime
import json
import logging
import os
import sys
import zipfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from pathlib import Path

from dotenv import load_dotenv

from ebicsclient import (
    Bank,
    BusinessTransactionFormat,
    Client,
    CreditDebit,
    Entry,
    Notification,
    ReturnCodeError,
    Statement,
    User,
    load_keyring,
)
from ebicsclient.formats import camt052, camt053, camt054, pain002

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_ENV_FILE = _REPO_ROOT.parent / "local" / ".env"
_DEFAULT_RUNS_DIRECTORY = _REPO_ROOT.parent / "local" / "simulation-runs"
_MANIFEST_NAME = "manifest.json"
_CSV_NAME = "incoming-payments.csv"
_DOWNLOADS_DIRECTORY_NAME = "downloads"

#: The CSV upload for the camt simulation (ZKB order type ``XTC``). Transcribed from the test
#: subscriber's HTD registry: no message version and no container.
SIMULATION_INPUT = BusinessTransactionFormat(
    service_name="OTH",
    message_name="csv",
    scope="BIL",
    service_option="CH004TPS",
)

# EBICS_NO_DOWNLOAD_DATA_AVAILABLE (Annex 1): nothing (more) is waiting for this BTF.
_NO_DOWNLOAD_DATA_AVAILABLE = "090005"
# A safety stop for the "download until nothing is left" loop of one BTF.
_MAX_DOWNLOADS_PER_ORDER_TYPE = 20

# The CSV columns in the order of the manual's QRR/SCOR/NON example (section 2.3.1).
_COLUMNS = (
    "Product",
    "Charges",
    "IBAN",
    "Amount",
    "Reference",
    "Name",
    "Street",
    "Number",
    "Postcode",
    "City",
    "Country",
    "AdditionalRemittanceInformation",
    "UltimateDebtorName",
    "UltimateDebtorStreet",
    "UltimateDebtorNumber",
    "UltimateDebtorPostcode",
    "UltimateDebtorTownName",
    "UltimateDebtorCountry",
)
_SEPARATOR = ";"
# Maximum lengths from the manual's column table (section 2.3.1).
_MAX_NAME_LENGTH = 70
_MAX_ADDRESS_FIELD_LENGTH = 35
_MAX_REMITTANCE_INFORMATION_LENGTH = 140
_MAX_AMOUNT = Decimal("999999999.99")

# Swiss QR reference and ESR/LSV reference: 26 digits plus a modulo-10-recursive check digit
# (SIX, Swiss Implementation Guidelines QR-bill, annex B).
_REFERENCE_PAYLOAD_LENGTH = 26
_MODULO_10_RECURSIVE_TABLE = (0, 9, 4, 6, 8, 2, 7, 1, 3, 5)
# ISO 11649 creditor reference: "RF", two check digits, then 1-21 alphanumeric characters.
_CREDITOR_REFERENCE_MAX_BODY_LENGTH = 21


class Product(StrEnum):
    """The incoming-payment products the platform simulates (the CSV ``Product`` column)."""

    QR_REFERENCE = "QRR"
    CREDITOR_REFERENCE = "SCOR"
    WITHOUT_REFERENCE = "NON"
    DIRECT_DEBIT = "LSV"


@dataclass(frozen=True, slots=True)
class Debtor:
    """The (fictitious) payer of a simulated credit.

    Attributes:
        name: The payer's name.
        street: The street name.
        building_number: The building number.
        postcode: The postcode.
        town: The town.
        country: The ISO 3166-1 alpha-2 country code.
    """

    name: str
    street: str
    building_number: str
    postcode: str
    town: str
    country: str


@dataclass(frozen=True, slots=True)
class SimulatedPayment:
    """One incoming payment for the platform to simulate (one CSV row).

    Attributes:
        product: The payment product.
        amount: The amount in the credit account's currency (the platform derives the
            currency from the account).
        reference: The QR, LSV or creditor reference; ``None`` for ``NON``, which must not
            carry one.
        debtor: The payer.
        remittance_information: Free text for the payee (QRR/SCOR/NON only), or ``None``.
    """

    product: Product
    amount: Decimal
    reference: str | None
    debtor: Debtor
    remittance_information: str | None = None


def modulo_10_recursive_check_digit(digits: str) -> str:
    """Return the modulo-10-recursive check digit of a Swiss QR or ESR/LSV reference.

    Args:
        digits: The reference digits without the check digit.

    Returns:
        The single check digit, as text.

    Raises:
        ValueError: ``digits`` is empty or contains a non-digit.
    """
    if not digits or not digits.isascii() or not digits.isdigit():
        raise ValueError(f"A modulo-10 reference payload must be digits only, got {digits!r}")
    carry = 0
    for digit in digits:
        carry = _MODULO_10_RECURSIVE_TABLE[(carry + int(digit)) % 10]
    return str((10 - carry) % 10)


def numeric_reference(payload: str) -> str:
    """Build a 27-digit Swiss QR or ESR/LSV reference from a 26-digit payload.

    Args:
        payload: The 26 reference digits before the check digit.

    Returns:
        The payload followed by its modulo-10-recursive check digit.

    Raises:
        ValueError: ``payload`` is not exactly 26 digits.
    """
    if len(payload) != _REFERENCE_PAYLOAD_LENGTH:
        raise ValueError(
            f"A QR/ESR reference payload has {_REFERENCE_PAYLOAD_LENGTH} digits, "
            f"got {len(payload)}"
        )
    return payload + modulo_10_recursive_check_digit(payload)


def creditor_reference(body: str) -> str:
    """Build an ISO 11649 creditor reference (``RF`` + check digits + body).

    The check digits follow ISO 7064 MOD 97-10, as for an IBAN: the body is followed by
    ``RF00``, letters become numbers (A=10 ... Z=35), and the check is 98 minus the
    remainder modulo 97.

    Args:
        body: The reference body: 1-21 characters, digits and uppercase ASCII letters.

    Returns:
        The complete creditor reference, e.g. ``RF18539007547034``.

    Raises:
        ValueError: ``body`` is empty, too long, or contains another character.
    """
    if not 1 <= len(body) <= _CREDITOR_REFERENCE_MAX_BODY_LENGTH:
        raise ValueError(
            f"A creditor reference body has 1-{_CREDITOR_REFERENCE_MAX_BODY_LENGTH} "
            f"characters, got {len(body)}"
        )
    if not all(character.isdigit() or "A" <= character <= "Z" for character in body):
        raise ValueError(f"A creditor reference body must be 0-9 and A-Z only, got {body!r}")
    remainder = _modulo_97(body + "RF00")
    return f"RF{98 - remainder:02d}{body}"


def validate_iban(iban: str) -> str:
    """Check an IBAN's structure and ISO 13616 check digits; return it without spaces.

    Args:
        iban: The IBAN, with or without grouping spaces.

    Returns:
        The IBAN in its electronic form (no spaces, uppercase).

    Raises:
        ValueError: the IBAN is malformed or its check digits are wrong.
    """
    compact = iban.replace(" ", "").upper()
    if not 15 <= len(compact) <= 34 or not compact.isascii() or not compact.isalnum():
        raise ValueError("The IBAN is malformed")
    if not compact[:2].isalpha() or not compact[2:4].isdigit():
        raise ValueError("The IBAN must start with a country code and two check digits")
    if _modulo_97(compact[4:] + compact[:4]) != 1:
        raise ValueError("The IBAN's check digits are wrong")
    return compact


def _modulo_97(alphanumeric: str) -> int:
    """Return ``alphanumeric`` modulo 97, with letters read as numbers (A=10 ... Z=35)."""
    return int("".join(str(int(character, 36)) for character in alphanumeric)) % 97


def build_scenario(run_stamp: str) -> tuple[SimulatedPayment, ...]:
    """Return the payments one run simulates: several per product, distinct amounts.

    Several payments per product let the platform produce a collective booking (one entry
    whose amount is the product total) next to its resolution into single transactions.
    The amounts carry cents so a misread decimal separator shows up in the reconciliation.

    Args:
        run_stamp: 14 digits (``YYYYMMDDHHMMSS``) that make this run's references unique.

    Returns:
        The payments, in CSV row order.

    Raises:
        ValueError: ``run_stamp`` is not 14 digits.
    """
    if len(run_stamp) != 14 or not run_stamp.isdigit():
        raise ValueError(f"The run stamp must be 14 digits (YYYYMMDDHHMMSS), got {run_stamp!r}")
    debtors = (
        Debtor("Anna Beispiel", "Musterweg", "12", "8000", "Zuerich", "CH"),
        Debtor("Beat Exempel", "Testgasse", "3", "3000", "Bern", "CH"),
        Debtor("Carla Probst", "Beispielstrasse", "45", "4000", "Basel", "CH"),
    )

    def qr_reference(sequence: int) -> str:
        return numeric_reference(f"{run_stamp}01{sequence:010d}")

    def lsv_reference(sequence: int) -> str:
        return numeric_reference(f"{run_stamp}02{sequence:010d}")

    def scor_reference(sequence: int) -> str:
        return creditor_reference(f"EBICS{run_stamp}{sequence:02d}")

    qr = Product.QR_REFERENCE
    scor = Product.CREDITOR_REFERENCE
    return (
        SimulatedPayment(qr, Decimal("1000.00"), qr_reference(1), debtors[0], "Rechnung 1"),
        SimulatedPayment(qr, Decimal("250.50"), qr_reference(2), debtors[1], "Rechnung 2"),
        SimulatedPayment(qr, Decimal("75.25"), qr_reference(3), debtors[2]),
        SimulatedPayment(scor, Decimal("300.00"), scor_reference(1), debtors[0]),
        SimulatedPayment(scor, Decimal("120.75"), scor_reference(2), debtors[1]),
        SimulatedPayment(Product.WITHOUT_REFERENCE, Decimal("42.10"), None, debtors[2], "Spende"),
        SimulatedPayment(Product.DIRECT_DEBIT, Decimal("500.00"), lsv_reference(1), debtors[0]),
        SimulatedPayment(Product.DIRECT_DEBIT, Decimal("89.90"), lsv_reference(2), debtors[1]),
    )


def render_csv(iban: str, payments: Sequence[SimulatedPayment]) -> bytes:
    """Render the simulation CSV in the format of the test-platform manual (section 2.3.1).

    Args:
        iban: The credit account's IBAN (as registered on the platform).
        payments: The payments to simulate; at least one.

    Returns:
        The CSV as UTF-8 bytes: a header row, then one row per payment, each ended by a
        Unix line break.

    Raises:
        ValueError: the IBAN is invalid, there are no payments, or a field breaks one of the
            manual's rules (length, reference presence, amount range, separator in a value).
    """
    account = validate_iban(iban)
    if not payments:
        raise ValueError("The simulation needs at least one payment")
    rows = [_SEPARATOR.join(_COLUMNS)]
    for payment in payments:
        rows.append(_SEPARATOR.join(_row(account, payment)))
    return ("\n".join(rows) + "\n").encode("utf-8")


def _row(iban: str, payment: SimulatedPayment) -> list[str]:
    _validate_payment(payment)
    debtor = payment.debtor
    # The address and remittance columns beyond Country exist for QRR/SCOR/NON only.
    with_extras = payment.product is not Product.DIRECT_DEBIT
    values = [
        payment.product.value,
        "",  # Charges: none, so the booked amounts equal the simulated ones.
        iban,
        f"{payment.amount:.2f}",
        payment.reference or "",
        debtor.name,
        debtor.street,
        debtor.building_number,
        debtor.postcode,
        debtor.town,
        debtor.country,
        (payment.remittance_information or "") if with_extras else "",
        "",
        "",
        "",
        "",
        "",
        "",
    ]
    for value in values:
        if _SEPARATOR in value or "\n" in value or "\r" in value:
            raise ValueError(f"A CSV value must not contain {_SEPARATOR!r} or a line break")
    return values


def _validate_payment(payment: SimulatedPayment) -> None:
    if not Decimal("0") < payment.amount <= _MAX_AMOUNT:
        raise ValueError(f"Amount {payment.amount} is outside 0 < amount <= {_MAX_AMOUNT}")
    if payment.amount != payment.amount.quantize(Decimal("0.01")):
        raise ValueError(f"Amount {payment.amount} has more than two decimal places")
    if payment.product is Product.WITHOUT_REFERENCE:
        if payment.reference is not None:
            raise ValueError("A NON payment must not carry a reference")
    elif payment.reference is None:
        raise ValueError(f"A {payment.product.value} payment needs a reference")
    if len(payment.debtor.name) > _MAX_NAME_LENGTH:
        raise ValueError(f"Debtor name is longer than {_MAX_NAME_LENGTH} characters")
    for field in (
        payment.debtor.street,
        payment.debtor.building_number,
        payment.debtor.postcode,
        payment.debtor.town,
    ):
        if len(field) > _MAX_ADDRESS_FIELD_LENGTH:
            raise ValueError(f"Address field {field!r} is longer than 35 characters")
    remittance = payment.remittance_information
    if remittance is not None and len(remittance) > _MAX_REMITTANCE_INFORMATION_LENGTH:
        raise ValueError("Remittance information is longer than 140 characters")


# ---------------------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------------------


def step_csv(iban: str) -> int:
    """Print the CSV for a run starting now, without uploading it."""
    sys.stdout.write(render_csv(iban, build_scenario(_run_stamp())).decode("utf-8"))
    return 0


def step_upload(iban: str, runs_directory: Path) -> int:
    """Upload the simulation CSV and record the run in a new run directory."""
    run_stamp = _run_stamp()
    payments = build_scenario(run_stamp)
    order_data = render_csv(iban, payments)

    run_directory = runs_directory / run_stamp
    run_directory.mkdir(parents=True, exist_ok=False)
    (run_directory / _CSV_NAME).write_bytes(order_data)

    client = _online_client()
    transaction_id = client.upload(SIMULATION_INPUT, order_data)
    manifest = {
        "created": datetime.datetime.now(datetime.UTC).isoformat(),
        "transaction_id": transaction_id,
        "payments": [
            {
                "product": payment.product.value,
                "amount": f"{payment.amount:.2f}",
                "reference": payment.reference,
            }
            for payment in payments
        ],
    }
    (run_directory / _MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"Uploaded {len(payments)} simulated payments, transaction {transaction_id}.")
    print(f"Run recorded in {run_directory}")
    for product, total in _expected_totals(payments).items():
        print(f"  {product.value:<5} {total:>12}")
    print("Give the platform 10-30 seconds, then run the 'fetch' step.")
    return 0


def step_fetch(runs_directory: Path, run_directory: Path | None) -> int:
    """Download everything waiting, store it, parse it, and reconcile it with the run."""
    target = run_directory if run_directory is not None else _latest_run(runs_directory)
    downloads = target / _DOWNLOADS_DIRECTORY_NAME
    downloads.mkdir(parents=True, exist_ok=True)

    client = _online_client()
    order_types = _distinct(client.available_order_types())
    if not order_types:
        print("HAA: no order types have data waiting.")
        return 0
    print(f"HAA: {len(order_types)} distinct order type(s) with data waiting:")
    for btf in order_types:
        print(f"  {_label(btf)}")

    results: list[_Download] = []
    failures = 0
    for btf in order_types:
        fetched, failed = _download_all(client, btf, downloads, start_index=len(results) + 1)
        results.extend(fetched)
        failures += failed

    print()
    for result in results:
        _print_download(result)

    manifest_path = target / _MANIFEST_NAME
    if manifest_path.exists():
        failures += _reconcile(_load_manifest(manifest_path), results)
    else:
        print(f"\nNo {_MANIFEST_NAME} in {target}: nothing to reconcile against.")
    return 1 if failures else 0


# ---------------------------------------------------------------------------------------
# Download and parse
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Download:
    """One downloaded order and what its parser made of it."""

    btf: BusinessTransactionFormat
    path: Path
    statements: tuple[Statement, ...] = ()
    notifications: tuple[Notification, ...] = ()
    status_report_count: int = 0
    archive_members: tuple[str, ...] = ()


def _download_all(
    client: Client, btf: BusinessTransactionFormat, downloads: Path, *, start_index: int
) -> tuple[list[_Download], int]:
    """Download one BTF until the bank has nothing left; return the results and failures."""
    results: list[_Download] = []
    for attempt in range(_MAX_DOWNLOADS_PER_ORDER_TYPE):
        path = downloads / f"{start_index + attempt:02d}-{_file_stem(btf)}"
        holder: list[_Download] = []
        try:
            # Store and parse inside the pre-receipt hook: a parser failure then sends a
            # negative receipt and the bank keeps the data, while the raw bytes are on disk.
            client.download(btf, validate=_store_and_parse(btf, path, holder))
        except ReturnCodeError as error:
            if error.code == _NO_DOWNLOAD_DATA_AVAILABLE:
                return results, 0
            print(f"{_label(btf)}: download failed: {error}", file=sys.stderr)
            return results, 1
        except Exception as error:  # report every other failure per BTF and carry on
            print(f"{_label(btf)}: failed, data not acknowledged: {error!r}", file=sys.stderr)
            return results, 1
        results.extend(holder)
    limit = _MAX_DOWNLOADS_PER_ORDER_TYPE
    print(f"{_label(btf)}: stopped after {limit} downloads", file=sys.stderr)
    return results, 1


def _store_and_parse(
    btf: BusinessTransactionFormat, path_stem: Path, holder: list[_Download]
) -> Callable[[bytes], None]:
    def store_and_parse(order_data: bytes) -> None:
        suffix = ".zip" if order_data.startswith(b"PK\x03\x04") else ".xml"
        path = path_stem.with_name(path_stem.name + suffix)
        path.write_bytes(order_data)
        holder.append(_parse(btf, path, order_data))

    return store_and_parse


def _parse(btf: BusinessTransactionFormat, path: Path, order_data: bytes) -> _Download:
    if btf.message_name == "camt.053":
        return _Download(btf, path, statements=tuple(camt053.parse(order_data)))
    if btf.message_name == "camt.052":
        return _Download(btf, path, statements=tuple(camt052.parse(order_data)))
    if btf.message_name == "camt.054":
        return _Download(btf, path, notifications=tuple(camt054.parse(order_data)))
    if btf.message_name == "pain.002":
        return _Download(btf, path, status_report_count=len(pain002.parse(order_data)))
    members: tuple[str, ...] = ()
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            members = tuple(sorted(archive.namelist()))
    return _Download(btf, path, archive_members=members)


def _print_download(result: _Download) -> None:
    print(f"{_label(result.btf)} -> {result.path.name}")
    for statement in result.statements:
        print(f"  {statement.identification}: {len(statement.entries)} entries")
        for balance in statement.balances:
            print(
                f"    balance {balance.code} {balance.credit_debit.value} "
                f"{balance.amount} {balance.currency} on {balance.date.isoformat()}"
            )
        for entry in statement.entries:
            print(f"    {_entry_text(entry)}")
        reconciliation = _balance_reconciliation(statement)
        if reconciliation is not None:
            print(f"    balances reconcile: {reconciliation}")
    for notification in result.notifications:
        print(f"  {notification.identification}: {len(notification.entries)} entries")
        for entry in notification.entries:
            print(f"    {_entry_text(entry)}")
    if result.status_report_count:
        print(f"  {result.status_report_count} payment status report(s)")
    for member in result.archive_members:
        print(f"  archive member {member}")


def _entry_text(entry: Entry) -> str:
    booking = entry.booking_date.isoformat() if entry.booking_date is not None else "-"
    return (
        f"{entry.credit_debit.value} {entry.amount:>12} {entry.currency} "
        f"{entry.status} booked {booking} ref {entry.reference or '-'}"
    )


def _balance_reconciliation(statement: Statement) -> str | None:
    """Check opening + credits - debits = closing, when both booked balances are present."""
    opening, closing = statement.opening_balance, statement.closing_balance
    if opening is None or closing is None:
        return None
    movement = sum(
        (entry.amount if entry.credit_debit is CreditDebit.CREDIT else -entry.amount)
        for entry in statement.entries
    )
    expected = _signed(opening.amount, opening.credit_debit) + movement
    actual = _signed(closing.amount, closing.credit_debit)
    verdict = "yes" if expected == actual else "NO"
    return f"{verdict} (opening + movement = {expected}, closing = {actual})"


def _signed(amount: Decimal, credit_debit: CreditDebit) -> Decimal:
    return amount if credit_debit is CreditDebit.CREDIT else -amount


# ---------------------------------------------------------------------------------------
# Reconciliation against the manifest
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _ManifestPayment:
    product: Product
    amount: Decimal


def _load_manifest(path: Path) -> list[_ManifestPayment]:
    data = json.loads(path.read_text())
    return [
        _ManifestPayment(Product(payment["product"]), Decimal(payment["amount"]))
        for payment in data["payments"]
    ]


def _expected_totals(payments: Sequence[SimulatedPayment]) -> dict[Product, Decimal]:
    totals: dict[Product, Decimal] = {}
    for payment in payments:
        totals[payment.product] = totals.get(payment.product, Decimal("0")) + payment.amount
    return totals


def _reconcile(payments: list[_ManifestPayment], results: list[_Download]) -> int:
    """Find each product's credits in the reports; return how many products went missing.

    A product's credits count as reported by a message when the message has a credit entry
    for the product total (a collective booking) or one credit entry per single amount.
    Every simulated credit must be booked, so a product absent from every camt.053 and
    camt.052 is a failure; its absence from camt.054 is reported but depends on which
    notifications the platform's settings enable.
    """
    print("\nReconciliation against the manifest:")
    missing = 0
    products = sorted({payment.product for payment in payments}, key=lambda item: item.value)
    for product in products:
        amounts = [payment.amount for payment in payments if payment.product is product]
        total = sum(amounts, Decimal("0"))
        found_in: list[str] = []
        for result in results:
            match = _match(_credit_entries(result), total, amounts)
            if match is not None:
                found_in.append(f"{_label(result.btf)} ({match})")
        booked = any(label.startswith(("EOP/", "STM/")) for label in found_in)
        print(f"  {product.value:<5} {len(amounts)} payment(s), total {total}")
        for label in found_in:
            print(f"        found in {label}")
        if not booked:
            print("        NOT FOUND in any camt.053/camt.052 — the credits were not booked")
            missing += 1
    return missing


def _credit_entries(result: _Download) -> list[Entry]:
    entries = [entry for statement in result.statements for entry in statement.entries]
    entries += [entry for notification in result.notifications for entry in notification.entries]
    return [entry for entry in entries if entry.credit_debit is CreditDebit.CREDIT]


def _match(entries: list[Entry], total: Decimal, amounts: list[Decimal]) -> str | None:
    credited = [entry.amount for entry in entries]
    if total in credited:
        return "collective entry"
    remaining = list(credited)
    for amount in amounts:
        if amount not in remaining:
            return None
        remaining.remove(amount)
    return "single entries"


# ---------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------


def _online_client() -> Client:
    """Build the client from the ``EBICS_*`` variables and fetch the bank's keys (HPB)."""
    bank = Bank(host_id=os.environ["EBICS_HOST_ID"], url=os.environ["EBICS_URL"])
    user = User(partner_id=os.environ["EBICS_PARTNER_ID"], user_id=os.environ["EBICS_USER_ID"])
    keyring = load_keyring(
        Path(os.environ["EBICS_KEYRING_PATH"]), os.environ["EBICS_KEYRING_PASSPHRASE"]
    )
    client = Client(bank, user, keyring)
    client.hpb()
    return client


def _run_stamp() -> str:
    return datetime.datetime.now(datetime.UTC).strftime("%Y%m%d%H%M%S")


def _latest_run(runs_directory: Path) -> Path:
    runs = sorted(path for path in runs_directory.glob("*") if path.is_dir())
    if not runs:
        raise FileNotFoundError(
            f"No run directory in {runs_directory}; run 'upload' first or pass --run"
        )
    return runs[-1]


def _distinct(order_types: list[BusinessTransactionFormat]) -> list[BusinessTransactionFormat]:
    # HAA can list a BTF once per waiting order; one download loop per BTF fetches them all.
    return list(dict.fromkeys(order_types))


def _label(btf: BusinessTransactionFormat) -> str:
    parts = [btf.service_name, btf.scope or "-", btf.service_option or "-", btf.message_name]
    version = f" v{btf.message_version}" if btf.message_version else ""
    container = f" {btf.container}" if btf.container else ""
    return "/".join(parts) + version + container


def _file_stem(btf: BusinessTransactionFormat) -> str:
    parts = (btf.service_name, btf.scope, btf.service_option, btf.message_name)
    stem = "-".join(part for part in parts if part)
    return stem + (f"-v{btf.message_version}" if btf.message_version else "")


def main() -> int:
    """Parse the chosen step and run it. Returns a process exit code."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    load_dotenv(os.environ.get("EBICS_ENV_FILE", _DEFAULT_ENV_FILE))

    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--runs-directory",
        type=Path,
        default=_DEFAULT_RUNS_DIRECTORY,
        help="where runs are stored (default: ../local/simulation-runs)",
    )
    steps = parser.add_subparsers(dest="step", required=True)
    for name, help_text in (
        ("csv", "print the CSV without uploading it"),
        ("upload", "upload the CSV and record the run"),
    ):
        step = steps.add_parser(name, help=help_text)
        step.add_argument(
            "--iban",
            default=os.environ.get("EBICS_SIMULATION_IBAN"),
            help="the credit account's IBAN (default: EBICS_SIMULATION_IBAN)",
        )
    fetch = steps.add_parser("fetch", help="download, parse and reconcile what is waiting")
    fetch.add_argument(
        "--run", type=Path, default=None, help="the run directory (default: the latest run)"
    )
    arguments = parser.parse_args()

    try:
        if arguments.step == "fetch":
            return step_fetch(arguments.runs_directory, arguments.run)
        if arguments.iban is None:
            print("Pass --iban or set EBICS_SIMULATION_IBAN", file=sys.stderr)
            return 2
        if arguments.step == "csv":
            return step_csv(arguments.iban)
        return step_upload(arguments.iban, arguments.runs_directory)
    except KeyError as error:
        print(f"Missing environment variable: {error}", file=sys.stderr)
        return 2
    except ValueError as error:
        print(f"Invalid input: {error}", file=sys.stderr)
        return 2
    except FileNotFoundError as error:
        print(error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
