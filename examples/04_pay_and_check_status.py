"""Submit a payment, then come back for the bank's verdict.

    Friday is supplier-payment day. Sofia's system has generated a pain.001 file — a batch of
    credit transfers — and she uploads it to the bank over EBICS. The upload returning a
    transaction ID only means the bank accepted the *envelope*: the signature verified, the
    encryption was right, the file is syntactically an order. It does *not* mean the payments
    will go through. Some minutes later the bank publishes a pain.002 status report with the
    real answer — accepted, partially accepted, or rejected, sometimes down to the individual
    transaction with a reason code. Sofia's workflow is two acts: pay now, check later.

This example mirrors that with two steps. ``pay`` uploads the pain.001 you point it at;
``status`` downloads the pain.002 reports and prints the group and per-transaction outcomes.
Run ``pay`` first, give the bank a little time, then run ``status``.

    uv run python examples/04_pay_and_check_status.py pay path/to/payment.xml
    # ... wait for the bank to process it ...
    uv run python examples/04_pay_and_check_status.py status
"""

import argparse
from collections.abc import Iterable
from pathlib import Path

from ebicsclient import StatusReason
from ebicsclient.models import PAIN_001

from _config import load_environment, online_client


def pay(pain001_path: Path) -> int:
    """Upload a pain.001 credit-transfer file and report the transaction ID."""
    order_data = pain001_path.read_bytes()
    client = online_client()
    transaction_id = client.upload(PAIN_001, order_data)
    print(
        f"Submitted {pain001_path.name} ({len(order_data)} bytes) — transaction {transaction_id}."
    )
    print("The bank accepted the envelope, signature, and encryption.")
    print("Give it a few minutes, then run the 'status' step to fetch the pain.002 verdict.")
    return 0


def status() -> int:
    """Download the pain.002 payment status reports and print each outcome."""
    client = online_client()
    reports = client.download_payment_status_reports()

    if not reports:
        print("No payment status reports available yet — the bank may still be processing.")
        return 0

    for report in reports:
        answers = report.original_message_id or "(unknown pain.001)"
        print(
            f"Report {report.identification}  answering {answers}  "
            f"group status: {report.group_status}"
        )
        _print_reasons("  group reason", report.reasons)
        for payment in report.payments:
            print(f"  payment block {payment.original_payment_information_id}: {payment.status}")
            _print_reasons("    reason", payment.reasons)
            for transaction in payment.transactions:
                reference = (
                    transaction.original_end_to_end_id
                    or transaction.original_instruction_id
                    or "?"
                )
                print(f"    txn {reference}: {transaction.status}")
                _print_reasons("      reason", transaction.reasons)
    return 0


def _print_reasons(label: str, reasons: Iterable[StatusReason]) -> None:
    """Print each ISO status reason (code + any free-text detail) under ``label``, if any."""
    for reason in reasons:
        detail = f" — {reason.additional_information}" if reason.additional_information else ""
        code = reason.code if reason.code is not None else "(no code)"
        print(f"{label}: {code}{detail}")


def main() -> int:
    """Dispatch the chosen step (pay or status)."""
    load_environment()

    parser = argparse.ArgumentParser(description="Submit a payment and check its status.")
    subcommands = parser.add_subparsers(dest="step", required=True)
    pay_command = subcommands.add_parser("pay", help="upload a pain.001 file")
    pay_command.add_argument("path", type=Path, help="path to the pain.001 document")
    subcommands.add_parser("status", help="download the pain.002 status reports")

    arguments = parser.parse_args()
    if arguments.step == "pay":
        return pay(arguments.path)
    return status()


if __name__ == "__main__":
    raise SystemExit(main())
