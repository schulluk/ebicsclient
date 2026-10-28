"""Match the day's incoming payments to invoices, out of one collective credit.

A Swiss bank books the day's QR-bill credits as *one* entry for the total: a single line on
the statement, which does not say who paid which invoice. The camt.054 booking advice
carries the resolution underneath that entry: each payment with its own amount, the QR or
creditor reference the payer quoted, the payer's name and IBAN, and the remittance text.
``download_booking_advices()`` parses the advice into :class:`~ebicsclient.Notification`
objects; every entry lists its payments as :class:`~ebicsclient.TransactionDetails` under
``entry.transactions`` (one for a plain booking, many for a collective one).

This example groups the credits by creditor reference, the key an invoice system matches
on, and lists the credits that carry none, which need a person to look at them. The sum of
an entry's transactions is printed next to the entry's own amount, so a collective booking
can be checked against its parts.

Which camt.054 tuple carries the resolution differs per bank: the plain ``CAMT_054``
(``REP / CH / camt.054 / 08 / ZIP``), or a variant with a service option such as ``XQRR``,
sometimes in message version ``04``. The bank's registry says which (HTD, see
``08_bank_discovery.py``); ``--option`` and ``--message-version`` request a variant. The
advices are consumed by default, as a reconciliation job would; ``--peek`` leaves them at
the bank, so a run can be repeated.

    uv run python examples/07_incoming_payments.py
    uv run python examples/07_incoming_payments.py --peek
    uv run python examples/07_incoming_payments.py --option XQRR --message-version 04
"""

import argparse
from collections import defaultdict
from dataclasses import replace
from decimal import Decimal

from ebicsclient import (
    CAMT_054,
    BusinessTransactionFormat,
    CreditDebit,
    Entry,
    Notification,
    ReceiptPolicy,
    ReturnCodeError,
    TransactionDetails,
)

from _config import is_nothing_waiting, load_environment, online_client


def main() -> int:
    """Download the booking advices and group the incoming payments by creditor reference."""
    load_environment()
    arguments = _parse_arguments()
    btf = _requested_tuple(arguments.option, arguments.message_version)
    receipt_policy = ReceiptPolicy.KEEP if arguments.peek else ReceiptPolicy.ACKNOWLEDGE

    client = online_client()
    try:
        notifications = client.download_booking_advices(btf, receipt_policy=receipt_policy)
    except ReturnCodeError as error:
        if not is_nothing_waiting(error):
            raise
        print("Nothing waiting for this camt.054 tuple (090005). 08_bank_discovery.py lists the")
        print("registered variants, and its HAA step shows which of them hold data.")
        return 0

    by_reference: dict[str, list[TransactionDetails]] = defaultdict(list)
    unreferenced: list[TransactionDetails] = []
    for notification in notifications:
        _print_notification(notification)
        for entry in notification.entries:
            if entry.credit_debit is not CreditDebit.CREDIT:
                continue  # outgoing payments are checked against the pain.002, not invoices
            for transaction in entry.transactions:
                reference = _creditor_reference(transaction)
                if reference is None:
                    unreferenced.append(transaction)
                else:
                    by_reference[reference].append(transaction)

    _print_reconciliation(by_reference, unreferenced)
    if arguments.peek:
        print("\nLeft at the bank (negative receipt): the next download gets the same advices.")
    return 0


def _requested_tuple(
    option: str | None, message_version: str | None
) -> BusinessTransactionFormat:
    """Return ``CAMT_054`` with the variant option and message version, if any were given."""
    btf = CAMT_054
    if option is not None:
        btf = replace(btf, service_option=option)
    if message_version is not None:
        btf = replace(btf, message_version=message_version)
    return btf


def _print_notification(notification: Notification) -> None:
    """Print one advice with its entries and the single transactions behind them."""
    account = notification.iban if notification.iban is not None else "(no IBAN)"
    count = len(notification.entries)
    print(f"\nAdvice {notification.identification}  {account}  ({count} entries)")
    for entry in notification.entries:
        _print_entry(entry)


def _print_entry(entry: Entry) -> None:
    """Print an entry's total and, underneath, each transaction behind it."""
    booking = entry.booking_date.isoformat() if entry.booking_date is not None else "?"
    detail = f"{len(entry.transactions)} transaction(s)"
    resolved = _resolved_total(entry)
    if resolved is not None:
        detail += f", together {resolved} {entry.currency}"
    print(f"  {booking}  {entry.credit_debit.value}  {entry.amount} {entry.currency}  ({detail})")
    for transaction in entry.transactions:
        _print_transaction(transaction)


def _resolved_total(entry: Entry) -> Decimal | None:
    """Sum the entry's transactions; ``None`` without transactions, an amount or one currency."""
    if not entry.transactions:
        return None
    total = Decimal(0)
    for transaction in entry.transactions:
        if transaction.amount is None or transaction.currency != entry.currency:
            return None
        total += transaction.amount
    return total


def _print_transaction(transaction: TransactionDetails) -> None:
    """Print one transaction: amount, creditor reference, payer and remittance text."""
    if transaction.amount is not None:
        amount = f"{transaction.amount} {transaction.currency}"
    else:
        amount = "(no amount)"
    reference = _creditor_reference(transaction)
    reference_text = reference if reference is not None else "(no reference)"
    payer = transaction.debtor_name if transaction.debtor_name is not None else "(no payer name)"
    print(f"      {amount:>18}  {reference_text:<30}  {payer}")
    for line in transaction.remittance_information:
        print(f"      {'':>18}  {line}")


def _creditor_reference(transaction: TransactionDetails) -> str | None:
    """Return the first structured creditor reference (QR, SCOR, ...) the transaction carries."""
    for creditor_reference in transaction.creditor_references:
        if creditor_reference.reference is not None:
            return creditor_reference.reference
    return None


def _print_reconciliation(
    by_reference: dict[str, list[TransactionDetails]], unreferenced: list[TransactionDetails]
) -> None:
    """Print the credits per creditor reference, then those a person has to match by hand."""
    print("\nCredits by creditor reference (the key an invoice is matched on):")
    if not by_reference:
        print("  none of the credits carried a creditor reference")
    for reference, transactions in sorted(by_reference.items()):
        payers = sorted(
            {
                transaction.debtor_name
                for transaction in transactions
                if transaction.debtor_name is not None
            }
        )
        print(
            f"  {reference:<30} {len(transactions)} payment(s)  "
            f"{_totals_by_currency(transactions)}  {', '.join(payers)}"
        )
    if unreferenced:
        print(f"\n{len(unreferenced)} credit(s) without a creditor reference, to match by hand:")
        for transaction in unreferenced:
            _print_transaction(transaction)


def _totals_by_currency(transactions: list[TransactionDetails]) -> str:
    """Format the transactions' totals, one per currency, such as ``150.00 CHF``."""
    totals: dict[str, Decimal] = defaultdict(Decimal)
    for transaction in transactions:
        if transaction.amount is not None and transaction.currency is not None:
            totals[transaction.currency] += transaction.amount
    return ", ".join(f"{amount} {currency}" for currency, amount in sorted(totals.items()))


def _parse_arguments() -> argparse.Namespace:
    """Parse ``--peek``, ``--option`` and ``--message-version``."""
    parser = argparse.ArgumentParser(description="Group incoming payments by creditor reference.")
    parser.add_argument(
        "--peek", action="store_true", help="leave the advices at the bank (ReceiptPolicy.KEEP)"
    )
    parser.add_argument("--option", help="service option of a variant camt.054 tuple, such as XQRR")
    parser.add_argument("--message-version", help="camt.054 message version, such as 04")
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(main())
