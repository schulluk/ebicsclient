"""The nightly job: pull yesterday's statements, book them, and only then acknowledge.

    Every night at 02:00 a cron job on Priya's finance server wakes up and asks the bank for
    the new end-of-day statements. It records each booking into the ledger, then lets the
    bank mark the statements delivered so tomorrow's run does not fetch them again. The one
    rule Priya insisted on: never tell the bank "got it" until the data is safely landed. If
    the ledger write fails, or a statement will not parse, the statements must stay at the
    bank so the next run can try again — losing a day of bookings to a half-finished import
    is not acceptable.

This is the library's default behaviour, and it is why :meth:`Client.download` acknowledges
*last*. The download decrypts and parses before sending the positive receipt; if anything in
between raises, it sends a *negative* receipt instead and the bank keeps the data. Here we
lean on that with the ``validate`` seam: the "booking" (this example just prints, but pretend
it is a database write) runs before the receipt, so any failure leaves the statements
un-acknowledged at the bank.

    uv run python examples/02_daily_statement_sync.py
"""

from ebicsclient import Statement
from ebicsclient.formats import camt053
from ebicsclient.models import CAMT_053

from _config import load_environment, online_client


def main() -> int:
    """Download today's statements and 'book' them; acknowledge only if all succeed."""
    load_environment()
    client = online_client()

    booked = 0

    def book_everything(order_data: bytes) -> None:
        """Post every entry to the ledger. Runs *before* the receipt (via ``validate``), so
        if it raises, the bank is sent a negative receipt and keeps the statements."""
        nonlocal booked
        for statement in camt053.parse(order_data):
            booked += _book(statement)

    # validate= is the seam that runs before the acknowledgement. Doing the real work there
    # is what makes this fail closed: an error propagates and the data is NOT consumed.
    client.download(CAMT_053, validate=book_everything)

    plural = "y" if booked == 1 else "ies"
    print(f"\nBooked {booked} entr{plural}; statements acknowledged at the bank.")
    return 0


def _book(statement: Statement) -> int:
    """Pretend to persist one statement's entries to a ledger; return how many were booked.

    A real implementation would write to a database inside a transaction and let any error
    surface — that is what keeps the EBICS data un-acknowledged on failure.
    """
    account = statement.iban if statement.iban is not None else "(no IBAN)"
    print(f"  booking {statement.identification}  {account}  ({len(statement.entries)} entries)")
    for entry in statement.entries:
        booking = entry.booking_date.isoformat() if entry.booking_date is not None else "?"
        print(f"      {booking}  {entry.credit_debit.value}  {entry.amount} {entry.currency}")
    return len(statement.entries)


if __name__ == "__main__":
    raise SystemExit(main())
