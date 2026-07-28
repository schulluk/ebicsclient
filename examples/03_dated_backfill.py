"""Backfill history: fetch a specific past date range, and fail closed if the bank ignores it.

    Marco is importing a company's accounts into a personal-finance tool for the first time.
    The nightly feed handles *new* statements fine, but the tool starts empty — he needs the
    back-history: every statement for the first quarter, 1 January to 31 March. EBICS can ask
    for exactly that with a ``DateRange`` order parameter, so instead of waiting for the data
    to trickle in he requests the whole quarter at once.

There is a catch worth being loud about: ``DateRange`` is a *request*, and whether a given
bank actually honours it is bank-specific. If a bank quietly ignores the range and hands back
its usual not-yet-delivered data, a naive importer would file today's statements under "Q1"
and corrupt the history. So the dated ``download_statements`` guards the result: every
returned entry's booking date must fall inside the requested window, or it raises
``DateRangeMismatchError`` and leaves the data un-acknowledged at the bank. Better a clear
failure than silently wrong history.

    uv run python examples/03_dated_backfill.py 2025-01-01 2025-03-31
"""

import argparse
import sys
from datetime import date

from ebicsclient import DateRange, DateRangeMismatchError

from _config import load_environment, online_client


def main() -> int:
    """Fetch statements for a past date range, guarding against a bank that ignores it."""
    load_environment()
    start, end = _parse_range()

    client = online_client()
    date_range = DateRange(start=start, end=end)

    try:
        statements = client.download_statements(date_range=date_range)
    except DateRangeMismatchError as mismatch:
        # The bank returned an entry outside the window — it likely does not support
        # DateRange. The data was NOT acknowledged, so nothing was lost; do not treat these
        # statements as belonging to the requested period.
        print(f"Backfill aborted — the bank did not honour the range: {mismatch}", file=sys.stderr)
        return 1

    total_entries = sum(len(statement.entries) for statement in statements)
    plural = "y" if total_entries == 1 else "ies"
    print(
        f"Backfilled {start.isoformat()}..{end.isoformat()}: "
        f"{len(statements)} statement(s), {total_entries} entr{plural}."
    )
    for statement in statements:
        account = statement.iban if statement.iban is not None else "(no IBAN)"
        print(f"  {statement.identification}  {account}  ({len(statement.entries)} entries)")
    return 0


def _parse_range() -> tuple[date, date]:
    """Parse the two ISO dates (YYYY-MM-DD) from the command line."""
    parser = argparse.ArgumentParser(description="Backfill statements for a date range.")
    parser.add_argument("start", type=date.fromisoformat, help="inclusive start date, YYYY-MM-DD")
    parser.add_argument("end", type=date.fromisoformat, help="inclusive end date, YYYY-MM-DD")
    arguments = parser.parse_args()
    return arguments.start, arguments.end


if __name__ == "__main__":
    raise SystemExit(main())
