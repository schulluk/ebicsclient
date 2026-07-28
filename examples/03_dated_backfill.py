"""Backfill history: fetch a specific past date range, and fail closed if the bank ignores it.

Fetches statements for an explicit past period using the EBICS ``DateRange`` order parameter
— useful for populating back-history rather than waiting for new statements to arrive. Pass
the inclusive start and end dates on the command line.

``DateRange`` is a *request*, and whether a bank honours it is bank-specific. If a bank
ignores the range and returns its usual not-yet-delivered data, filing that under the
requested period would corrupt the history. So the dated ``download_statements`` guards the
result: every returned entry's booking date must fall inside the requested window, or it
raises ``DateRangeMismatchError`` and leaves the data un-acknowledged at the bank — a clear
failure instead of silently wrong data.

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
