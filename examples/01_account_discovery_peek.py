"""Peek at what the bank is holding — without consuming it.

Downloads the end-of-day statements with ``ReceiptPolicy.KEEP``: the download runs in full
— initialise, transfer, decrypt, parse — but finishes with a *negative* receipt, so the bank
keeps the data queued for the next reader instead of marking it delivered. A positive receipt
(the default) tells the bank "I've got it, stop offering it"; ``KEEP`` declines that.

Use this for a read-only look at what is waiting — checking a newly wired-up account, say —
without disturbing whatever consumes the data for real. It is safe to run repeatedly against
production; each run leaves the statements available.

    uv run python examples/01_account_discovery_peek.py
"""

from ebicsclient import ReceiptPolicy

from _config import load_environment, online_client


def main() -> int:
    """Peek at the statements waiting at the bank without acknowledging them."""
    load_environment()
    client = online_client()

    # KEEP: run the whole download, but decline it with a negative receipt at the end, so
    # the bank still has the data for tonight's real (acknowledging) import.
    statements = client.download_statements(receipt_policy=ReceiptPolicy.KEEP)

    if not statements:
        print("Nothing waiting: the bank offered no end-of-day statements right now.")
        return 0

    print(f"The bank is holding {len(statements)} statement(s) — peeked, not consumed:\n")
    for statement in statements:
        account = statement.iban if statement.iban is not None else "(no IBAN)"
        print(f"  {statement.identification}  {account}  ({len(statement.entries)} entries)")
        balance = statement.closing_balance
        if balance is not None:
            print(
                f"      closing {balance.amount} {balance.currency} on {balance.date.isoformat()}"
            )

    print("\nThese are still queued at the bank — the negative receipt left them untouched.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
