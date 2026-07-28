"""Peek at what the bank is holding — without consuming it.

    Dana runs operations at a small treasury team. A new account has just been wired up for
    EBICS, and before the nightly import job goes live she wants to *see* what the bank will
    deliver — which IBAN, roughly how many entries — to sanity-check that the right mandate
    was linked. But she must not actually collect the statements: in EBICS a positive receipt
    tells the bank "I've got it, you can stop offering it", and if she consumes them now the
    real import tonight would find nothing. She wants a look, not a take.

That is exactly what ``ReceiptPolicy.KEEP`` is for. The download runs in full — initialise,
transfer, decrypt, parse — but finishes with a *negative* receipt, so the bank keeps the
data queued for the next reader. It is a read-only peek: safe to run against production, as
often as you like, without disturbing whatever consumes the data for real.

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
