"""Insist on the message version you asked for.

A download names the ISO 20022 message and version it wants, ``camt.053`` version ``08``
say, and every delivered document declares what it actually is in its root namespace. The
two can differ: a bank in a format transition, an order type set up for the older vintage,
a test platform whose simulation still produces version ``04``. The parsers read every
version, so by default (``VersionPolicy.ACCEPT_ANY``) such a download succeeds and only
logs a warning. That is fine for a nightly import and wrong for a system that archives the
documents and promised its auditors a particular format.

``Client(..., version_policy=VersionPolicy.STRICT)`` makes the mismatch an error: the
delivered version is compared before the receipt, a mismatch raises
``MessageVersionMismatchError`` and sends a negative receipt, so the data stays at the bank
instead of being consumed under the wrong label. The example runs the statement download
under the strict policy and, on a mismatch, says which version the bank delivers, so the
caller can decide whether to request that version instead (the same tuple with another
``message_version``) or to take it up with the bank.

    uv run python examples/10_strict_message_version.py
"""

from ebicsclient import (
    CAMT_053,
    MessageVersionMismatchError,
    ReceiptPolicy,
    ReturnCodeError,
    VersionPolicy,
)

from _config import is_nothing_waiting, load_environment, online_client


def main() -> int:
    """Download the statements under the strict version policy and report a mismatch."""
    load_environment()
    client = online_client(version_policy=VersionPolicy.STRICT)

    try:
        statements = client.download_statements(CAMT_053, receipt_policy=ReceiptPolicy.KEEP)
    except ReturnCodeError as error:
        if not is_nothing_waiting(error):
            raise
        print("Nothing waiting: the bank holds no end-of-day statements right now (090005).")
        return 0
    except MessageVersionMismatchError as mismatch:
        print(f"Requested {mismatch.requested}; the bank delivered {mismatch.delivered}.")
        print("The data was not acknowledged and is still at the bank. Either request the")
        print("version the bank delivers (the same BTF with that message_version) or ask the")
        print("bank to deliver the registered one.")
        return 1

    print(
        f"{len(statements)} statement(s) delivered as {CAMT_053.message_name} version "
        f"{CAMT_053.message_version}, exactly as requested:"
    )
    for statement in statements:
        account = statement.iban if statement.iban is not None else "(no IBAN)"
        print(f"  {statement.identification}  {account}  ({len(statement.entries)} entries)")
    print("\nLeft at the bank (ReceiptPolicy.KEEP), so the real import still gets them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
