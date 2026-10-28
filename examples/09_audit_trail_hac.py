"""Did the bank verify my signature? Read its log of EBICS actions (HAC).

An accepted upload returns a transaction ID, and ``000000`` says only that the exchange
worked: the bank verifies the electronic signature afterwards, and a rejected signature or
file produces no error on the upload itself. The customer acknowledgement, order type
``HAC``, is the bank's own log of every EBICS action of the customer since the previous HAC
download: each upload and download, each signature check with its ISO reason code, and a
final label per order once nothing more will follow.

``customer_acknowledgement()`` returns it as a :class:`~ebicsclient.CustomerAcknowledgement`
with one :class:`~ebicsclient.AcknowledgementEntry` per step. This example groups the
entries by order and reads the verdict off them: ``DS01`` on the signature check means the
signatures were correct, the final label ``ORDER_HAC_FINAL_POS`` or ``ORDER_HAC_FINAL_NEG``
closes the order, and every other reason code (``TD03`` file format invalid, say) is listed
so nothing is hidden.

By default the log is left at the bank (``ReceiptPolicy.KEEP``), so the example can be run
again and an audit job that consumes the log is not disturbed; ``--consume`` marks it as
fetched, so the next download starts after it.

    uv run python examples/09_audit_trail_hac.py
    uv run python examples/09_audit_trail_hac.py --consume
"""

import argparse
from collections import defaultdict

from ebicsclient import (
    AcknowledgementAction,
    AcknowledgementEntry,
    BusinessTransactionFormat,
    ReceiptPolicy,
    ReturnCodeError,
)

from _config import is_nothing_waiting, load_environment, online_client

#: ISO reason code the bank logs when an order's electronic signatures were correct.
SIGNATURES_CORRECT = "DS01"
#: ISO reason code the bank logs for a successful transmission.
TRANSMISSION_SUCCESSFUL = "TS01"
#: The reason codes of routine success, left out of the verdict's list of other codes.
ROUTINE_CODES = frozenset({SIGNATURES_CORRECT, TRANSMISSION_SUCCESSFUL})


def main() -> int:
    """Download the customer acknowledgement and print each order's steps and verdict."""
    load_environment()
    arguments = _parse_arguments()
    receipt_policy = ReceiptPolicy.ACKNOWLEDGE if arguments.consume else ReceiptPolicy.KEEP

    client = online_client()
    try:
        acknowledgement = client.customer_acknowledgement(receipt_policy=receipt_policy)
    except ReturnCodeError as error:
        if not is_nothing_waiting(error):
            raise
        print("The bank has nothing to report since the last HAC download (090005).")
        return 0

    print(
        f"Customer acknowledgement {acknowledgement.identification} from "
        f"{acknowledgement.host_id}, created {acknowledgement.created_at.isoformat()}: "
        f"{len(acknowledgement.entries)} entries"
    )
    by_order: dict[str | None, list[AcknowledgementEntry]] = defaultdict(list)
    for entry in acknowledgement.entries:
        by_order[entry.order_id].append(entry)
    for order_id, entries in by_order.items():
        _print_order(order_id, entries)

    if not arguments.consume:
        print("\nLeft at the bank (negative receipt); pass --consume to mark the log as fetched.")
    return 0


def _print_order(order_id: str | None, entries: list[AcknowledgementEntry]) -> None:
    """Print an order's steps in the bank's order, then the verdict read off them.

    Downloads get no order ID and no final label; their steps are listed without a verdict.
    """
    first = entries[0]
    order_type = first.admin_order_type if first.admin_order_type is not None else "?"
    if order_id is None:
        print("\nSteps without an order ID (downloads)")
    else:
        print(f"\nOrder {order_id}  {order_type}  {_describe(first.service)}")
    for entry in entries:
        timestamp = entry.timestamp.isoformat() if entry.timestamp is not None else "?"
        reason = entry.reason_code if entry.reason_code is not None else "-"
        user = entry.user_id if entry.user_id is not None else "-"
        print(f"  {timestamp}  {entry.action.value:<22} {reason:<5} by {user}")
        for line in entry.additional_information:
            print(f"      {line}")
    if order_id is not None:
        print(f"  verdict: {_verdict(entries)}")


def _verdict(entries: list[AcknowledgementEntry]) -> str:
    """Read the order's outcome off the signature check, the final label and the other codes."""
    parts: list[str] = []
    if any(
        entry.action is AcknowledgementAction.SIGNATURE_VERIFICATION
        and entry.reason_code == SIGNATURES_CORRECT
        for entry in entries
    ):
        parts.append("signatures verified (DS01)")
    labels = {entry.action for entry in entries}
    if AcknowledgementAction.ORDER_FINAL_POSITIVE in labels:
        parts.append("closed with a positive result")
    elif AcknowledgementAction.ORDER_FINAL_NEGATIVE in labels:
        parts.append("closed with a negative result")
    elif AcknowledgementAction.ORDER_FINAL in labels:
        parts.append("closed")
    else:
        parts.append("not closed yet")
    other_codes = sorted(
        {
            entry.reason_code
            for entry in entries
            if entry.reason_code is not None and entry.reason_code not in ROUTINE_CODES
        }
    )
    if other_codes:
        parts.append(f"other reason codes: {', '.join(other_codes)}")
    return "; ".join(parts)


def _describe(btf: BusinessTransactionFormat | None) -> str:
    """Format a BTF as ``service/scope/option/message vNN container=...``; ``-`` for none."""
    if btf is None:
        return "-"
    return (
        f"{btf.service_name}/{btf.scope or '-'}/{btf.service_option or '-'}/{btf.message_name}"
        f" v{btf.message_version or '-'} container={btf.container or '-'}"
    )


def _parse_arguments() -> argparse.Namespace:
    """Parse ``--consume``."""
    parser = argparse.ArgumentParser(description="Read the bank's log of EBICS actions (HAC).")
    parser.add_argument(
        "--consume",
        action="store_true",
        help="mark the log as fetched (ReceiptPolicy.ACKNOWLEDGE) instead of leaving it",
    )
    return parser.parse_args()


if __name__ == "__main__":
    raise SystemExit(main())
