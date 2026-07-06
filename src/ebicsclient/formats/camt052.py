"""Parser for ISO 20022 camt.052 intraday account reports.

A ``STM/camt.052`` download yields either a single camt.052 XML document or a ZIP
container holding several. An intraday report has the same shape as a camt.053
statement — identification, account, optional balances (interim rather than closing
codes), and booking entries — so :func:`parse` returns the same
:class:`~ebicsclient.models.Statement` model; ``opening_balance``/``closing_balance``
are usually ``None`` for intraday reports, with any interim balances in ``balances``.

The parsing core is shared with the other camt types in :mod:`ebicsclient.formats.camt`.
"""

from ebicsclient.formats import camt
from ebicsclient.formats.container import extract_documents
from ebicsclient.models import Statement

_MESSAGE = "camt.052"


def parse(order_data: bytes) -> list[Statement]:
    """Parse camt.052 order data into intraday account reports.

    Args:
        order_data: The raw order-data bytes a download returned — a single camt.052 XML
            document or a ZIP container of them.

    Returns:
        Every report found, in document order (and, for a ZIP, in entry-name order).

    Raises:
        MessageFormatError: the data is not a readable camt.052 document or container.
    """
    return [
        camt.parse_statement(element, namespace)
        for document in extract_documents(order_data)
        for element, namespace in camt.document_items(
            document, _MESSAGE, "BkToCstmrAcctRpt", "Rpt"
        )
    ]
