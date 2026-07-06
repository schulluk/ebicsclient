"""Parser for ISO 20022 camt.053 account statements.

A ``EOP/camt.053`` download yields either a single camt.053 XML document or a ZIP
container holding several (one per statement period). :func:`parse` accepts the raw
order-data bytes from :meth:`ebicsclient.client.Client.download` in either form and
returns the statements as normalised :class:`~ebicsclient.models.Statement` models —
account, opening and closing booked balances, and booking entries.

The parsing core is shared with the other camt types in :mod:`ebicsclient.formats.camt`.
"""

from ebicsclient.formats import camt
from ebicsclient.formats.container import extract_documents
from ebicsclient.models import Statement

_MESSAGE = "camt.053"


def parse(order_data: bytes) -> list[Statement]:
    """Parse camt.053 order data into account statements.

    Args:
        order_data: The raw order-data bytes a download returned — a single camt.053 XML
            document or a ZIP container of them.

    Returns:
        Every statement found, in document order (and, for a ZIP, in entry-name order).

    Raises:
        MessageFormatError: the data is not a readable camt.053 document or container.
    """
    return [
        camt.parse_statement(element, namespace)
        for document in extract_documents(order_data)
        for element, namespace in camt.document_items(document, _MESSAGE, "BkToCstmrStmt", "Stmt")
    ]
