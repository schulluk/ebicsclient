"""Parser for ISO 20022 camt.054 debit/credit notifications (booking advices).

A ``REP/camt.054`` download yields either a single camt.054 XML document or a ZIP
container holding several — Swiss banks deliver one notification per booking advice
(credits, debits, and the QRR/SCOR/LSV collective resolutions as separate documents).
:func:`parse` returns them as :class:`~ebicsclient.models.Notification` models —
identification, account, and booking entries; notifications carry no balances.

The parsing core is shared with the other camt types in :mod:`ebicsclient.formats.camt`.
"""

from ebicsclient.formats import camt
from ebicsclient.formats.container import extract_documents
from ebicsclient.models import Notification

_MESSAGE = "camt.054"


def parse(order_data: bytes) -> list[Notification]:
    """Parse camt.054 order data into debit/credit notifications.

    Args:
        order_data: The raw order-data bytes a download returned — a single camt.054 XML
            document or a ZIP container of them.

    Returns:
        Every notification found, in document order (and, for a ZIP, in entry-name order).

    Raises:
        MessageFormatError: the data is not a readable camt.054 document or container.
    """
    return [
        Notification(
            identification=camt.identification(element, namespace),
            iban=camt.iban(element, namespace),
            entries=camt.parse_entries(element, namespace),
        )
        for document in extract_documents(order_data)
        for element, namespace in camt.document_items(
            document, _MESSAGE, "BkToCstmrDbtCdtNtfctn", "Ntfctn"
        )
    ]
