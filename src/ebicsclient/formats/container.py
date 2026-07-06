"""Container handling shared by the message-format parsers.

EBICS download order data arrives either as a single XML document or as a ZIP container
holding several (one per message). Every format parser accepts both, so the splitting
logic lives here once.
"""

import io
import zipfile

from ebicsclient.errors import MessageFormatError

_ZIP_MAGIC = b"PK\x03\x04"


def extract_documents(order_data: bytes) -> list[bytes]:
    """Split raw order data into its individual XML documents.

    Args:
        order_data: The raw order-data bytes a download returned — a single XML document
            or a ZIP container of them.

    Returns:
        The contained documents; for a ZIP, in entry-name order (stable and reproducible),
        otherwise the input as a single-element list.

    Raises:
        MessageFormatError: the data looks like a ZIP but cannot be read.
    """
    if not order_data.startswith(_ZIP_MAGIC):
        return [order_data]
    try:
        with zipfile.ZipFile(io.BytesIO(order_data)) as archive:
            return [archive.read(name) for name in sorted(archive.namelist())]
    except (zipfile.BadZipFile, OSError) as error:
        raise MessageFormatError("Order data is not a readable ZIP container") from error
