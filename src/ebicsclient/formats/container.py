"""Container handling shared by the message-format parsers.

EBICS download order data arrives either as a single XML document or as a ZIP container
holding several (one per message). Every format parser accepts both, so the splitting
logic lives here once.
"""

import io
import zipfile

from ebicsclient.errors import MessageFormatError

_ZIP_MAGIC = b"PK\x03\x04"

# Bounds on a downloaded ZIP container. The bank's response AuthSignature covers the
# transaction envelope, not this encrypted-then-inflated payload, so a hostile or
# compromised endpoint could ship a "ZIP bomb" — a tiny archive that expands to gigabytes,
# or one with an absurd number of entries — to exhaust the client's memory. These caps are
# far above any real EBICS delivery (many daily statements per file) while bounding the
# blast radius; raise them only with a concrete need.
_MAX_TOTAL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
_MAX_ENTRIES = 10_000


def extract_documents(order_data: bytes, *, prefix_length: int | None = None) -> list[bytes]:
    """Split raw order data into its individual XML documents.

    Args:
        order_data: The raw order-data bytes a download returned — a single XML document
            or a ZIP container of them.
        prefix_length: If given, return only the first ``prefix_length`` bytes of each
            document, so a caller that needs just the root element does not inflate whole
            ZIP entries.

    Returns:
        The contained documents (or their prefixes); for a ZIP, in entry-name order (stable
        and reproducible), otherwise the input as a single-element list.

    Raises:
        ValueError: ``prefix_length`` is not positive.
        MessageFormatError: the data looks like a ZIP but cannot be read (damaged,
            encrypted, or compressed with a method this Python cannot inflate), holds more
            than ``_MAX_ENTRIES`` entries, or inflates past ``_MAX_TOTAL_UNCOMPRESSED_BYTES``
            (a possible decompression bomb).
    """
    if prefix_length is not None and prefix_length < 1:
        raise ValueError(f"prefix_length must be positive, got {prefix_length}")
    if not order_data.startswith(_ZIP_MAGIC):
        return [order_data if prefix_length is None else order_data[:prefix_length]]
    try:
        with zipfile.ZipFile(io.BytesIO(order_data)) as archive:
            names = sorted(archive.namelist())
            if len(names) > _MAX_ENTRIES:
                raise MessageFormatError(
                    f"ZIP container holds {len(names)} entries, over the {_MAX_ENTRIES} "
                    f"limit — refusing a possible decompression bomb"
                )
            return [_read_entry(archive, name, prefix_length) for name in names]
    except (MessageFormatError, MemoryError):
        raise
    except Exception as error:
        # zipfile reports a damaged or unusual archive through many exception types, and
        # the set grows with every decompressor it gains: BadZipFile, ValueError (a negative
        # seek), EOFError, RuntimeError (an encrypted entry), NotImplementedError (an
        # unsupported method or version), zlib.error, lzma.LZMAError, ZstdError. The bank's
        # signature does not cover this payload, so each one is a malformed delivery.
        raise MessageFormatError("Order data is not a readable ZIP container") from error


def _read_entry(archive: zipfile.ZipFile, name: str, prefix_length: int | None) -> bytes:
    # Decompress lazily and stop one byte past the ceiling, so a member whose header lies
    # about its size still cannot inflate without bound. The cap is applied per entry; a
    # container of many just-under-cap members is still bounded by _MAX_ENTRIES.
    with archive.open(name) as entry:
        if prefix_length is not None:
            return entry.read(prefix_length)
        data = entry.read(_MAX_TOTAL_UNCOMPRESSED_BYTES + 1)
    if len(data) > _MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise MessageFormatError(
            f"ZIP entry {name!r} inflates past the {_MAX_TOTAL_UNCOMPRESSED_BYTES}-byte "
            f"safety limit — refusing a possible decompression bomb"
        )
    return data
