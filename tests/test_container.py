"""Tests for ebicsclient.formats.container: order-data splitting and bomb defences.

Download order data arrives as a single XML document or a ZIP of them. The container
layer both splits it and bounds decompression, because the encrypted-then-inflated payload
is not covered by the bank's response signature — a hostile or compromised endpoint could
ship a ZIP bomb, and the client must fail closed rather than exhaust memory.
"""

import io
import zipfile

import pytest

from ebicsclient.errors import MessageFormatError
from ebicsclient.formats import container


def _zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def test_a_single_document_is_returned_as_is() -> None:
    document = b"<Document>not a zip</Document>"
    assert container.extract_documents(document) == [document]


def test_zip_entries_are_returned_in_entry_name_order() -> None:
    archive = _zip({"b.xml": b"<B/>", "a.xml": b"<A/>"})
    assert container.extract_documents(archive) == [b"<A/>", b"<B/>"]


def test_an_unreadable_zip_raises_message_format_error() -> None:
    # Starts with the ZIP magic but is truncated garbage.
    with pytest.raises(MessageFormatError, match="not a readable ZIP"):
        container.extract_documents(b"PK\x03\x04broken")


def test_a_zip_entry_over_the_limit_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    # A small archive whose single entry inflates past the cap must be rejected. Lower the
    # ceiling so the test stays fast and does not allocate hundreds of megabytes.
    monkeypatch.setattr(container, "_MAX_TOTAL_UNCOMPRESSED_BYTES", 1024)
    archive = _zip({"bomb.xml": b"\x00" * 4096})  # highly compressible, well over 1 KiB inflated
    with pytest.raises(MessageFormatError, match="decompression bomb"):
        container.extract_documents(archive)


def test_a_zip_with_too_many_entries_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(container, "_MAX_ENTRIES", 3)
    archive = _zip({f"{index}.xml": b"<X/>" for index in range(4)})
    with pytest.raises(MessageFormatError, match="over the 3 limit"):
        container.extract_documents(archive)


def test_a_zip_entry_at_the_limit_is_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(container, "_MAX_TOTAL_UNCOMPRESSED_BYTES", 4096)
    payload = b"A" * 4096
    archive = _zip({"ok.xml": payload})
    assert container.extract_documents(archive) == [payload]
