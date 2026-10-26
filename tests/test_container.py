"""Tests for ebicsclient.formats.container: order-data splitting and bomb defences.

Download order data arrives as a single XML document or a ZIP of them. The container
layer both splits it and bounds decompression, because the encrypted-then-inflated payload
is not covered by the bank's response signature — a hostile or compromised endpoint could
ship a ZIP bomb, and the client must fail closed rather than exhaust memory.
"""

import contextlib
import io
import random
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


def _with_entry_header_field(
    archive: bytes, local_offset: int, central_offset: int, value: bytes
) -> bytes:
    # Overwrite one field of the (single) entry in both its local and its central header,
    # the way a damaged or unusual archive would carry it.
    patched = bytearray(archive)
    local = patched.find(b"PK\x03\x04")
    central = patched.rfind(b"PK\x01\x02")
    patched[local + local_offset : local + local_offset + len(value)] = value
    patched[central + central_offset : central + central_offset + len(value)] = value
    return bytes(patched)


def test_an_encrypted_entry_raises_message_format_error() -> None:
    # General-purpose flag bit 0 marks the entry encrypted; zipfile then raises RuntimeError.
    archive = _with_entry_header_field(_zip({"a.xml": b"<A/>"}), 6, 8, b"\x01\x00")
    with pytest.raises(MessageFormatError, match="not a readable ZIP"):
        container.extract_documents(archive)


def test_an_unsupported_compression_method_raises_message_format_error() -> None:
    # Method 99 (AES) is not one zipfile can inflate; it raises NotImplementedError.
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_STORED) as stored:
        stored.writestr("a.xml", b"<A/>")
    archive = _with_entry_header_field(buffer.getvalue(), 8, 10, b"\x63\x00")
    with pytest.raises(MessageFormatError, match="not a readable ZIP"):
        container.extract_documents(archive)


@pytest.mark.parametrize(
    "method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2, zipfile.ZIP_LZMA]
)
def test_a_damaged_zip_only_ever_raises_message_format_error(method: int) -> None:
    # Random byte damage reaches zipfile's many exception types (ValueError, EOFError,
    # zlib.error, lzma.LZMAError, …); every one must surface as MessageFormatError.
    buffer = io.BytesIO()
    document = b"<Document>" + b"<Ntry>entry</Ntry>" * 200 + b"</Document>"
    with zipfile.ZipFile(buffer, "w", method) as archive:
        archive.writestr("a.xml", document)
        archive.writestr("b.xml", document)
    original = buffer.getvalue()
    generator = random.Random(method)
    for _ in range(500):
        damaged = bytearray(original)
        for _ in range(generator.randint(1, 6)):
            damaged[generator.randrange(4, len(damaged))] = generator.randrange(256)
        with contextlib.suppress(MessageFormatError):
            container.extract_documents(bytes(damaged))


def test_a_prefix_of_a_single_document_is_returned() -> None:
    assert container.extract_documents(b"<Document/>", prefix_length=4) == [b"<Doc"]


def test_a_prefix_of_each_zip_entry_is_returned() -> None:
    archive = _zip({"b.xml": b"<Bravo/>", "a.xml": b"<Alpha/>"})
    assert container.extract_documents(archive, prefix_length=3) == [b"<Al", b"<Br"]


def test_a_prefix_read_inflates_no_more_than_the_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    # The entry inflates past the (lowered) bomb ceiling, but a prefix read stops long
    # before it, so the entry is never inflated in full.
    monkeypatch.setattr(container, "_MAX_TOTAL_UNCOMPRESSED_BYTES", 1024)
    archive = _zip({"large.xml": b"<Document/>" + b"\x00" * 4096})
    assert container.extract_documents(archive, prefix_length=11) == [b"<Document/>"]


@pytest.mark.parametrize("prefix_length", [0, -1])
def test_a_non_positive_prefix_length_is_rejected(prefix_length: int) -> None:
    with pytest.raises(ValueError, match="prefix_length must be positive"):
        container.extract_documents(b"<Document/>", prefix_length=prefix_length)
