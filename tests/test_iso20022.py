"""Tests for ebicsclient.formats.iso20022: reading the message a document declares."""

from pathlib import Path

import pytest

from ebicsclient.errors import MessageFormatError
from ebicsclient.formats.iso20022 import MessageIdentifier, message_identifier, root_namespace

_DATA = Path(__file__).parent / "data"


@pytest.mark.parametrize(
    ("fixture", "expected"),
    [
        ("camt052_zkb_sample.xml", "camt.052.001.08"),
        ("camt053_zkb_sample.xml", "camt.053.001.08"),
        ("camt054_credit_zkb_sample.xml", "camt.054.001.08"),
        ("pain002_part.xml", "pain.002.001.10"),
    ],
)
def test_reads_the_message_of_a_genuine_zkb_document(fixture: str, expected: str) -> None:
    identifier = message_identifier(root_namespace((_DATA / fixture).read_bytes()))
    assert identifier is not None
    assert str(identifier) == expected


def test_splits_the_identifier_into_the_btf_parts() -> None:
    assert message_identifier("urn:iso:std:iso:20022:tech:xsd:camt.054.001.04") == (
        MessageIdentifier(message_name="camt.054", variant="001", version="04")
    )


@pytest.mark.parametrize(
    "namespace",
    [
        None,
        "urn:org:ebics:H005",
        "urn:iso:std:iso:20022:tech:xsd:camt.053",  # no variant or version
        "urn:iso:std:iso:20022:tech:xsd:camt.053.001.08.ch.02",  # trailing qualifier
        "http://www.six-interbank-clearing.com/de/camt.053.001.04.xsd",
    ],
)
def test_names_no_message_for_other_namespaces(namespace: str | None) -> None:
    assert message_identifier(namespace) is None


def test_reads_the_root_namespace_without_parsing_the_rest() -> None:
    # Only the root start tag is read, so a document truncated after it still identifies.
    truncated = b'<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.053.001.08"><BkToC'
    assert root_namespace(truncated) == "urn:iso:std:iso:20022:tech:xsd:camt.053.001.08"


def test_a_document_without_a_namespace_has_none() -> None:
    assert root_namespace(b"<Document/>") is None


@pytest.mark.parametrize("document", [b"<x:Document/>", b'<x:Document xmlns="urn:a"/>'])
def test_a_root_with_an_undeclared_prefix_has_no_namespace(document: bytes) -> None:
    # lxml builds such a root with the tag "x:Document", which etree.QName cannot name.
    assert root_namespace(document) is None


@pytest.mark.parametrize("document", [b"", b"not XML", b"<"])
def test_unreadable_xml_raises(document: bytes) -> None:
    with pytest.raises(MessageFormatError):
        root_namespace(document)
