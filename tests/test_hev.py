"""Tests for ebicsclient.protocol.hev: the HEV request and the bank's version list.

``hev_zkb_sample.xml`` is the genuine answer of the ZKB test platform (2026-10-26). It names
the same protocol versions as the bank's signed HPD answer (H002 to H005), and it validates
against ``ebics_hev.xsd``. The hand-written responses cover the other shapes the schema
allows and the failures the parser must not let through.
"""

from pathlib import Path

import pytest
from lxml import etree

from ebicsclient.errors import ProtocolError, ReturnCodeError, UnknownReturnCodeError
from ebicsclient.models import Bank, EbicsVersion
from ebicsclient.protocol import hev

_DATA = Path(__file__).parent / "data"
_NS = hev.NAMESPACE


def _response(body: str) -> bytes:
    return f'<ebicsHEVResponse xmlns="{_NS}">{body}</ebicsHEVResponse>'.encode()


_OK = (
    "<SystemReturnCode><ReturnCode>000000</ReturnCode><ReportText>OK</ReportText>"
    "</SystemReturnCode>"
)


def test_request_names_only_the_host() -> None:
    request = etree.fromstring(hev.build_request(Bank(host_id="HOST1", url="https://x.example")))
    assert request.tag == f"{{{_NS}}}ebicsHEVRequest"
    assert [child.tag for child in request] == [f"{{{_NS}}}HostID"]
    assert request.findtext(f"{{{_NS}}}HostID") == "HOST1"


def test_zkb_answer_lists_its_versions_in_order() -> None:
    assert hev.parse_response((_DATA / "hev_zkb_sample.xml").read_bytes()) == [
        EbicsVersion("H002", "02.30"),
        EbicsVersion("H003", "02.40"),
        EbicsVersion("H004", "02.50"),
        EbicsVersion("H005", "03.00"),
    ]


def test_answer_without_versions_is_an_empty_list() -> None:
    assert hev.parse_response(_response(_OK)) == []


def test_extension_elements_of_other_namespaces_are_ignored() -> None:
    # HEVResponseDataType ends with xs:any namespace="##other".
    response = _response(
        _OK + '<VersionNumber ProtocolVersion="H005">03.00</VersionNumber>'
        '<x:Note xmlns:x="urn:example:extension">ignored</x:Note>'
    )
    assert hev.parse_response(response) == [EbicsVersion("H005", "03.00")]


def test_token_whitespace_is_not_part_of_the_value() -> None:
    response = _response(_OK + '<VersionNumber ProtocolVersion=" H005 "> 03.00 </VersionNumber>')
    assert hev.parse_response(response) == [EbicsVersion("H005", "03.00")]


def test_known_error_code_raises_with_the_bank_text() -> None:
    response = _response(
        "<SystemReturnCode><ReturnCode>061099</ReturnCode>"
        "<ReportText>[EBICS_INTERNAL_ERROR] failed</ReportText></SystemReturnCode>"
    )
    with pytest.raises(ReturnCodeError) as caught:
        hev.parse_response(response)
    assert type(caught.value) is ReturnCodeError
    assert (caught.value.code, caught.value.text) == ("061099", "[EBICS_INTERNAL_ERROR] failed")


def test_unverified_error_code_raises_unknown_return_code_error() -> None:
    response = _response(
        "<SystemReturnCode><ReturnCode>099999</ReturnCode><ReportText>?</ReportText>"
        "</SystemReturnCode>"
    )
    with pytest.raises(UnknownReturnCodeError):
        hev.parse_response(response)


def test_versions_are_not_read_from_a_failed_answer() -> None:
    response = _response(
        "<SystemReturnCode><ReturnCode>061099</ReturnCode><ReportText>x</ReportText>"
        '</SystemReturnCode><VersionNumber ProtocolVersion="H005">03.00</VersionNumber>'
    )
    with pytest.raises(ReturnCodeError):
        hev.parse_response(response)


@pytest.mark.parametrize(
    "response",
    [
        b"<ebicsHEVResponse",
        # An H005 response is not an HEV answer, whatever it carries.
        b'<ebicsResponse xmlns="urn:org:ebics:H005"><ReturnCode>000000</ReturnCode>'
        b"</ebicsResponse>",
        b"<ebicsHEVResponse><SystemReturnCode><ReturnCode>000000</ReturnCode></SystemReturnCode>"
        b"</ebicsHEVResponse>",
        _response('<VersionNumber ProtocolVersion="H005">03.00</VersionNumber>'),
        _response("<SystemReturnCode><ReturnCode/><ReportText>x</ReportText></SystemReturnCode>"),
        _response(_OK + '<VersionNumber ProtocolVersion="H05">03.00</VersionNumber>'),
        _response(_OK + '<VersionNumber ProtocolVersion="h005">03.00</VersionNumber>'),
        _response(_OK + "<VersionNumber>03.00</VersionNumber>"),
        _response(_OK + '<VersionNumber ProtocolVersion="H005">3.0</VersionNumber>'),
        _response(_OK + '<VersionNumber ProtocolVersion="H005"></VersionNumber>'),
    ],
    ids=[
        "malformed",
        "h005-response",
        "no-namespace",
        "no-return-code",
        "empty-return-code",
        "short-protocol",
        "lowercase-protocol",
        "no-protocol",
        "short-release",
        "empty-release",
    ],
)
def test_unreadable_answers_fail_closed(response: bytes) -> None:
    with pytest.raises(ProtocolError):
        hev.parse_response(response)
