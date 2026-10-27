"""HEV: ask a bank which EBICS versions it supports (``ebics_hev.xsd``).

HEV is the one EBICS exchange that belongs to no protocol version. A client sends it before
it knows which version a bank speaks, so its schema has a namespace of its own
(``http://www.ebics.org/H000``) and every version shares it. The request names only the
host: it carries no subscriber, no signature and no keys, so it works before INI and HIA.
The bank's answer is not signed either; TLS is its only protection.
"""

import re
from typing import cast

from lxml import etree

from ebicsclient.errors import ProtocolError
from ebicsclient.models import Bank, EbicsVersion
from ebicsclient.protocol import h005

NAMESPACE = "http://www.ebics.org/H000"
_NSMAP = cast("dict[str, str]", {None: NAMESPACE})
_OK_RETURN_CODE = "000000"
# ebics_hev.xsd: ProtocolVersionType is "H" and three digits, VersionNumberType two digits,
# a dot and two digits. Both are xs:token, so surrounding whitespace is not part of the value.
_PROTOCOL_VERSION = re.compile(r"H[0-9]{3}")
_RELEASE = re.compile(r"[0-9]{2}\.[0-9]{2}")


def build_request(bank: Bank) -> bytes:
    """Build the ``ebicsHEVRequest`` for one bank host.

    Args:
        bank: The bank whose host is asked; only its Host ID goes into the request.

    Returns:
        The serialised request (``HEVRequestDataType``: a single ``HostID``).
    """
    root = etree.Element(etree.QName(NAMESPACE, "ebicsHEVRequest"), nsmap=_NSMAP)
    host_id = etree.SubElement(root, etree.QName(NAMESPACE, "HostID"))
    host_id.text = bank.host_id
    data: bytes = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
    return data


def parse_response(response: bytes) -> list[EbicsVersion]:
    """Read the supported versions from an ``ebicsHEVResponse``.

    Args:
        response: The raw response bytes from the bank.

    Returns:
        The versions the bank reports, in document order. Empty if it reports none, which
        the schema allows (``VersionNumber`` occurs zero or more times).

    Raises:
        ProtocolError: the response is not a readable HEV response, carries no or an empty
            return code, or reports a version that breaks the schema's format.
        ReturnCodeError: the bank reported a non-OK return code; a code outside the
            client's verified table raises its subclass ``UnknownReturnCodeError``.
    """
    root = _parse(response)
    if root.tag != etree.QName(NAMESPACE, "ebicsHEVResponse").text:
        raise ProtocolError(f"Expected an HEV response <ebicsHEVResponse>, got <{root.tag}>")
    system_return_code = _child(root, "SystemReturnCode")
    code = _token(_child(system_return_code, "ReturnCode"))
    if not code:
        raise ProtocolError("HEV response carries an empty ReturnCode")
    if code != _OK_RETURN_CODE:
        report = system_return_code.find(f"{{{NAMESPACE}}}ReportText")
        raise h005.return_code_error(code, report.text if report is not None else None)
    return [_version(element) for element in root.findall(f"{{{NAMESPACE}}}VersionNumber")]


def _version(element: etree._Element) -> EbicsVersion:
    protocol_version = (element.get("ProtocolVersion") or "").strip()
    release = _token(element)
    if not _PROTOCOL_VERSION.fullmatch(protocol_version):
        raise ProtocolError(f"HEV response has an invalid ProtocolVersion: {protocol_version!r}")
    if not _RELEASE.fullmatch(release):
        raise ProtocolError(f"HEV response has an invalid VersionNumber: {release!r}")
    return EbicsVersion(protocol_version=protocol_version, release=release)


def _child(parent: etree._Element, local_name: str) -> etree._Element:
    child = parent.find(f"{{{NAMESPACE}}}{local_name}")
    if child is None:
        raise ProtocolError(f"HEV response is missing <{local_name}>")
    return child


def _token(element: etree._Element) -> str:
    return element.text.strip() if element.text is not None else ""


def _parse(data: bytes) -> etree._Element:
    # Hardened parser: no entity expansion, no network, no huge trees (see docs/06).
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    try:
        return etree.fromstring(data, parser=parser)
    except etree.XMLSyntaxError as error:
        raise ProtocolError(f"Malformed HEV response: {error}") from error
