"""Parser for the EBICS customer acknowledgement (HAC).

HAC is the bank's log of a customer's EBICS actions, delivered as an ISO 20022 pain.002
document filled by the rules of EBICS 3.0 spec chapter 10 (the spec uses the 2009 edition,
``pain.002.001.03``). Its fields mean something else than in a payment status report:

- ``OrgnlGrpInfAndSts`` carries the constant ``EBICS`` (spec 10.2.2), which tells a HAC
  apart from a status report on a payment file.
- Each ``OrgnlPmtInfAndSts`` is one protocol step: ``OrgnlPmtInfId`` names the type of
  action (spec 10.2.3.1), and its single ``StsRsnInf`` holds the identifiers of the order
  in ``Orgtr/Id/OrgId/Othr`` (each named by ``SchmeNm/Prtry``), the result as an ISO reason
  code in ``Rsn/Cd``, and free text in ``AddtlInf`` (spec 10.2.3.2, 10.2.3.3).

:func:`parse` reads the namespace from the document, so a later pain.002 version parses as
long as it keeps these elements. The structure the models need is checked and fails closed;
which reason codes may follow which action (spec 10.4) is the bank's rule and is not
checked. Built against the HAC the ZKB test platform delivered on 2026-10-27, which
validates against the ``pain.002.001.03`` schema.
"""

import datetime

from lxml import etree

from ebicsclient.errors import MessageFormatError
from ebicsclient.formats import iso20022
from ebicsclient.formats.container import extract_documents
from ebicsclient.models import (
    AcknowledgementAction,
    AcknowledgementEntry,
    BusinessTransactionFormat,
    CustomerAcknowledgement,
)

_DOCUMENT = "Document"
_MESSAGE_NAME = "pain.002"
# OrgnlMsgId and OrgnlMsgNmId of every HAC (spec 10.2.2).
_ORIGINAL_MESSAGE = "EBICS"

# The scheme names of the identifiers spec 10.2.3.2 lists (and the BTF version ZKB adds as
# MsgNameVersion); any other name is kept in other_identifiers.
_PARTNER_ID = "PartnerID"
_USER_ID = "UserID"
_SYSTEM_ID = "SystemID"
_ORDER_ID = "OrderID"
_ADMIN_ORDER_TYPE = "AdminOrderType"
_ORDER_ID_REFERENCE = "OrderIDRef"
_ADMIN_ORDER_TYPE_REFERENCE = "AdminOrderTypeRef"
_PARTNER_ID_REFERENCE = "PartnerIDRef"
_TIMESTAMP = "TimeStamp"
_DATA_DIGEST = "DataDigest"
_SERVICE_NAME = "ServiceName"
_SCOPE = "Scope"
_SERVICE_OPTION = "ServiceOption"
_CONTAINER_TYPE = "ContainerType"
_MESSAGE_NAME_SCHEME = "MsgName"
_MESSAGE_VERSION = "MsgNameVersion"
_REFERENCE_SUFFIX = "Ref"
_SERVICE_SCHEMES = (_SERVICE_NAME, _SCOPE, _SERVICE_OPTION, _CONTAINER_TYPE, _MESSAGE_NAME_SCHEME)
_KNOWN_SCHEMES = frozenset(
    {
        _PARTNER_ID,
        _USER_ID,
        _SYSTEM_ID,
        _ORDER_ID,
        _ADMIN_ORDER_TYPE,
        _ORDER_ID_REFERENCE,
        _ADMIN_ORDER_TYPE_REFERENCE,
        _PARTNER_ID_REFERENCE,
        _TIMESTAMP,
        _DATA_DIGEST,
        _MESSAGE_VERSION,
        *_SERVICE_SCHEMES,
        *(scheme + _REFERENCE_SUFFIX for scheme in _SERVICE_SCHEMES),
    }
)


def parse(order_data: bytes) -> CustomerAcknowledgement:
    """Parse HAC order data into a customer acknowledgement.

    Args:
        order_data: The raw order-data bytes a HAC download returned: one pain.002 document,
            or a ZIP container holding exactly one.

    Returns:
        The customer acknowledgement.

    Raises:
        MessageFormatError: the data is not exactly one readable pain.002 document filled
            as a HAC (spec 10.2), or an entry names an unknown type of action, a reason
            other than an ISO code, an identifier without a scheme name, one identifier
            twice, an incomplete BTF, or an unreadable timestamp.
    """
    documents = extract_documents(order_data)
    if len(documents) != 1:
        raise MessageFormatError(
            f"A customer acknowledgement is one pain.002 document, got {len(documents)}"
        )
    return _parse_document(documents[0])


def _parse_document(document: bytes) -> CustomerAcknowledgement:
    root = _parse_xml(document)
    local_name = etree.QName(root).localname
    if local_name != _DOCUMENT:
        raise MessageFormatError(f"Expected a pain.002 <Document>, got <{local_name}>")
    namespace = etree.QName(root).namespace
    message = iso20022.message_identifier(namespace)
    if namespace is None or message is None or message.message_name != _MESSAGE_NAME:
        raise MessageFormatError(
            f"A customer acknowledgement is a pain.002 document, got namespace {namespace!r}"
        )
    report = _child(root, namespace, "CstmrPmtStsRpt")
    group_header = _child(report, namespace, "GrpHdr")
    original_group = _child(report, namespace, "OrgnlGrpInfAndSts")
    for element in ("OrgnlMsgId", "OrgnlMsgNmId"):
        value = _text(_child(original_group, namespace, element))
        if value != _ORIGINAL_MESSAGE:
            raise MessageFormatError(
                f"Not a customer acknowledgement: <{element}> is {value!r}, a HAC carries "
                f"{_ORIGINAL_MESSAGE!r} (spec 10.2.2)"
            )
    statuses = report.findall(f"{{{namespace}}}OrgnlPmtInfAndSts")
    if not statuses:
        raise MessageFormatError(
            "A customer acknowledgement holds at least one <OrgnlPmtInfAndSts> (spec 10.2.3)"
        )
    return CustomerAcknowledgement(
        identification=_text(_child(group_header, namespace, "MsgId")),
        created_at=_timestamp(_text(_child(group_header, namespace, "CreDtTm")), "CreDtTm"),
        # Optional in ISO, mandatory in a HAC (spec 10.2.1).
        host_id=_text(
            _descendant(group_header, namespace, "InitgPty", "Id", "OrgId", "Othr", "Id")
        ),
        entries=tuple(_parse_entry(status, namespace) for status in statuses),
    )


def _parse_entry(status: etree._Element, namespace: str) -> AcknowledgementEntry:
    action_code = _text(_child(status, namespace, "OrgnlPmtInfId"))
    try:
        action = AcknowledgementAction(action_code)
    except ValueError as error:
        raise MessageFormatError(
            f"Unknown type of action {action_code!r} in a customer acknowledgement "
            "(spec 10.2.3.1)"
        ) from error
    reason_information = status.findall(f"{{{namespace}}}StsRsnInf")
    if len(reason_information) != 1:
        raise MessageFormatError(
            f"A customer-acknowledgement entry holds exactly one <StsRsnInf> (spec 10.2.3), "
            f"got {len(reason_information)}"
        )
    information = reason_information[0]
    identifiers, other_identifiers = _identifiers(information, namespace)
    timestamp = identifiers.get(_TIMESTAMP)
    return AcknowledgementEntry(
        action=action,
        reason_code=_reason_code(information, namespace),
        timestamp=_timestamp(timestamp, _TIMESTAMP) if timestamp is not None else None,
        customer_name=_optional_text(information, namespace, "Orgtr", "Nm"),
        partner_id=identifiers.get(_PARTNER_ID),
        user_id=identifiers.get(_USER_ID),
        system_id=identifiers.get(_SYSTEM_ID),
        order_id=identifiers.get(_ORDER_ID),
        admin_order_type=identifiers.get(_ADMIN_ORDER_TYPE),
        service=_service(identifiers, "", identifiers.get(_MESSAGE_VERSION)),
        referenced_order_id=identifiers.get(_ORDER_ID_REFERENCE),
        referenced_admin_order_type=identifiers.get(_ADMIN_ORDER_TYPE_REFERENCE),
        referenced_service=_service(identifiers, _REFERENCE_SUFFIX, None),
        referenced_partner_id=identifiers.get(_PARTNER_ID_REFERENCE),
        data_digest=identifiers.get(_DATA_DIGEST),
        additional_information=tuple(
            element.text or "" for element in information.findall(f"{{{namespace}}}AddtlInf")
        ),
        other_identifiers=other_identifiers,
    )


def _identifiers(
    information: etree._Element, namespace: str
) -> tuple[dict[str, str], tuple[tuple[str, str], ...]]:
    known: dict[str, str] = {}
    other: list[tuple[str, str]] = []
    path = f"{{{namespace}}}Orgtr/{{{namespace}}}Id/{{{namespace}}}OrgId/{{{namespace}}}Othr"
    for identifier in information.iterfind(path):
        value = _text(_child(identifier, namespace, "Id"))
        scheme = identifier.findtext(f"{{{namespace}}}SchmeNm/{{{namespace}}}Prtry")
        if scheme is None or not scheme.strip():
            raise MessageFormatError(
                f"A customer-acknowledgement identifier {value!r} has no <SchmeNm><Prtry> "
                "to say what it is (spec 10.2.3.2)"
            )
        scheme = scheme.strip()
        if scheme not in _KNOWN_SCHEMES:
            other.append((scheme, value))
        elif scheme in known:
            raise MessageFormatError(f"A customer-acknowledgement entry names {scheme} twice")
        else:
            known[scheme] = value
    return known, tuple(other)


def _service(
    identifiers: dict[str, str], suffix: str, message_version: str | None
) -> BusinessTransactionFormat | None:
    values = {scheme: identifiers.get(scheme + suffix) for scheme in _SERVICE_SCHEMES}
    if all(value is None for value in values.values()) and message_version is None:
        return None
    service_name = values[_SERVICE_NAME]
    message_name = values[_MESSAGE_NAME_SCHEME]
    if service_name is None or message_name is None:
        raise MessageFormatError(
            f"A customer-acknowledgement entry names a BTF without {_SERVICE_NAME}{suffix} "
            f"or {_MESSAGE_NAME_SCHEME}{suffix}"
        )
    try:
        return BusinessTransactionFormat(
            service_name=service_name,
            message_name=message_name,
            scope=values[_SCOPE],
            message_version=message_version,
            container=values[_CONTAINER_TYPE],
            service_option=values[_SERVICE_OPTION],
        )
    except (TypeError, ValueError) as error:
        raise MessageFormatError(
            f"A customer-acknowledgement entry names an invalid BTF: {error}"
        ) from error


def _reason_code(information: etree._Element, namespace: str) -> str | None:
    reason = information.find(f"{{{namespace}}}Rsn")
    if reason is None:
        return None
    code = reason.findtext(f"{{{namespace}}}Cd")
    if code is None or not code.strip():
        raise MessageFormatError(
            "A customer-acknowledgement result is not an ISO reason code in <Rsn><Cd> "
            "(spec 10.2.3.2)"
        )
    return code.strip()


def _timestamp(value: str, local_name: str) -> datetime.datetime:
    try:
        return datetime.datetime.fromisoformat(value)
    except ValueError as error:
        raise MessageFormatError(
            f"A customer-acknowledgement {local_name} is not an ISO 8601 timestamp: {value!r}"
        ) from error


def _child(parent: etree._Element, namespace: str, local_name: str) -> etree._Element:
    child = parent.find(f"{{{namespace}}}{local_name}")
    if child is None:
        raise MessageFormatError(f"A customer-acknowledgement element is missing <{local_name}>")
    return child


def _descendant(parent: etree._Element, namespace: str, *path: str) -> etree._Element:
    element = parent
    for local_name in path:
        element = _child(element, namespace, local_name)
    return element


def _optional_text(parent: etree._Element, namespace: str, *path: str) -> str | None:
    text = parent.findtext("/".join(f"{{{namespace}}}{name}" for name in path))
    return text.strip() if text is not None else None


def _text(element: etree._Element) -> str:
    text = element.text.strip() if element.text is not None else ""
    if not text:
        raise MessageFormatError(
            f"A customer-acknowledgement <{etree.QName(element).localname}> is empty"
        )
    return text


def _parse_xml(data: bytes) -> etree._Element:
    # Hardened parser: no entity expansion, no network access (see docs/06).
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    try:
        return etree.fromstring(data, parser=parser)
    except etree.XMLSyntaxError as error:
        raise MessageFormatError(f"Malformed customer-acknowledgement XML: {error}") from error
