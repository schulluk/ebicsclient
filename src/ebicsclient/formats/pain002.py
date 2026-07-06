"""Parser for ISO 20022 pain.002 customer payment status reports.

A pain.002 is the bank's verdict on a previously submitted pain.001: a group status for
the whole file (``ACTC`` technically valid, ``ACCP`` accepted, ``PART`` partially
accepted, ``RJCT`` rejected), plus — where relevant — per-payment and per-transaction
statuses with ISO reason codes. :func:`parse` accepts the raw order-data bytes from a
status-report download (a single pain.002 XML document or a ZIP container of them, as the
``PSR/pain.002`` BTF delivers) and returns normalised
:class:`~ebicsclient.models.PaymentStatusReport` models.

The element names are read namespace-agnostically: the parser adopts whatever pain.002
namespace the document declares (``...pain.002.001.10``, ``.03``, …) from its root, so a
bank sending a different version is still parsed without a code change. The parsers were
built against genuine ``pain.002.001.10`` reports produced by the ZKB test platform
(``ACTC``, ``ACCP``, ``PART`` with per-transaction rejects, and ``RJCT`` with a
payment-level reason).
"""

from lxml import etree

from ebicsclient.errors import MessageFormatError
from ebicsclient.formats.container import extract_documents
from ebicsclient.models import (
    PaymentStatus,
    PaymentStatusReport,
    StatusReason,
    TransactionStatus,
)

_DOCUMENT = "Document"


def parse(order_data: bytes) -> list[PaymentStatusReport]:
    """Parse pain.002 order data into payment status reports.

    Args:
        order_data: The raw order-data bytes a download returned — a single pain.002 XML
            document or a ZIP container of them.

    Returns:
        Every status report found, in document order (and, for a ZIP, in entry-name order).

    Raises:
        MessageFormatError: the data is not a readable pain.002 document or container.
    """
    reports: list[PaymentStatusReport] = []
    for document in extract_documents(order_data):
        reports.append(_parse_document(document))
    return reports


def _parse_document(document: bytes) -> PaymentStatusReport:
    root = _parse_xml(document)
    local_name = etree.QName(root).localname
    if local_name != _DOCUMENT:
        raise MessageFormatError(f"Expected a pain.002 <Document>, got <{local_name}>")
    namespace = etree.QName(root).namespace
    if namespace is None:
        raise MessageFormatError("pain.002 <Document> declares no namespace")
    report = _child(root, namespace, "CstmrPmtStsRpt")
    group_header = _child(report, namespace, "GrpHdr")
    original_group = _child(report, namespace, "OrgnlGrpInfAndSts")
    return PaymentStatusReport(
        identification=_text(_child(group_header, namespace, "MsgId")),
        original_message_id=_text(_child(original_group, namespace, "OrgnlMsgId")),
        original_message_name=_optional_text(original_group, namespace, "OrgnlMsgNmId"),
        group_status=_optional_text(original_group, namespace, "GrpSts"),
        reasons=_reasons(original_group, namespace),
        payments=tuple(
            _parse_payment(payment, namespace)
            for payment in _children(report, namespace, "OrgnlPmtInfAndSts")
        ),
    )


def _parse_payment(payment: etree._Element, namespace: str) -> PaymentStatus:
    return PaymentStatus(
        original_payment_information_id=_text(_child(payment, namespace, "OrgnlPmtInfId")),
        status=_optional_text(payment, namespace, "PmtInfSts"),
        reasons=_reasons(payment, namespace),
        transactions=tuple(
            _parse_transaction(transaction, namespace)
            for transaction in _children(payment, namespace, "TxInfAndSts")
        ),
    )


def _parse_transaction(transaction: etree._Element, namespace: str) -> TransactionStatus:
    return TransactionStatus(
        status=_optional_text(transaction, namespace, "TxSts"),
        original_instruction_id=_optional_text(transaction, namespace, "OrgnlInstrId"),
        original_end_to_end_id=_optional_text(transaction, namespace, "OrgnlEndToEndId"),
        reasons=_reasons(transaction, namespace),
    )


def _reasons(parent: etree._Element, namespace: str) -> tuple[StatusReason, ...]:
    # StsRsnInf holds an optional <Rsn><Cd>…</Cd></Rsn> (or a proprietary code) and
    # zero or more free-text <AddtlInf> lines, which are joined.
    reasons = []
    for info in _children(parent, namespace, "StsRsnInf"):
        reason = info.find(f"{{{namespace}}}Rsn")
        code = None
        if reason is not None:
            code = reason.findtext(f"{{{namespace}}}Cd") or reason.findtext(
                f"{{{namespace}}}Prtry"
            )
        additional = [
            element.text.strip()
            for element in _children(info, namespace, "AddtlInf")
            if element.text is not None
        ]
        reasons.append(
            StatusReason(
                code=code.strip() if code is not None else None,
                additional_information=" ".join(additional) if additional else None,
            )
        )
    return tuple(reasons)


def _child(parent: etree._Element, namespace: str, local_name: str) -> etree._Element:
    child = parent.find(f"{{{namespace}}}{local_name}")
    if child is None:
        raise MessageFormatError(f"A pain.002 element is missing <{local_name}>")
    return child


def _children(parent: etree._Element, namespace: str, local_name: str) -> list[etree._Element]:
    return parent.findall(f"{{{namespace}}}{local_name}")


def _optional_text(parent: etree._Element, namespace: str, local_name: str) -> str | None:
    text = parent.findtext(f"{{{namespace}}}{local_name}")
    return text.strip() if text is not None else None


def _text(element: etree._Element) -> str:
    text = element.text
    if text is None:
        raise MessageFormatError(f"A pain.002 <{etree.QName(element).localname}> is empty")
    return text.strip()


def _parse_xml(data: bytes) -> etree._Element:
    # Hardened parser: no entity expansion, no network access (see docs/06).
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    try:
        return etree.fromstring(data, parser=parser)
    except etree.XMLSyntaxError as error:
        raise MessageFormatError(f"Malformed pain.002 XML: {error}") from error
