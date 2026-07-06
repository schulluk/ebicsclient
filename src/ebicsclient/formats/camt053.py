"""Parser for ISO 20022 camt.053 account statements.

A ``EOP/camt.053`` download yields either a single camt.053 XML document or a ZIP
container holding several (one per statement period). :func:`parse` accepts the raw
order-data bytes from :meth:`ebicsclient.client.Client.download` in either form and
returns the statements as normalised :class:`~ebicsclient.models.Statement` models —
account, opening and closing booked balances, and booking entries.

The element names are read namespace-agnostically: the parser adopts whatever camt.053
namespace the document declares (``...camt.053.001.08``, ``.02``, …) from its root, so a
bank sending a different minor version is still parsed without a code change.
"""

import datetime
from decimal import Decimal, InvalidOperation

from lxml import etree

from ebicsclient.errors import MessageFormatError
from ebicsclient.formats.container import extract_documents
from ebicsclient.models import Balance, CreditDebit, Entry, Statement

_DOCUMENT = "Document"
# Closing/opening booked balances are selected by their ISO external balance-type code.
_CLOSING_BOOKED = "CLBD"
_OPENING_BOOKED = "OPBD"


def parse(order_data: bytes) -> list[Statement]:
    """Parse camt.053 order data into account statements.

    Args:
        order_data: The raw order-data bytes a download returned — a single camt.053 XML
            document or a ZIP container of them.

    Returns:
        Every statement found, in document order (and, for a ZIP, in entry-name order).

    Raises:
        MessageFormatError: the data is not a readable camt.053 document or container.
    """
    statements: list[Statement] = []
    for document in extract_documents(order_data):
        statements.extend(_parse_document(document))
    return statements


def _parse_document(document: bytes) -> list[Statement]:
    root = _parse_xml(document)
    local_name = etree.QName(root).localname
    if local_name != _DOCUMENT:
        raise MessageFormatError(f"Expected a camt.053 <Document>, got <{local_name}>")
    namespace = etree.QName(root).namespace
    if namespace is None:
        raise MessageFormatError("camt.053 <Document> declares no namespace")
    report = _child(root, namespace, "BkToCstmrStmt")
    return [_parse_statement(stmt, namespace) for stmt in _children(report, namespace, "Stmt")]


def _parse_statement(statement: etree._Element, namespace: str) -> Statement:
    balances = tuple(
        _parse_balance(balance, namespace) for balance in _children(statement, namespace, "Bal")
    )
    entries = tuple(
        _parse_entry(entry, namespace) for entry in _children(statement, namespace, "Ntry")
    )
    return Statement(
        identification=_text(_child(statement, namespace, "Id")),
        iban=_iban(statement, namespace),
        opening_balance=_balance_with_code(balances, _OPENING_BOOKED),
        closing_balance=_balance_with_code(balances, _CLOSING_BOOKED),
        balances=balances,
        entries=entries,
    )


def _iban(statement: etree._Element, namespace: str) -> str | None:
    account = _optional_child(statement, namespace, "Acct")
    if account is None:
        return None
    identification = _optional_child(account, namespace, "Id")
    if identification is None:
        return None
    iban = _optional_child(identification, namespace, "IBAN")
    return _text(iban) if iban is not None else None


def _parse_balance(balance: etree._Element, namespace: str) -> Balance:
    amount, currency = _amount(balance, namespace)
    return Balance(
        code=_text(_child(_child(_child(balance, namespace, "Tp"), namespace, "CdOrPrtry"),
                          namespace, "Cd")),
        amount=amount,
        currency=currency,
        credit_debit=_credit_debit(balance, namespace),
        date=_date(_child(balance, namespace, "Dt"), namespace),
    )


def _parse_entry(entry: etree._Element, namespace: str) -> Entry:
    amount, currency = _amount(entry, namespace)
    reference = _optional_child(entry, namespace, "AcctSvcrRef")
    return Entry(
        amount=amount,
        currency=currency,
        credit_debit=_credit_debit(entry, namespace),
        status=_status(entry, namespace),
        booking_date=_optional_date(entry, namespace, "BookgDt"),
        value_date=_optional_date(entry, namespace, "ValDt"),
        reference=_text(reference) if reference is not None else None,
    )


def _status(entry: etree._Element, namespace: str) -> str:
    # camt.053.001.08 wraps the status in <Sts><Cd>…</Cd></Sts>; older vintages put the
    # code straight in <Sts>. Accept either.
    status = _child(entry, namespace, "Sts")
    code = _optional_child(status, namespace, "Cd")
    return _text(code) if code is not None else _text(status)


def _amount(parent: etree._Element, namespace: str) -> tuple[Decimal, str]:
    element = _child(parent, namespace, "Amt")
    currency = element.get("Ccy")
    if currency is None:
        raise MessageFormatError("A camt.053 <Amt> is missing its Ccy attribute")
    text = element.text
    if text is None:
        raise MessageFormatError("A camt.053 <Amt> is empty")
    try:
        return Decimal(text), currency
    except InvalidOperation as error:
        raise MessageFormatError(f"A camt.053 <Amt> is not a decimal: {text!r}") from error


def _credit_debit(parent: etree._Element, namespace: str) -> CreditDebit:
    text = _text(_child(parent, namespace, "CdtDbtInd"))
    try:
        return CreditDebit(text)
    except ValueError as error:
        raise MessageFormatError(f"A camt.053 <CdtDbtInd> is not CRDT/DBIT: {text!r}") from error


def _optional_date(parent: etree._Element, namespace: str, local_name: str) -> datetime.date | None:
    element = _optional_child(parent, namespace, local_name)
    return _date(element, namespace) if element is not None else None


def _date(parent: etree._Element, namespace: str) -> datetime.date:
    # A camt.053 date choice is <Dt> (a date) or <DtTm> (a date-time); take the date part.
    date = _optional_child(parent, namespace, "Dt")
    if date is not None:
        return _parse_iso_date(_text(date))
    date_time = _optional_child(parent, namespace, "DtTm")
    if date_time is not None:
        return _parse_iso_date(_text(date_time)[:10])
    raise MessageFormatError("A camt.053 date is missing both <Dt> and <DtTm>")


def _parse_iso_date(text: str) -> datetime.date:
    try:
        return datetime.date.fromisoformat(text)
    except ValueError as error:
        raise MessageFormatError(f"A camt.053 date is not an ISO date: {text!r}") from error


def _balance_with_code(balances: tuple[Balance, ...], code: str) -> Balance | None:
    return next((balance for balance in balances if balance.code == code), None)


def _child(parent: etree._Element, namespace: str, local_name: str) -> etree._Element:
    child = _optional_child(parent, namespace, local_name)
    if child is None:
        raise MessageFormatError(f"A camt.053 element is missing <{local_name}>")
    return child


def _optional_child(
    parent: etree._Element, namespace: str, local_name: str
) -> etree._Element | None:
    return parent.find(f"{{{namespace}}}{local_name}")


def _children(parent: etree._Element, namespace: str, local_name: str) -> list[etree._Element]:
    return parent.findall(f"{{{namespace}}}{local_name}")


def _text(element: etree._Element) -> str:
    text = element.text
    if text is None:
        raise MessageFormatError(f"A camt.053 <{etree.QName(element).localname}> is empty")
    return text.strip()


def _parse_xml(data: bytes) -> etree._Element:
    # Hardened parser: no entity expansion, no network access (see docs/06).
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    try:
        return etree.fromstring(data, parser=parser)
    except etree.XMLSyntaxError as error:
        raise MessageFormatError(f"Malformed camt.053 XML: {error}") from error
