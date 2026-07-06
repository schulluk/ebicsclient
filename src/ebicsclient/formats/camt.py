"""Shared parsing core for the ISO 20022 camt account-reporting family.

camt.053 statements (``BkToCstmrStmt/Stmt``), camt.052 intraday reports
(``BkToCstmrAcctRpt/Rpt``), and camt.054 debit/credit notifications
(``BkToCstmrDbtCdtNtfctn/Ntfctn``) all share one core shape: an identification, an
account, and booking entries — statements and reports additionally carry balances. This
module holds that shared machinery; the thin per-type modules
(:mod:`~ebicsclient.formats.camt053`, :mod:`~ebicsclient.formats.camt052`,
:mod:`~ebicsclient.formats.camt054`) only name their wrapper elements and models.

Element names are read namespace-agnostically: each document's camt namespace is adopted
from its root, so a different message version still parses without a code change.
"""

import datetime
from decimal import Decimal, InvalidOperation

from lxml import etree

from ebicsclient.errors import MessageFormatError
from ebicsclient.models import Balance, CreditDebit, Entry, Statement

_DOCUMENT = "Document"
# Closing/opening booked balances are selected by their ISO external balance-type code.
_CLOSING_BOOKED = "CLBD"
_OPENING_BOOKED = "OPBD"


def document_items(
    document: bytes, message: str, wrapper: str, item: str
) -> list[tuple[etree._Element, str]]:
    """Extract the per-account item elements from one camt XML document.

    Args:
        document: The raw XML document bytes.
        message: The message name for error reporting (e.g. ``"camt.053"``).
        wrapper: The wrapper element under ``Document`` (e.g. ``"BkToCstmrStmt"``).
        item: The repeated item element (e.g. ``"Stmt"``, ``"Rpt"``, ``"Ntfctn"``).

    Returns:
        The item elements paired with the document's namespace, in document order.

    Raises:
        MessageFormatError: the document is malformed or not the expected shape.
    """
    root = _parse_xml(document, message)
    local_name = etree.QName(root).localname
    if local_name != _DOCUMENT:
        raise MessageFormatError(f"Expected a {message} <Document>, got <{local_name}>")
    namespace = etree.QName(root).namespace
    if namespace is None:
        raise MessageFormatError(f"{message} <Document> declares no namespace")
    report = child(root, namespace, wrapper)
    return [(element, namespace) for element in children(report, namespace, item)]


def parse_statement(statement: etree._Element, namespace: str) -> Statement:
    """Parse one ``Stmt``/``Rpt`` element into a :class:`~ebicsclient.models.Statement`."""
    balances = tuple(
        parse_balance(balance, namespace) for balance in children(statement, namespace, "Bal")
    )
    return Statement(
        identification=identification(statement, namespace),
        iban=iban(statement, namespace),
        opening_balance=balance_with_code(balances, _OPENING_BOOKED),
        closing_balance=balance_with_code(balances, _CLOSING_BOOKED),
        balances=balances,
        entries=parse_entries(statement, namespace),
    )


def identification(item: etree._Element, namespace: str) -> str:
    """Read the item's ``Id``."""
    return text(child(item, namespace, "Id"))


def iban(item: etree._Element, namespace: str) -> str | None:
    """Read the account IBAN (``Acct/Id/IBAN``), or ``None`` if another id is used."""
    account = optional_child(item, namespace, "Acct")
    if account is None:
        return None
    account_id = optional_child(account, namespace, "Id")
    if account_id is None:
        return None
    element = optional_child(account_id, namespace, "IBAN")
    return text(element) if element is not None else None


def parse_entries(item: etree._Element, namespace: str) -> tuple[Entry, ...]:
    """Parse every booking entry (``Ntry``) of one item, in document order."""
    return tuple(_parse_entry(entry, namespace) for entry in children(item, namespace, "Ntry"))


def parse_balance(balance: etree._Element, namespace: str) -> Balance:
    """Parse one ``Bal`` element."""
    amount, currency = _amount(balance, namespace)
    return Balance(
        code=text(
            child(child(child(balance, namespace, "Tp"), namespace, "CdOrPrtry"), namespace, "Cd")
        ),
        amount=amount,
        currency=currency,
        credit_debit=_credit_debit(balance, namespace),
        date=_date(child(balance, namespace, "Dt"), namespace),
    )


def balance_with_code(balances: tuple[Balance, ...], code: str) -> Balance | None:
    """Return the first balance carrying the given ISO balance-type code, if any."""
    return next((balance for balance in balances if balance.code == code), None)


def _parse_entry(entry: etree._Element, namespace: str) -> Entry:
    amount, currency = _amount(entry, namespace)
    reference = optional_child(entry, namespace, "AcctSvcrRef")
    return Entry(
        amount=amount,
        currency=currency,
        credit_debit=_credit_debit(entry, namespace),
        status=_status(entry, namespace),
        booking_date=_optional_date(entry, namespace, "BookgDt"),
        value_date=_optional_date(entry, namespace, "ValDt"),
        reference=text(reference) if reference is not None else None,
    )


def _status(entry: etree._Element, namespace: str) -> str:
    # The 2019 vintages wrap the status in <Sts><Cd>…</Cd></Sts>; older ones put the
    # code straight in <Sts>. Accept either.
    status = child(entry, namespace, "Sts")
    code = optional_child(status, namespace, "Cd")
    return text(code) if code is not None else text(status)


def _amount(parent: etree._Element, namespace: str) -> tuple[Decimal, str]:
    element = child(parent, namespace, "Amt")
    currency = element.get("Ccy")
    if currency is None:
        raise MessageFormatError("A camt <Amt> is missing its Ccy attribute")
    value = element.text
    if value is None:
        raise MessageFormatError("A camt <Amt> is empty")
    try:
        return Decimal(value), currency
    except InvalidOperation as error:
        raise MessageFormatError(f"A camt <Amt> is not a decimal: {value!r}") from error


def _credit_debit(parent: etree._Element, namespace: str) -> CreditDebit:
    value = text(child(parent, namespace, "CdtDbtInd"))
    try:
        return CreditDebit(value)
    except ValueError as error:
        raise MessageFormatError(f"A camt <CdtDbtInd> is not CRDT/DBIT: {value!r}") from error


def _optional_date(
    parent: etree._Element, namespace: str, local_name: str
) -> datetime.date | None:
    element = optional_child(parent, namespace, local_name)
    return _date(element, namespace) if element is not None else None


def _date(parent: etree._Element, namespace: str) -> datetime.date:
    # A camt date choice is <Dt> (a date) or <DtTm> (a date-time); take the date part.
    date = optional_child(parent, namespace, "Dt")
    if date is not None:
        return _parse_iso_date(text(date))
    date_time = optional_child(parent, namespace, "DtTm")
    if date_time is not None:
        return _parse_iso_date(text(date_time)[:10])
    raise MessageFormatError("A camt date is missing both <Dt> and <DtTm>")


def _parse_iso_date(value: str) -> datetime.date:
    try:
        return datetime.date.fromisoformat(value)
    except ValueError as error:
        raise MessageFormatError(f"A camt date is not an ISO date: {value!r}") from error


def child(parent: etree._Element, namespace: str, local_name: str) -> etree._Element:
    """Return the required direct child, raising :class:`MessageFormatError` if absent."""
    element = optional_child(parent, namespace, local_name)
    if element is None:
        raise MessageFormatError(f"A camt element is missing <{local_name}>")
    return element


def optional_child(
    parent: etree._Element, namespace: str, local_name: str
) -> etree._Element | None:
    """Return the direct child, or ``None`` if absent."""
    return parent.find(f"{{{namespace}}}{local_name}")


def children(parent: etree._Element, namespace: str, local_name: str) -> list[etree._Element]:
    """Return every direct child with the given name, in document order."""
    return parent.findall(f"{{{namespace}}}{local_name}")


def text(element: etree._Element) -> str:
    """Return the element's stripped text, raising if it is empty."""
    value = element.text
    if value is None:
        raise MessageFormatError(f"A camt <{etree.QName(element).localname}> is empty")
    return value.strip()


def _parse_xml(data: bytes, message: str) -> etree._Element:
    # Hardened parser: no entity expansion, no network access (see docs/06).
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    try:
        return etree.fromstring(data, parser=parser)
    except etree.XMLSyntaxError as error:
        raise MessageFormatError(f"Malformed {message} XML: {error}") from error
