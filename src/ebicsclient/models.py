"""Data models for ebicsclient.

Plain data holders kept free of behaviour; the logic that operates on them lives in
the feature modules (e.g. ``keys.py`` for keyring generation and persistence).
"""

import datetime
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum

from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass(frozen=True, slots=True)
class Bank:
    """Connection details for a bank's EBICS endpoint.

    Attributes:
        host_id: The bank's EBICS Host ID.
        url: The bank's EBICS HTTPS endpoint.
    """

    host_id: str
    url: str


@dataclass(frozen=True, slots=True)
class User:
    """A subscriber's identifiers at the bank.

    Attributes:
        partner_id: The customer (Partner) ID.
        user_id: The subscriber (User) ID.
    """

    partner_id: str
    user_id: str


@dataclass(frozen=True, slots=True)
class Keyring:
    """A subscriber's three EBICS RSA key pairs.

    Every EBICS subscriber holds three RSA key pairs, identified by their EBICS
    algorithm version: the bank-technical signature key (A006), the identification
    and authentication key (X002), and the encryption key (E002).

    Attributes:
        signature: The A006 bank-technical signature key pair.
        authentication: The X002 identification and authentication key pair.
        encryption: The E002 encryption key pair.
    """

    signature: rsa.RSAPrivateKey
    authentication: rsa.RSAPrivateKey
    encryption: rsa.RSAPrivateKey


@dataclass(frozen=True, slots=True)
class BankKeys:
    """The bank's public keys, retrieved over HPB.

    The bank holds its own identification/authentication (X002) and encryption (E002)
    key pairs; HPB returns their public halves. The subscriber must verify the keys'
    hashes against the values the bank publishes out of band before trusting them.

    Attributes:
        authentication: The bank's X002 identification and authentication public key.
        encryption: The bank's E002 encryption public key.
    """

    authentication: rsa.RSAPublicKey
    encryption: rsa.RSAPublicKey


class InitializationState(StrEnum):
    """The outcome of submitting subscriber keys with INI or HIA.

    - ``SUBMITTED``: the bank accepted and stored the keys.
    - ``ALREADY_INITIALISED``: the subscriber was already in this state, so the keys were
      not re-submitted (a handshake re-run). The bank reports this the same way it reports
      an unknown subscriber, which would instead surface later at HPB.
    """

    SUBMITTED = "submitted"
    ALREADY_INITIALISED = "already_initialised"


@dataclass(frozen=True, slots=True)
class BusinessTransactionFormat:
    """An EBICS 3.0 Business Transaction Format (BTF) — what to download or upload.

    In H005 the BTF replaces the old order type: it names the service and message via the
    parameters below (e.g. Swiss camt.053 statements are ``EOP / CH / ZIP / camt.053 / 08``).

    Attributes:
        service_name: The service code (e.g. ``"EOP"`` for end-of-period statements).
        message_name: The message name (e.g. ``"camt.053"``).
        scope: The rule scope, e.g. an ISO country code (``"CH"``); ``None`` for global.
        message_version: The ISO 20022 version, e.g. ``"08"``.
        container: The container format, e.g. ``"ZIP"``; ``None`` for none.
        service_option: An optional service option code.
    """

    service_name: str
    message_name: str
    scope: str | None = None
    message_version: str | None = None
    container: str | None = None
    service_option: str | None = None


#: The Swiss camt.053.001.08 account-statement download (end-of-period, ZIP container).
CAMT_053 = BusinessTransactionFormat(
    service_name="EOP",
    message_name="camt.053",
    scope="CH",
    message_version="08",
    container="ZIP",
)


@dataclass(frozen=True, slots=True)
class DownloadInitialisation:
    """The bank's reply to a download-initialisation request (BTD, phase Initialisation).

    Opening a download transaction returns the transaction handle, how many segments the
    order data was split into, the encrypted symmetric key needed to decrypt it, and the
    first order-data segment. Further segments (if ``num_segments > 1``) are fetched with
    transfer requests keyed by ``transaction_id``.

    Attributes:
        transaction_id: The bank-issued transaction ID, echoed on transfer and receipt.
        num_segments: The total number of segments the order data was split into.
        transaction_key: The symmetric transaction key, RSA-encrypted to the subscriber's
            E002 encryption key; unwrap it with the E002 private key to decrypt the data.
        segment_number: The 1-based number of the segment carried here (always 1).
        last_segment: Whether this is the final segment (true when ``num_segments == 1``).
        order_data_segment: This segment's order data, as the raw base64 text from the wire.
            Segments are pieces of one base64 stream, so they must be concatenated *before*
            decoding — never decoded individually.
    """

    transaction_id: str
    num_segments: int
    transaction_key: bytes
    segment_number: int
    last_segment: bool
    order_data_segment: str


@dataclass(frozen=True, slots=True)
class DownloadSegment:
    """The bank's reply to a download-transfer request (one further order-data segment).

    Attributes:
        segment_number: The 1-based number of the segment carried here.
        last_segment: Whether this is the final segment of the transfer.
        order_data_segment: This segment's order data, as the raw base64 text from the wire
            (see :class:`DownloadInitialisation.order_data_segment` on concatenation).
    """

    segment_number: int
    last_segment: bool
    order_data_segment: str


class CreditDebit(StrEnum):
    """Whether an amount is a credit or a debit (ISO 20022 ``CreditDebitCode``).

    - ``CREDIT``: money into the account (ISO code ``CRDT``).
    - ``DEBIT``: money out of the account (ISO code ``DBIT``).
    """

    CREDIT = "CRDT"
    DEBIT = "DBIT"


#: ISO external balance-type code for the closing booked balance — the definitive
#: end-of-period balance carried in a camt.053 statement.
BALANCE_CLOSING_BOOKED = "CLBD"
#: ISO external balance-type code for the opening booked balance.
BALANCE_OPENING_BOOKED = "OPBD"


@dataclass(frozen=True, slots=True)
class Balance:
    """One balance reported in an account statement.

    Attributes:
        code: The ISO external balance-type code (an open code list), e.g. ``"CLBD"``
            (closing booked) or ``"OPBD"`` (opening booked). See ``BALANCE_*`` constants.
        amount: The balance amount, as an exact decimal (never a float).
        currency: The ISO 4217 currency code of ``amount`` (e.g. ``"CHF"``).
        credit_debit: Whether the balance is a credit or a debit position.
        date: The date the balance refers to.
    """

    code: str
    amount: Decimal
    currency: str
    credit_debit: CreditDebit
    date: datetime.date


@dataclass(frozen=True, slots=True)
class Entry:
    """One booking entry in an account statement.

    Attributes:
        amount: The entry amount, as an exact decimal (never a float).
        currency: The ISO 4217 currency code of ``amount``.
        credit_debit: Whether the entry credits or debits the account.
        status: The ISO entry status (e.g. ``"BOOK"`` booked, ``"PDNG"`` pending).
        booking_date: The booking date, or ``None`` if the statement omitted it.
        value_date: The value date, or ``None`` if the statement omitted it.
        reference: The account-servicer reference, or ``None`` if absent.
    """

    amount: Decimal
    currency: str
    credit_debit: CreditDebit
    status: str
    booking_date: datetime.date | None
    value_date: datetime.date | None
    reference: str | None


@dataclass(frozen=True, slots=True)
class Statement:
    """A single account statement parsed from a camt.053 document.

    Attributes:
        identification: The statement identification assigned by the bank.
        iban: The account IBAN, or ``None`` if the statement carried another account id.
        opening_balance: The opening booked balance (``OPBD``), or ``None`` if not reported.
        closing_balance: The closing booked balance (``CLBD``), or ``None`` if not reported.
        balances: Every balance the statement reported, in document order.
        entries: Every booking entry the statement reported, in document order.
    """

    identification: str
    iban: str | None
    opening_balance: Balance | None
    closing_balance: Balance | None
    balances: tuple[Balance, ...]
    entries: tuple[Entry, ...]


class OutputFormat(StrEnum):
    """The rendering format for the initialisation letter.

    - ``AUTO``: render PDF when the optional ``pdf`` extra is installed, otherwise HTML.
    - ``HTML``: dependency-free HTML; always available.
    - ``PDF``: PDF; requires the ``pdf`` extra (reportlab).
    """

    AUTO = "auto"
    HTML = "html"
    PDF = "pdf"


@dataclass(frozen=True, slots=True)
class Letter:
    """A rendered initialisation letter, ready to be written out and sent to the bank.

    Attributes:
        output_format: The concrete format rendered — ``HTML`` or ``PDF``, never ``AUTO``.
        media_type: The IANA media type of ``content`` (e.g. ``"application/pdf"``).
        content: The rendered document bytes.
    """

    output_format: OutputFormat
    media_type: str
    content: bytes
