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


@dataclass(frozen=True, slots=True)
class BankKeyHashes:
    """The SHA-256 hashes that pin the bank's public keys across sessions.

    Used to detect if the bank's HPB keys ever change from a previously trusted set (or from
    the values the bank publishes out of band). The caller persists these two hashes wherever
    it likes — they are public values, not secrets — and passes them back to pin a later HPB.

    Attributes:
        authentication: The SHA-256 EBICS hash of the bank's X002 authentication key.
        encryption: The SHA-256 EBICS hash of the bank's E002 encryption key.
    """

    authentication: bytes
    encryption: bytes


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
#: Matches the ZKB ``Z53`` order type verbatim (``EOP / CH / camt.053 / 08 / ZIP``); see
#: docs/10-btf-order-types.md, which transcribes ZKB's published order-type/BTF catalogue.
CAMT_053 = BusinessTransactionFormat(
    service_name="EOP",
    message_name="camt.053",
    scope="CH",
    message_version="08",
    container="ZIP",
)

#: The Swiss camt.052.001.08 intraday account report download (the ZKB ``Z52`` order type,
#: ``STM / CH / camt.052 / 08 / ZIP``); confirmed against the bank's HTD registry.
CAMT_052 = BusinessTransactionFormat(
    service_name="STM",
    message_name="camt.052",
    scope="CH",
    message_version="08",
    container="ZIP",
)

#: The Swiss camt.054.001.08 debit/credit notification download (the ZKB ``Z54`` order type,
#: ``REP / CH / camt.054 / 08 / ZIP``); confirmed against the bank's HTD registry. The
#: QRR/SCOR/LSV collective-resolution variants use the same tuple with a ``service_option``
#: (``XQRR``/``XSCR``/…, see docs/10-btf-order-types.md).
CAMT_054 = BusinessTransactionFormat(
    service_name="REP",
    message_name="camt.054",
    scope="CH",
    message_version="08",
    container="ZIP",
)

#: The Swiss pain.001.001.09 payment-submission upload (no container). Matches the ZKB ``XE2``
#: order type (``MCT / CH / pain.001 / 09``); see docs/10-btf-order-types.md.
PAIN_001 = BusinessTransactionFormat(
    service_name="MCT",
    message_name="pain.001",
    scope="CH",
    message_version="09",
)

#: The Swiss pain.002.001.10 payment-status-report download (the ZKB ``Z01`` order type).
#: The bank's own HTD registry lists this BTF as ``PSR / CH / pain.002 / 10`` **without** a
#: Container — a request carrying ``Container=ZIP`` is rejected with ``091005``, even though
#: ZKB's human-readable catalogue shows a ZIP column (the *delivered file* is a ZIP; the BTF
#: registration is container-less). Validated live; see docs/09 and docs/10.
PAIN_002 = BusinessTransactionFormat(
    service_name="PSR",
    message_name="pain.002",
    scope="CH",
    message_version="10",
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


@dataclass(frozen=True, slots=True)
class UploadPayload:
    """The encrypted, signed pieces of one upload, shared across its request phases.

    An upload encrypts the order data once (and the order signature with the same transaction
    key), so the initialisation and transfer requests are built from this single prepared
    payload. It carries no plaintext secret: the transaction key is wrapped to the bank, and
    the signature and order-data segments are already encrypted.

    Attributes:
        wrapped_transaction_key: The AES transaction key, RSA-encrypted to the bank's E002 key.
        data_digest: The SHA-256 digest of the order data (the request's DataDigest value).
        signature_data: The compressed, encrypted A006 order signature (UserSignatureData), as
            base64 text — carried in the initialisation request.
        order_data_segments: The compressed, encrypted order data as base64 text, split into
            one or more segments carried by the transfer requests.
    """

    wrapped_transaction_key: bytes
    data_digest: bytes
    signature_data: str
    order_data_segments: tuple[str, ...]

    @property
    def num_segments(self) -> int:
        """The number of order-data segments (the request's NumSegments)."""
        return len(self.order_data_segments)


@dataclass(frozen=True, slots=True)
class Notification:
    """A camt.054 debit/credit notification (booking advice).

    Attributes:
        identification: The notification identification assigned by the bank.
        iban: The account IBAN, or ``None`` if the notification carried another account id.
        entries: The booking entries the notification reports, in document order.
    """

    identification: str
    iban: str | None
    entries: tuple[Entry, ...]


#: ISO external status code: the file passed technical validation (syntax/schema).
STATUS_ACCEPTED_TECHNICAL = "ACTC"
#: ISO external status code: the payment or file was accepted for processing.
STATUS_ACCEPTED = "ACCP"
#: ISO external status code: some transactions were accepted, others rejected.
STATUS_PARTIALLY_ACCEPTED = "PART"
#: ISO external status code: the transaction, payment, or file was rejected.
STATUS_REJECTED = "RJCT"


@dataclass(frozen=True, slots=True)
class StatusReason:
    """One reason attached to a pain.002 status (``StsRsnInf``).

    Attributes:
        code: The ISO external status-reason code (e.g. ``"AC01"`` invalid account number,
            ``"RC05"`` invalid BIC), or ``None`` if the report gave only free text.
        additional_information: Free-text detail from the bank, or ``None``.
    """

    code: str | None
    additional_information: str | None


@dataclass(frozen=True, slots=True)
class TransactionStatus:
    """The status of one original transaction in a pain.002 report (``TxInfAndSts``).

    Attributes:
        status: The ISO transaction status (e.g. ``"RJCT"``; see the ``STATUS_*`` constants).
            ``None`` if the report omitted it.
        original_instruction_id: The ``InstrId`` of the original transaction, or ``None``.
        original_end_to_end_id: The ``EndToEndId`` of the original transaction, or ``None``.
        reasons: The status reasons, in document order (usually one; empty when accepted).
    """

    status: str | None
    original_instruction_id: str | None
    original_end_to_end_id: str | None
    reasons: tuple[StatusReason, ...]


@dataclass(frozen=True, slots=True)
class PaymentStatus:
    """The status of one original payment block in a pain.002 report (``OrgnlPmtInfAndSts``).

    Attributes:
        original_payment_information_id: The ``PmtInfId`` of the original payment block.
        status: The ISO payment status (``PmtInfSts``), or ``None`` if omitted.
        reasons: Payment-level status reasons, in document order.
        transactions: Per-transaction statuses, in document order (may be empty — banks
            often report only the exceptions).
    """

    original_payment_information_id: str
    status: str | None
    reasons: tuple[StatusReason, ...]
    transactions: tuple[TransactionStatus, ...]


@dataclass(frozen=True, slots=True)
class PaymentStatusReport:
    """A pain.002 customer payment status report (``CstmrPmtStsRpt``).

    The bank's verdict on a previously submitted pain.001: a group status for the whole
    file, and — where relevant — per-payment and per-transaction statuses with reasons.

    Attributes:
        identification: The report's own message ID (``GrpHdr/MsgId``).
        original_message_id: The ``MsgId`` of the pain.001 this report answers.
        original_message_name: The original message name (e.g.
            ``"pain.001.001.09.ch.03"``), or ``None`` if omitted.
        group_status: The ISO group status (e.g. ``"ACTC"``, ``"ACCP"``, ``"PART"``,
            ``"RJCT"``; see the ``STATUS_*`` constants), or ``None`` if omitted.
        reasons: Group-level status reasons, in document order.
        payments: Per-payment statuses, in document order.
    """

    identification: str
    original_message_id: str
    original_message_name: str | None
    group_status: str | None
    reasons: tuple[StatusReason, ...]
    payments: tuple[PaymentStatus, ...]

    @property
    def rejected_transactions(self) -> tuple[TransactionStatus, ...]:
        """Every transaction reported with status ``RJCT``, across all payment blocks."""
        return tuple(
            transaction
            for payment in self.payments
            for transaction in payment.transactions
            if transaction.status == STATUS_REJECTED
        )


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
