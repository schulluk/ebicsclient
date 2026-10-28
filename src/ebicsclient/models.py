"""Data models for ebicsclient.

Plain data holders kept free of behaviour; the logic that operates on them lives in
the feature modules (e.g. ``keys.py`` for keyring generation and persistence).
"""

import datetime
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa


def _require_identifier(field_name: str, value: object) -> None:
    # EBICS identifiers can carry leading zeros (e.g. a Partner ID of "00123456").
    # Loaded from an unquoted YAML/JSON/TOML config value they arrive as numbers — the wrong
    # type AND silently stripped of their zeros (PyYAML even reads all-octal-digit values as
    # octal). Failing here, with the fix in the message, beats a cryptic TypeError four
    # frames deep in a crypto or XML library.
    if not isinstance(value, str):
        raise TypeError(
            f"{field_name} must be a str, got {type(value).__name__} ({value!r}). EBICS "
            f"identifiers can carry leading zeros — quote them in your configuration to "
            f"keep both the type and the zeros."
        )
    if not value.strip():
        raise ValueError(f"{field_name} must not be empty")


def _require_optional_identifier(field_name: str, value: object) -> None:
    if value is not None:
        _require_identifier(field_name, value)


@dataclass(frozen=True, slots=True)
class Bank:
    """Connection details for a bank's EBICS endpoint.

    Attributes:
        host_id: The bank's EBICS Host ID.
        url: The bank's EBICS HTTPS endpoint.

    Raises:
        TypeError: a field is not a ``str`` (e.g. a numeric config value).
        ValueError: a field is empty.
    """

    host_id: str
    url: str

    def __post_init__(self) -> None:
        _require_identifier("host_id", self.host_id)
        _require_identifier("url", self.url)


@dataclass(frozen=True, slots=True)
class User:
    """A subscriber's identifiers at the bank.

    Attributes:
        partner_id: The customer (Partner) ID.
        user_id: The subscriber (User) ID.

    Raises:
        TypeError: an ID is not a ``str`` — commonly an unquoted, zero-leading ID in a
            YAML/JSON config parsed as a number (which also silently drops the zeros).
        ValueError: an ID is empty.
    """

    partner_id: str
    user_id: str

    def __post_init__(self) -> None:
        _require_identifier("partner_id", self.partner_id)
        _require_identifier("user_id", self.user_id)


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

    def __post_init__(self) -> None:
        for field_name, value in (
            ("signature", self.signature),
            ("authentication", self.authentication),
            ("encryption", self.encryption),
        ):
            if not isinstance(value, rsa.RSAPrivateKey):
                raise TypeError(
                    f"{field_name} must be an RSA private key, got {type(value).__name__} — "
                    f"generate keys with generate_keyring() or load them with load_keyring()"
                )


@dataclass(frozen=True, slots=True)
class BankKeys:
    """The bank's public keys, retrieved over HPB, with the certificates that carried them.

    The bank holds its own identification/authentication (X002) and encryption (E002)
    key pairs; HPB returns their public halves, in EBICS 3.0 as X.509 certificates. The
    subscriber must verify the keys' hashes against the values the bank publishes out of
    band before trusting them.

    Every later request names the bank keys it was built for: ``BankPubKeyDigests`` in the
    header and, for uploads, ``EncryptionPubKeyDigest``. EBICS 3.0 defines those values as
    the SHA-256 over the certificate in DER form (spec 5.5.1.1.1, 5.6.1.1.1, 11.3.2.2), so
    the certificates are kept here. A key the bank still delivers without a certificate,
    carried over from EBICS 2.x, is named by the hash of the public key instead (spec
    11.3.2.2); its certificate field stays ``None``.

    Attributes:
        authentication: The bank's X002 identification and authentication public key.
        encryption: The bank's E002 encryption public key.
        authentication_certificate: The X.509 certificate HPB delivered for the X002 key,
            or ``None`` when the bank sent a bare key.
        encryption_certificate: The X.509 certificate HPB delivered for the E002 key, or
            ``None`` when the bank sent a bare key.

    Raises:
        TypeError: a key is not an RSA public key, or a certificate is not an
            :class:`cryptography.x509.Certificate`.
        ValueError: a certificate does not hold the public key it is given for.
    """

    authentication: rsa.RSAPublicKey
    encryption: rsa.RSAPublicKey
    authentication_certificate: x509.Certificate | None = None
    encryption_certificate: x509.Certificate | None = None

    def __post_init__(self) -> None:
        for field_name, value, certificate in (
            ("authentication", self.authentication, self.authentication_certificate),
            ("encryption", self.encryption, self.encryption_certificate),
        ):
            if not isinstance(value, rsa.RSAPublicKey):
                raise TypeError(
                    f"{field_name} must be an RSA public key, got {type(value).__name__}"
                )
            if certificate is None:
                continue
            if not isinstance(certificate, x509.Certificate):
                raise TypeError(
                    f"{field_name}_certificate must be an x509.Certificate or None, got "
                    f"{type(certificate).__name__}"
                )
            certified_key = certificate.public_key()
            if (
                not isinstance(certified_key, rsa.RSAPublicKey)
                or certified_key.public_numbers() != value.public_numbers()
            ):
                # The digest sent to the bank is computed over this certificate; a certificate
                # for another key would name a key the bank does not hold under this subscriber.
                raise ValueError(f"{field_name}_certificate does not certify the {field_name} key")


@dataclass(frozen=True, slots=True)
class BankKeyHashes:
    """The SHA-256 hashes that pin the bank's public keys across sessions.

    Used to detect if the bank's HPB keys ever change from a previously trusted set (or from
    the values the bank publishes out of band). The caller persists these two hashes wherever
    it likes — they are public values, not secrets — and passes them back to pin a later HPB.

    Each value is a raw 32-byte SHA-256 digest in either form a bank publishes for a key: the
    hash of the public key itself (the EBICS 2.x ``exponent modulus`` form, which
    :func:`~ebicsclient.public_key_hash` and :func:`~ebicsclient.bank_key_hashes` compute and
    banks print for the key-based "mit Schlüsseln" profile), or the hash of the key's X.509
    certificate in DER form (what EBICS 3.0 means by the hash value of a key, spec 5.5.1.1.1
    and glossary; :func:`~ebicsclient.certificate_fingerprint` computes it). HPB pinning
    compares a value with both forms of the delivered key; a key the bank delivers without a
    certificate (spec 11.3.2.2) matches the public-key form only. For a published
    hexadecimal value use ``bytes.fromhex(hash_text.replace(" ", ""))``.

    Attributes:
        authentication: The SHA-256 hash of the bank's X002 authentication key, in either form.
        encryption: The SHA-256 hash of the bank's E002 encryption key, in either form.
    """

    authentication: bytes
    encryption: bytes

    def __post_init__(self) -> None:
        for field_name, value in (
            ("authentication", self.authentication),
            ("encryption", self.encryption),
        ):
            if not isinstance(value, bytes):
                raise TypeError(
                    f"{field_name} must be the raw 32-byte SHA-256 digest as bytes, got "
                    f"{type(value).__name__} — for a published hex hash use "
                    f'bytes.fromhex(hash_text.replace(" ", ""))'
                )
            if len(value) != 32:
                raise ValueError(
                    f"{field_name} must be exactly 32 bytes (SHA-256), got {len(value)}"
                )


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

    def __post_init__(self) -> None:
        # message_version is the classic trap: an unquoted "08" in YAML/JSON config arrives
        # as the int 8 — wrong type and a silently different version on the wire.
        _require_identifier("service_name", self.service_name)
        _require_identifier("message_name", self.message_name)
        _require_optional_identifier("scope", self.scope)
        _require_optional_identifier("message_version", self.message_version)
        _require_optional_identifier("container", self.container)
        _require_optional_identifier("service_option", self.service_option)


@dataclass(frozen=True, slots=True)
class DateRange:
    """An inclusive date range for a dated download (the BTD ``DateRange`` order parameter).

    EBICS 3.0 lets a download request a specific reporting period instead of the default
    (the bank's not-yet-delivered data). The H005 schema types both bounds as calendar
    dates and treats them as **inclusive** (``DateRangeType``, ``ebics_orders_H005.xsd``);
    the bank returns the messages whose reporting date falls within ``start..end``.

    Whether a bank re-serves data it has *already* delivered for a past range is a
    bank-side policy, not guaranteed by the standard — confirm with the bank before
    relying on a dated re-download.

    Attributes:
        start: The first day to include (inclusive).
        end: The last day to include (inclusive); must not precede ``start``.

    Raises:
        TypeError: a bound is not a :class:`datetime.date`.
        ValueError: ``end`` precedes ``start``.
    """

    start: datetime.date
    end: datetime.date

    def __post_init__(self) -> None:
        for field_name, value in (("start", self.start), ("end", self.end)):
            # A datetime is a date subclass; reject it so a caller does not silently drop a
            # time component the wire format has no room for.
            if not isinstance(value, datetime.date) or isinstance(value, datetime.datetime):
                raise TypeError(
                    f"{field_name} must be a datetime.date, got {type(value).__name__}"
                )
        if self.end < self.start:
            raise ValueError(
                f"end ({self.end.isoformat()}) must not precede start ({self.start.isoformat()})"
            )


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
#: ``REP / CH / camt.054 / 08 / ZIP``); confirmed against the bank's HTD registry. ZKB
#: delivers its notifications under variants of this tuple that add a ``service_option`` —
#: see the constants below and docs/10-btf-order-types.md.
CAMT_054 = BusinessTransactionFormat(
    service_name="REP",
    message_name="camt.054",
    scope="CH",
    message_version="08",
    container="ZIP",
)

#: The Swiss camt.054.001.08 booking information (the ZKB ``ZS2`` order type, ``REP / CH /
#: XDCI / camt.054 / 08 / ZIP``): one notification per booking, credits and debits alike.
#: Confirmed against the bank's HTD registry and downloaded live from the ZKB test platform
#: (docs/09).
CAMT_054_BOOKING_INFORMATION = BusinessTransactionFormat(
    service_name="REP",
    message_name="camt.054",
    scope="CH",
    message_version="08",
    container="ZIP",
    service_option="XDCI",
)

#: The Swiss camt.054.001.08 details of collective debits (the ZKB ``ZS4`` order type,
#: ``REP / CH / XABK / camt.054 / 08 / ZIP``): a payment file booked as one batch debit,
#: reported with its single transactions. Confirmed against the bank's HTD registry and
#: downloaded live from the ZKB test platform (docs/09).
CAMT_054_COLLECTIVE_DEBITS = BusinessTransactionFormat(
    service_name="REP",
    message_name="camt.054",
    scope="CH",
    message_version="08",
    container="ZIP",
    service_option="XABK",
)

#: The Swiss pain.001.001.09 payment-submission upload (no container). Matches the ZKB ``XE2``
#: order type (``MCT / CH / pain.001 / 09``); see docs/10-btf-order-types.md.
PAIN_001 = BusinessTransactionFormat(
    service_name="MCT",
    message_name="pain.001",
    scope="CH",
    message_version="09",
)

#: The pain.001.001.09 payment-submission upload in the original ISO 20022 schema, as the
#: Common Global Implementation (CGI) uses it (the ZKB ``XCT`` order type, ``MCT / CGI /
#: XCH / pain.001 / 09``, no container). Confirmed against the bank's HTD registry and
#: processed live by the ZKB test platform. Which payment types a bank accepts in this schema
#: is its own rule: the ZKB test platform allows only SEPA payments (type S) and rejects
#: foreign-currency payments abroad (docs/09).
PAIN_001_CGI = BusinessTransactionFormat(
    service_name="MCT",
    message_name="pain.001",
    scope="CGI",
    message_version="09",
    service_option="XCH",
)

#: The Swiss pain.002.001.10 payment-status-report download as ZKB registers it (the ZKB
#: ``Z01`` order type): ``PSR / CH / pain.002 / 10`` **without** a container, although the
#: delivered file is a ZIP and ZKB's printed catalogue shows a ZIP column. Banks register this
#: tuple differently: ZKB refuses a request carrying ``Container=ZIP`` with ``091005``, while
#: PostFinance registers the tuple **with** the ZIP container and refuses this container-less
#: form with ``091005`` — use ``PAIN_002_ZIP`` there. The bank's HTD registry
#: (``Client.subscriber_info()``) shows which form it holds. Both validated live; see docs/09,
#: docs/10 and docs/14.
PAIN_002 = BusinessTransactionFormat(
    service_name="PSR",
    message_name="pain.002",
    scope="CH",
    message_version="10",
)

#: The same pain.002.001.10 download with the ZIP container named in the request
#: (``PSR / CH / pain.002 / 10 / ZIP``), as PostFinance registers it. Pass it to
#: ``Client.download_payment_status_reports()`` at a bank whose HTD registry carries the
#: container; ZKB refuses it with ``091005``. Validated live against the PostFinance test
#: platform; see docs/14.
PAIN_002_ZIP = BusinessTransactionFormat(
    service_name="PSR",
    message_name="pain.002",
    scope="CH",
    message_version="10",
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


#: ISO 20022 document-type code (``DocumentType3Code``) of an ISO 11649 structured creditor
#: reference (``RF…``), carried in ``CdtrRefInf/Tp/CdOrPrtry/Cd``.
CREDITOR_REFERENCE_TYPE_SCOR = "SCOR"
#: Swiss proprietary creditor-reference type (``CdOrPrtry/Prtry``) of a 27-digit QR reference
#: (ZKB ISO 20022 handbook, section 10.7.3).
CREDITOR_REFERENCE_TYPE_QR = "QRR"
#: Swiss proprietary creditor-reference type (``CdOrPrtry/Prtry``) of an ESR-format reference,
#: which LSV+ collections carry (ZKB ISO 20022 handbook, section 10.7.3).
CREDITOR_REFERENCE_TYPE_ISR = "ISR Reference"


@dataclass(frozen=True, slots=True)
class CreditorReference:
    """A structured creditor reference (``RmtInf/Strd/CdtrRefInf``), such as a QR reference.

    The reference the payee put on the invoice, which the payer quoted when paying. It is what
    matches an incoming payment to its invoice. The type is either an ISO code or a
    proprietary text, never both; see the ``CREDITOR_REFERENCE_TYPE_*`` constants.

    Attributes:
        reference: The reference (``Ref``), e.g. a 27-digit QR reference or an ISO 11649
            ``RF`` reference, or ``None`` if the bank sent only the type.
        type_code: The ISO document-type code (``Tp/CdOrPrtry/Cd``), e.g. ``"SCOR"``, or
            ``None`` if the type is proprietary or absent.
        proprietary_type: The proprietary type (``Tp/CdOrPrtry/Prtry``), e.g. ``"QRR"`` or
            ``"ISR Reference"`` in Swiss reports, or ``None`` if the type is a code or absent.
    """

    reference: str | None
    type_code: str | None
    proprietary_type: str | None


@dataclass(frozen=True, slots=True)
class TransactionDetails:
    """One single transaction of a booking entry (``NtryDtls/TxDtls``).

    A collective booking, for example all QR-bill credits of a day or the debits of one
    payment file, is one entry for the total; its transaction details carry each payment with
    its own amount, references, parties and remittance information. A single booking usually
    carries one. Every field the bank omitted is ``None`` or empty.

    Attributes:
        amount: The transaction amount, as an exact decimal, or ``None`` if omitted
            (camt version 08 makes it optional). It is in the transaction's own currency,
            which can differ from the entry's: a USD payment booked to a CHF account reports
            the USD amount here.
        currency: The ISO 4217 currency code of ``amount``, or ``None`` with it.
        credit_debit: Whether the transaction credits or debits the account, or ``None`` if
            omitted.
        account_servicer_reference: The bank's own reference for the transaction
            (``Refs/AcctSvcrRef``), or ``None``.
        message_id: The message ID of the original payment message (``Refs/MsgId``), e.g. a
            pain.001 group header's, or ``None``.
        payment_information_id: The original payment block's ID (``Refs/PmtInfId``), or
            ``None``.
        instruction_id: The original instruction ID (``Refs/InstrId``), or ``None``.
        end_to_end_id: The originator's end-to-end ID (``Refs/EndToEndId``), or ``None``.
        debtor_name: The payer's name (``RltdPties/Dbtr``), or ``None``.
        debtor_iban: The payer's IBAN (``RltdPties/DbtrAcct``), or ``None`` if absent or
            identified otherwise.
        creditor_name: The payee's name (``RltdPties/Cdtr``), or ``None``.
        creditor_iban: The payee's IBAN (``RltdPties/CdtrAcct``), or ``None`` if absent or
            identified otherwise.
        creditor_references: The structured creditor references (``RmtInf/Strd/CdtrRefInf``),
            in document order; usually one, empty if the payment carried none.
        remittance_information: The unstructured remittance information lines
            (``RmtInf/Ustrd``), in document order.
        additional_remittance_information: The additional remittance information of the
            structured blocks (``RmtInf/Strd/AddtlRmtInf``), in document order.
    """

    amount: Decimal | None
    currency: str | None
    credit_debit: CreditDebit | None
    account_servicer_reference: str | None
    message_id: str | None
    payment_information_id: str | None
    instruction_id: str | None
    end_to_end_id: str | None
    debtor_name: str | None
    debtor_iban: str | None
    creditor_name: str | None
    creditor_iban: str | None
    creditor_references: tuple[CreditorReference, ...]
    remittance_information: tuple[str, ...]
    additional_remittance_information: tuple[str, ...]


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
        transactions: The single transactions behind the entry (``NtryDtls/TxDtls``), in
            document order. Empty when the bank sent no details, which for Swiss banks
            depends on the report and its settings.
    """

    amount: Decimal
    currency: str
    credit_debit: CreditDebit
    status: str
    booking_date: datetime.date | None
    value_date: datetime.date | None
    reference: str | None
    transactions: tuple[TransactionDetails, ...] = ()


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
            the segments carried by the transfer requests: one or more, or none for an order
            that carries only a signature (SPR, spec 4.5.2).
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


class AcknowledgementAction(StrEnum):
    """The type of action one customer-acknowledgement entry records (EBICS 3.0 spec 10.2.3.1).

    The bank writes it into ``OrgnlPmtInfId``. The three ``ORDER_FINAL`` values are labels,
    not actions: they mark that no further entry follows for the order, and carry no reason
    code. EBICS 3.0.2 has a positive and a negative label; banks on an earlier version send
    the neutral ``ORDER_HAC_FINAL``, which the spec text still names (spec 10.2.3.3, 10.4).
    """

    FILE_UPLOAD = "FILE_UPLOAD"
    FILE_DOWNLOAD = "FILE_DOWNLOAD"
    SIGNATURE_UPLOAD = "ES_UPLOAD"
    SIGNATURE_DOWNLOAD = "ES_DOWNLOAD"
    SIGNATURE_VERIFICATION = "ES_VERIFICATION"
    DISTRIBUTED_SIGNATURE_FORWARDING = "VEU_FORWARDING"
    DISTRIBUTED_SIGNATURE_VERIFICATION = "VEU_VERIFICATION"
    DISTRIBUTED_SIGNATURE_VERIFICATION_END = "VEU_VERIFICATION_END"
    DISTRIBUTED_SIGNATURE_CANCELLATION = "VEU_CANCEL_ORDER"
    ADDITIONAL_INFORMATION = "ADDITIONAL"
    ORDER_FINAL = "ORDER_HAC_FINAL"
    ORDER_FINAL_POSITIVE = "ORDER_HAC_FINAL_POS"
    ORDER_FINAL_NEGATIVE = "ORDER_HAC_FINAL_NEG"


@dataclass(frozen=True, slots=True)
class AcknowledgementEntry:
    """One protocol step in a customer acknowledgement (one ``OrgnlPmtInfAndSts``, spec 10.2.3).

    The identifiers come from ``StsRsnInf/Orgtr/Id/OrgId/Othr``, where ``SchmeNm/Prtry`` names
    each one (spec 10.2.3.2). The bank provides those it has, so any of them may be ``None``.

    Attributes:
        action: The type of action.
        reason_code: The result of the action, an ISO ``ExternalStatusReason1Code`` (e.g.
            ``"TS01"`` transmission successful, ``"DS01"`` signatures correct, ``"TD01"`` no
            data available; spec 10.3). ``None`` for the final labels, where the spec forbids
            one, and when an ``ADDITIONAL`` entry carries none.
        timestamp: When the action happened (``TimeStamp``), or ``None``.
        customer_name: The customer's name (``Orgtr/Nm``), or ``None``.
        partner_id: The customer's Partner ID (``PartnerID``), or ``None``.
        user_id: The subscriber who acted (``UserID``), or ``None``.
        system_id: The technical subscriber who acted (``SystemID``), or ``None``.
        order_id: The order number (``OrderID``), or ``None``.
        admin_order_type: The administrative order type (``AdminOrderType``, e.g. ``"BTU"``),
            or ``None``.
        service: The BTF of the order (``ServiceName``, ``Scope``, ``ServiceOption``,
            ``ContainerType``, ``MsgName``, and ``MsgNameVersion`` for its version), or
            ``None`` if the entry names none.
        referenced_order_id: The order an action on another order refers to (``OrderIDRef``),
            or ``None``.
        referenced_admin_order_type: That order's administrative order type
            (``AdminOrderTypeRef``), or ``None``.
        referenced_service: That order's BTF (the ``…Ref`` service identifiers), or ``None``.
        referenced_partner_id: That order's Partner ID, when it is another customer's
            (``PartnerIDRef``), or ``None``.
        data_digest: The hash value of the order data (``DataDigest``), or ``None``.
        additional_information: The free-text lines (``AddtlInf``), in order: notes, the
            order's ``AdditionalOrderInfo``, or a display of the file's content.
        other_identifiers: Identifiers under a scheme name the spec does not list, as
            ``(scheme name, value)`` pairs in document order, so none is dropped.
    """

    action: AcknowledgementAction
    reason_code: str | None
    timestamp: datetime.datetime | None
    customer_name: str | None
    partner_id: str | None
    user_id: str | None
    system_id: str | None
    order_id: str | None
    admin_order_type: str | None
    service: BusinessTransactionFormat | None
    referenced_order_id: str | None
    referenced_admin_order_type: str | None
    referenced_service: BusinessTransactionFormat | None
    referenced_partner_id: str | None
    data_digest: str | None
    additional_information: tuple[str, ...]
    other_identifiers: tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class CustomerAcknowledgement:
    """The bank's log of the EBICS actions of a customer (HAC, EBICS 3.0 spec 10).

    A HAC holds every action and its result since the previous HAC download, for all
    subscribers of the Partner ID: uploads, downloads, signature checks, and when each order
    was finished at EBICS level. It is a pain.002 document filled by the rules of spec 10.2.

    Attributes:
        identification: The message ID (``GrpHdr/MsgId``).
        created_at: When the bank created it (``GrpHdr/CreDtTm``).
        host_id: The bank's Host ID (``GrpHdr/InitgPty``).
        entries: The protocol steps, in document order.
    """

    identification: str
    created_at: datetime.datetime
    host_id: str
    entries: tuple[AcknowledgementEntry, ...]


class AuthorisationLevel(StrEnum):
    """The signature class a subscriber holds for an order type (``AuthorisationLevelType``).

    The H005 schema restricts the value to these four codes (``ebics_types_H005.xsd``); the
    bank states it on upload permissions and omits it for downloads (spec 9.3.2.1.3).

    - ``INDIVIDUAL``: an individual signature (``E``) — authorises the order on its own.
    - ``FIRST``: a first signature (``A``).
    - ``SECOND``: a second signature (``B``) — needs an ``A`` signature alongside.
    - ``TRANSPORT``: a transport signature (``T``) — submits the order but does not authorise it.
    """

    INDIVIDUAL = "E"
    FIRST = "A"
    SECOND = "B"
    TRANSPORT = "T"


@dataclass(frozen=True, slots=True)
class OrderTypeInfo:
    """One order type entry from the bank's subscriber data (HTD/HKD ``OrderInfo``/``Permission``).

    The same shape serves both lists: a partner's registered order types (``OrderInfo``,
    which carry a description and a signature count) and a user's permissions
    (``Permission``, which may carry a signature class, an account, and an amount limit).
    Fields the entry does not carry are ``None``.

    Attributes:
        admin_order_type: The administrative order type (``"BTD"``, ``"BTU"``, ``"HPB"``, …).
        service: For ``BTD``/``BTU`` entries, the Business Transaction Format the entry
            refers to; ``None`` for plain administrative order types.
        description: The bank's human-readable description, or ``None`` (permissions
            carry none).
        number_of_signatures_required: How many electronic signatures the order type
            requires (upload entries), or ``None`` if not stated.
        authorisation_level: The user's signature class for this permission, or ``None``
            (download permissions and partner order types carry none).
        account_id: The ``AccountInfo`` ID the permission is limited to, or ``None`` when it
            applies to all of the customer's accounts.
        maximum_amount: The amount up to which the permission is valid, as an exact decimal,
            or ``None`` for no stated limit.
        maximum_amount_currency: The ISO 4217 currency of ``maximum_amount`` (the schema
            default ``"EUR"`` when the bank omits it), or ``None`` when there is no limit.
    """

    admin_order_type: str
    service: BusinessTransactionFormat | None
    description: str | None
    number_of_signatures_required: int | None
    authorisation_level: AuthorisationLevel | None = None
    account_id: str | None = None
    maximum_amount: Decimal | None = None
    maximum_amount_currency: str | None = None


@dataclass(frozen=True, slots=True)
class SubscriberInfo:
    """The bank's registered data for this subscriber (the HTD download).

    The authoritative view of what the bank has configured: the order types offered to
    the partner and the permissions granted to this user. Useful for diagnosing
    ``091005``-style rejections — an order type missing here is not registered, whatever
    a catalogue says.

    Attributes:
        user_id: The subscriber's User ID as registered at the bank.
        user_status: The bank's user-status attribute (a bank-defined code), or ``None``.
        name: The subscriber's registered name, or ``None``.
        permissions: The order types this user may use, in document order.
        order_types: Every order type registered for the partner, in document order.
    """

    user_id: str
    user_status: str | None
    name: str | None
    permissions: tuple[OrderTypeInfo, ...]
    order_types: tuple[OrderTypeInfo, ...]


@dataclass(frozen=True, slots=True)
class CustomerAddress:
    """The customer's address as registered at the bank (HKD/HTD ``AddressInfo``).

    Every part is optional in the schema (``AddressInfoType``), so each is ``None`` when the
    bank does not state it.

    Attributes:
        name: The customer's name.
        street: Street and house number.
        post_code: The postal code.
        city: The city.
        region: The region, province, or federal state.
        country: The country, as the bank writes it (free text, not necessarily an ISO code).
    """

    name: str | None
    street: str | None
    post_code: str | None
    city: str | None
    region: str | None
    country: str | None


@dataclass(frozen=True, slots=True)
class AccountNumber:
    """One account number of a registered account (``AccountNumber``/``NationalAccountNumber``).

    Attributes:
        value: The account number as the bank sent it.
        international: ``True`` for an IBAN (``AccountNumber`` with ``international="true"``);
            ``False`` for a national number.
        national_format: For a free-format ``NationalAccountNumber``, the bank's format code
            (its ``format`` attribute); ``None`` for an ``AccountNumber``.
    """

    value: str
    international: bool
    national_format: str | None


@dataclass(frozen=True, slots=True)
class BankCode:
    """One bank code of a registered account (``BankCode``/``NationalBankCode``).

    Attributes:
        value: The bank code as the bank sent it.
        international: ``True`` for a SWIFT BIC (``BankCode`` with ``international="true"``);
            ``False`` for a national bank code.
        prefix: The national bank-code prefix (e.g. ``"DE"``), or ``None``.
        national_format: For a free-format ``NationalBankCode``, the bank's format code;
            ``None`` for a ``BankCode``.
    """

    value: str
    international: bool
    prefix: str | None
    national_format: str | None


@dataclass(frozen=True, slots=True)
class AccountInfo:
    """One of the customer's accounts as registered at the bank (HKD/HTD ``AccountInfo``).

    A bank lists an account when the customer receives statements for it or one of its
    subscribers may sign for it (spec 9.3); the holder need not be the customer itself.

    Attributes:
        identification: The account's ID within this response — what a permission's
            ``account_id`` refers to.
        currency: The account's ISO 4217 currency (the schema default ``"EUR"`` when the bank
            omits it).
        description: The bank's description of the account, or ``None``.
        account_numbers: The account's numbers, in document order (one or two).
        bank_codes: The account's bank codes, in document order (possibly none).
        holder: The account holder's name, or ``None``.
        permitted_services: The business transactions the account is enabled for. ``None``
            means the bank states no restriction; an empty tuple means the account is enabled
            for none (spec 9.3.2.1.3, ``UsageOrderTypes``).
    """

    identification: str
    currency: str
    description: str | None
    account_numbers: tuple[AccountNumber, ...]
    bank_codes: tuple[BankCode, ...]
    holder: str | None
    permitted_services: tuple[BusinessTransactionFormat, ...] | None


@dataclass(frozen=True, slots=True)
class SubscriberPermissions:
    """One subscriber of the customer and what it may do (an HKD ``UserInfo``).

    Attributes:
        user_id: The subscriber's User ID.
        user_status: The bank's user-status code (spec 9.3.2.1.3; e.g. ``"1"`` = ready).
        name: The subscriber's registered name, or ``None``.
        permissions: The subscriber's permissions, in document order.
    """

    user_id: str
    user_status: str
    name: str | None
    permissions: tuple[OrderTypeInfo, ...]


@dataclass(frozen=True, slots=True)
class CustomerInfo:
    """The bank's registered data for the customer and all of its subscribers (the HKD download).

    Where :class:`SubscriberInfo` (HTD) shows only the requesting subscriber, this is the
    customer-wide view: the address, the accounts, the order types registered for the
    customer, and every subscriber with their permissions.

    Attributes:
        address: The customer's registered address.
        host_id: The EBICS Host ID the customer is registered under.
        accounts: The customer's accounts, in document order (possibly none).
        order_types: Every order type registered for the customer, in document order.
        subscribers: Every subscriber of the customer, in document order (at least one).
    """

    address: CustomerAddress
    host_id: str
    accounts: tuple[AccountInfo, ...]
    order_types: tuple[OrderTypeInfo, ...]
    subscribers: tuple[SubscriberPermissions, ...]


@dataclass(frozen=True, slots=True)
class BankUrl:
    """One EBICS access address the bank publishes (an HPD ``URL``).

    Attributes:
        url: The URL or IP address.
        valid_from: When the address becomes valid, or ``None`` for "valid now". Timezone-aware
            when the bank states a zone, as banks normally do.
    """

    url: str
    valid_from: datetime.datetime | None


@dataclass(frozen=True, slots=True)
class BankParameters:
    """The bank's EBICS access and protocol parameters (the HPD download).

    The support flags follow the spec's rule for optional protocol parameters (spec 9.2): a
    parameter the bank omits means *not supported*; one it lists without a ``supported``
    attribute means *supported*.

    Attributes:
        urls: The bank's EBICS access addresses, in document order (at least one).
        institute: The bank's name.
        host_id: The bank's EBICS Host ID, or ``None`` if the bank does not state it.
        protocol_versions: The supported EBICS protocol versions (e.g. ``("H005",)``).
        authentication_versions: The supported authentication versions (e.g. ``("X002",)``).
        encryption_versions: The supported encryption versions (e.g. ``("E002",)``).
        signature_versions: The supported electronic-signature versions (e.g. ``("A006",)``).
        supports_recovery: Whether the bank supports transaction recovery.
        supports_pre_validation: Whether the bank accepts pre-validation data.
        supports_client_data_download: Whether the bank supports HKD and HTD.
        supports_downloadable_order_data: Whether the bank supports HAA.
    """

    urls: tuple[BankUrl, ...]
    institute: str
    host_id: str | None
    protocol_versions: tuple[str, ...]
    authentication_versions: tuple[str, ...]
    encryption_versions: tuple[str, ...]
    signature_versions: tuple[str, ...]
    supports_recovery: bool
    supports_pre_validation: bool
    supports_client_data_download: bool
    supports_downloadable_order_data: bool


@dataclass(frozen=True, slots=True)
class EbicsVersion:
    """One EBICS version a bank supports, as its HEV answer reports it (``VersionNumber``).

    Attributes:
        protocol_version: The protocol schema version (``@ProtocolVersion``), ``H`` and
            three digits, e.g. ``"H005"`` for EBICS 3.0.
        release: The EBICS release, two digits, a dot and two digits, e.g. ``"03.00"``.
    """

    protocol_version: str
    release: str


class KeyRotation(StrEnum):
    """Which of the subscriber's keys a key change replaces at the bank.

    Each value maps to one EBICS 3.0 administrative order type (spec 4.6.1.1), all of which
    replace the keys in a single exchange, with no new initialisation letter:

    - ``SIGNATURE``: the A006 signature key (order type ``PUB``).
    - ``AUTHENTICATION_AND_ENCRYPTION``: the X002 authentication and E002 encryption keys
      (order type ``HCA``).
    - ``ALL``: all three keys at once (order type ``HCS``).
    """

    SIGNATURE = "signature"
    AUTHENTICATION_AND_ENCRYPTION = "authentication_and_encryption"
    ALL = "all"


class ReceiptPolicy(StrEnum):
    """What to do with downloaded data once it has been received and verified.

    An EBICS download ends with a *receipt* that tells the bank whether to consume the data.
    A positive receipt (``ReceiptCode`` 0) lets the bank mark the data delivered — it will
    not be served again. A negative receipt (``ReceiptCode`` 1) tells the bank the data was
    not processed, so it stays available for a later download (EBICS 3.0 spec 5.6.1.2.2).

    This client acknowledges only **after** it has successfully decrypted (and, for a dated
    download, validated) the data — a failure before that always sends a negative receipt,
    so data is never consumed against an error. This policy governs the *successful* path:

    - ``ACKNOWLEDGE``: on success, send a positive receipt — the normal case; the bank
      consumes the data (default).
    - ``KEEP``: on success, still send a *negative* receipt so the bank keeps the data
      available — a non-consuming "peek" for discovery or test reads, where another
      download must fetch the same data afterwards. Realised via the spec's negative
      acknowledgement; whether a given bank then re-serves the kept data is bank-specific.
    """

    ACKNOWLEDGE = "acknowledge"
    KEEP = "keep"


class VersionPolicy(StrEnum):
    """Whether a download must deliver the message version its BTF requested.

    A download request names the ISO 20022 message and version it wants (the BTF
    ``MsgName`` with its ``version`` attribute), and every delivered ISO 20022 document
    declares the message it actually is in its root namespace
    (``urn:iso:std:iso:20022:tech:xsd:camt.053.001.08``). The two can differ — a bank in a
    format transition, a misconfigured order type — even when the content is equivalent.

    - ``ACCEPT_ANY``: return whatever the bank delivered; the parsers read every camt and
      pain.002 version without a code change (default). The comparison still runs, and a
      mismatch is logged as a warning on the ``ebicsclient.client`` logger.
    - ``STRICT``: before the receipt, compare each delivered document's message name and
      version with the request. A mismatch raises
      :class:`~ebicsclient.errors.MessageVersionMismatchError` and sends a negative receipt,
      so the data stays at the bank. A BTF without a ``message_version`` requests no
      version and is not compared; the library sends no ``variant``, so any variant passes.
    """

    ACCEPT_ANY = "accept_any"
    STRICT = "strict"


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
