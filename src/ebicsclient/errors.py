"""Exception hierarchy for ebicsclient.

Every error raised by this library derives from :class:`EbicsError`, so a caller can
catch that single base. Each error also declares its :class:`Retryability`, so retry
loops and user interfaces can react without parsing error messages. See
docs/06-engineering-conventions.md.
"""

from enum import StrEnum


class Retryability(StrEnum):
    """How an :class:`EbicsError` may be recovered from.

    Lets callers decide what to do without matching on error text, and keeps automatic
    retries safe — only ``TRANSIENT`` errors are eligible for auto-retry.

    - ``PERMANENT``: retrying never helps; surface it.
    - ``CORRECTABLE``: retry only after the caller corrects the input (e.g. a wrong passphrase).
    - ``TRANSIENT``: safe to auto-retry the same call after a backoff.
    """

    PERMANENT = "permanent"
    CORRECTABLE = "correctable"
    TRANSIENT = "transient"


class EbicsError(Exception):
    """Base class for every error raised by ebicsclient."""

    #: How a retry may help. Defaults to PERMANENT (fail closed). Subtypes set it at
    #: class level (e.g. KeyringDecryptionError), or a call site passes ``retryability=``
    #: for cases that vary per instance (e.g. a transport timeout vs a 4xx).
    retryability: Retryability = Retryability.PERMANENT

    def __init__(self, *args: object, retryability: Retryability | None = None) -> None:
        super().__init__(*args)
        if retryability is not None:
            self.retryability = retryability


class MissingDependencyError(EbicsError):
    """An optional feature was requested but its install extra is not present.

    Raised when a feature gated behind an optional extra is used without that extra
    installed — for example, PDF letter output without the ``pdf`` extra (reportlab).
    Installing the named extra and retrying resolves it.

    Args:
        feature: Human description of the requested feature (e.g. "PDF letter output").
        extra: The install extra that provides it (e.g. ``"pdf"``).

    Attributes:
        extra: The install extra that provides the missing feature.
    """

    def __init__(self, feature: str, extra: str) -> None:
        self.extra = extra
        super().__init__(
            f'{feature} requires the optional "{extra}" extra '
            f'(install with: pip install "ebicsclient[{extra}]")'
        )


class CryptoError(EbicsError):
    """A cryptographic operation failed (key handling, signing, encryption)."""


class CertificateError(CryptoError):
    """A subscriber certificate could not be provided or does not match its key.

    Raised by a :class:`~ebicsclient.certificates.CertificateProvider` — for example when a
    caller-supplied ("mit Zertifikaten") certificate is missing for a key, or its public key
    does not match the private key it is meant to certify (which the bank would reject).
    """


class KeyringError(CryptoError):
    """The keyring could not be created, serialised, written, read, or decrypted."""


class KeyringFormatError(KeyringError):
    """The serialised keyring is structurally invalid.

    Raised when the data is not valid JSON, carries an unknown format version, or is
    missing keys (or holds a non-RSA key). Re-trying with a different passphrase will
    not help — the bytes are not a well-formed keyring.
    """


class KeyringDecryptionError(KeyringError):
    """The keyring could not be decrypted.

    Usually a wrong passphrase; possibly corrupt key material. The two cannot be told
    apart reliably, because the underlying crypto layer reports both the same way.
    Correctable: re-prompt for the passphrase and retry — never auto-retry the same call.
    """

    retryability = Retryability.CORRECTABLE


class ClientStateError(EbicsError):
    """An operation was called before a prerequisite step had run.

    Raised when the client is used out of order — for example, downloading before the
    bank's keys have been fetched with HPB. Run the prerequisite step and retry.
    """


class MessageFormatError(EbicsError):
    """A downloaded business message could not be parsed.

    Raised when order data the bank returned — a camt.053 statement, for instance — is not
    the well-formed, expected shape (missing mandatory elements, a malformed amount, an
    unreadable container). Distinct from :class:`ProtocolError`, which concerns the EBICS
    envelope rather than the payload it carries.
    """


class DateRangeMismatchError(EbicsError):
    """A dated download returned data outside the requested range.

    Raised when :meth:`~ebicsclient.Client.download_statements` (or a sibling) was given a
    ``date_range`` but the bank's data carries booking dates outside it — the strong signal
    that the bank ignored the ``DateRange`` filter (it is an optional EBICS element a bank
    may accept yet not honour) and served other data instead. The download is **not**
    acknowledged when this is raised: the client sends a negative receipt so the bank keeps
    the data available rather than consuming it against a mismatched request. Fail closed —
    never return silently-wrong data as if it matched the request.
    """


class MessageVersionMismatchError(EbicsError):
    """A strict download delivered a different message or version than it requested.

    Raised only under :attr:`~ebicsclient.VersionPolicy.STRICT`, when a delivered document's
    root namespace names another ISO 20022 message or version than the BTF requested (say
    ``camt.053.001.04`` for ``camt.053`` version ``08``), or names no ISO 20022 message at
    all. The download is **not** acknowledged when this is raised: the client sends a
    negative receipt, so the data stays available at the bank.

    Args:
        requested: The requested message and version, e.g. ``"camt.053 version 08"``.
        delivered: What the document declared, e.g. ``"camt.053.001.04"``.

    Attributes:
        requested: The requested message and version.
        delivered: What the delivered document declared.
    """

    def __init__(self, *, requested: str, delivered: str) -> None:
        self.requested = requested
        self.delivered = delivered
        super().__init__(
            f"Requested {requested}, the bank delivered {delivered}. The data was NOT "
            f"acknowledged and remains available at the bank."
        )


class KeyChangeUnconfirmedError(EbicsError):
    """A key change (PUB, HCA, HCS) reached the bank, but its outcome is unknown.

    The bank processes a key change synchronously and reports the result in its response to
    the final upload segment (EBICS 3.0 spec 4.3, 5.1.3.1). This error means that segment was
    sent but no trustworthy answer came back — the connection failed, the response could not be
    verified, or it carried a return code this client does not know. The bank may hold
    either the old keys or the new ones.

    Keep **both** keyrings until you know which one the bank holds; discarding either may
    lock the subscriber out (recovery then needs a full re-initialisation through the bank).
    After an HCA or HCS, an HPB with the new keyring succeeds only if the bank switched,
    since HPB is authenticated with the X002 key and encrypted to the E002 key. Never retry
    automatically: the client is still on the old keys, and a second key change against an
    unknown state cannot clarify it.

    Attributes:
        order_type: The key-change order type that was sent (``"PUB"``, ``"HCA"``, ``"HCS"``).
        transaction_id: The bank-issued transaction ID of the key-change upload.
    """

    def __init__(self, order_type: str, transaction_id: str) -> None:
        self.order_type = order_type
        self.transaction_id = transaction_id
        super().__init__(
            f"{order_type} key change (transaction {transaction_id}) was sent, but the bank's "
            f"answer could not be confirmed — it may hold the old or the new keys. Keep both "
            f"keyrings until you have established which one is active."
        )


class UploadUnconfirmedError(EbicsError):
    """An upload's final segment was sent, but whether the bank accepted it is unknown.

    The bank takes an order once it has received the last segment (EBICS 3.0 spec 5.1.3.1),
    so the answer to that segment decides whether the order exists. This error means the
    segment was sent but no trustworthy answer came back: the connection failed, the response
    could not be verified, or it carried a return code this client does not know. The client
    has already sent the segment again within the same transaction as far as its
    ``recovery_attempts`` allow (spec 5.5.2), without a confirming answer. The bank may hold
    the order, and may execute it.

    **Never send the order again automatically**: if the bank has it, a second upload pays
    twice. Check first whether it arrived — a payment status report (pain.002) for its
    message ID, the bank's protocol, or its e-banking. The underlying error is chained as
    ``__cause__``; a transport timeout there is marked ``TRANSIENT``, but that only means
    the connection may work again, not that the upload may be repeated.

    Attributes:
        transaction_id: The bank-issued transaction ID of the upload.
    """

    def __init__(self, transaction_id: str) -> None:
        self.transaction_id = transaction_id
        super().__init__(
            f"Upload transaction {transaction_id}: the final segment was sent, but the bank's "
            f"answer could not be confirmed — the bank may hold the order. Do not upload it "
            f"again before checking whether it arrived (e.g. a pain.002 for its message ID)."
        )


class TransportError(EbicsError):
    """The HTTP exchange with the bank failed (connection, TLS, status code)."""


class ProtocolError(EbicsError):
    """The bank's response violated the expected EBICS protocol or could not be parsed."""


class ResponseAuthenticationError(ProtocolError):
    """The bank's response failed authentication-signature verification.

    Every ``ebicsResponse`` carries the bank's ``AuthSignature`` (X002) over its
    ``authenticate="true"`` nodes. A missing or invalid signature means the response
    cannot be attributed to the bank — do not trust its contents. Fail closed.
    """


class BankKeyMismatchError(ProtocolError):
    """The bank's HPB public keys did not match the pinned values.

    Raised when HPB is pinned (a previously trusted set of bank-key hashes, or the values the
    bank publishes out of band) and the freshly downloaded keys hash to something different.
    The keys must not be trusted — a mismatch means a changed or spoofed bank key. Fail closed.
    """


class BankCertificateError(ProtocolError):
    """The bank's certificate from the HPB response failed verification.

    Raised by a :class:`~ebicsclient.certificates.BankCertificateVerifier` when the bank's
    certificate is outside its validity period or does not chain to a trusted anchor. The
    keys must not be trusted — fail closed rather than proceed.
    """


class ReturnCodeError(ProtocolError):
    """The bank returned a non-OK EBICS return code.

    Args:
        code: The EBICS technical or business return code (e.g. ``"061099"``).
        text: The human-readable report text, if the bank supplied one.

    Attributes:
        code: The EBICS return code carried by the response.
        text: The report text, or ``None`` if the bank supplied none.
    """

    def __init__(
        self, code: str, text: str | None = None, *, retryability: Retryability | None = None
    ) -> None:
        self.code = code
        self.text = text
        super().__init__(code if text is None else f"{code}: {text}", retryability=retryability)


class UnknownReturnCodeError(ReturnCodeError):
    """The bank returned an EBICS code this client does not recognise.

    Deliberately distinct from a *known* failure: the code is outside the client's
    knowledge, so its meaning is unverified — it could be a bank-specific extension, a
    spec code not yet in the client's table, or even a success variant (as ``011000``
    once was). It is treated as a failure (fail closed, never fail open), but callers and
    logs can tell it apart and verify the code against the EBICS specification and the
    bank's documentation instead of trusting a masked classification.
    """

    def __init__(self, code: str, text: str | None = None) -> None:
        self.code = code
        self.text = text
        detail = f" ({text})" if text is not None else ""
        # Bypass ReturnCodeError.__init__ so the message carries the unknown-code framing.
        ProtocolError.__init__(
            self,
            f"Unknown EBICS return code {code}{detail} — failing closed; verify the code "
            f"against the EBICS specification and the bank's documentation",
        )


class ReceiptMismatchError(ReturnCodeError):
    """The bank confirmed the opposite of the receipt the client sent for a download.

    A download ends with a receipt. The bank answers a positive receipt (``ReceiptCode`` 0)
    with ``011000`` EBICS_DOWNLOAD_POSTPROCESS_DONE, the data now marked delivered, and a
    negative receipt (``ReceiptCode`` 1) with ``011001`` EBICS_DOWNLOAD_POSTPROCESS_SKIPPED,
    the data left available (EBICS 3.0 spec 5.6.1.2.2). The other code means the bank did
    the opposite of what the receipt asked:

    - ``011001`` after a positive receipt: the data was not marked delivered, so the bank
      may serve the same data again. The download raises although its data arrived.
    - ``011000`` after a negative receipt: the bank marked the data delivered although the
      client declined it, so it will not serve that data again. After
      :attr:`~ebicsclient.ReceiptPolicy.KEEP` the download raises; after a failed
      validation the validation error is raised, carrying this message as a note.

    Args:
        code: The confirmation code the bank returned.
        text: The bank's report text, if it supplied one.
        positive: Whether the receipt sent was positive.

    Attributes:
        positive: Whether the receipt sent was positive (``ReceiptCode`` 0).
    """

    def __init__(self, code: str, text: str | None = None, *, positive: bool) -> None:
        self.code = code
        self.text = text
        self.positive = positive
        detail = f" ({text})" if text is not None else ""
        if positive:
            receipt = "positive"
            consequence = "did not mark the data delivered, so it may serve the same data again"
        else:
            receipt = "negative"
            consequence = (
                "marked the data delivered although the receipt declined it, so it will not "
                "serve that data again"
            )
        # Bypass ReturnCodeError.__init__ so the message names the receipt and the consequence.
        ProtocolError.__init__(
            self, f"The bank answered the {receipt} receipt with {code}{detail}: it {consequence}"
        )
