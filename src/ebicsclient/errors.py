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
