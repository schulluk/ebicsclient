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


class CryptoError(EbicsError):
    """A cryptographic operation failed (key handling, signing, encryption)."""


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


class TransportError(EbicsError):
    """The HTTP exchange with the bank failed (connection, TLS, status code)."""


class ProtocolError(EbicsError):
    """The bank's response violated the expected EBICS protocol or could not be parsed."""


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
