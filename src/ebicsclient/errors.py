"""Exception hierarchy for ebicsclient.

Every error raised by this library derives from :class:`EbicsError`, so a caller can
catch that single base. See docs/06-engineering-conventions.md.
"""


class EbicsError(Exception):
    """Base class for every error raised by ebicsclient."""


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
    """


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

    def __init__(self, code: str, text: str | None = None) -> None:
        self.code = code
        self.text = text
        super().__init__(code if text is None else f"{code}: {text}")
