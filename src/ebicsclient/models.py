"""Data models for ebicsclient.

Plain data holders kept free of behaviour; the logic that operates on them lives in
the feature modules (e.g. ``keys.py`` for keyring generation and persistence).
"""

from dataclasses import dataclass
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
