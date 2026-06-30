"""Data models for ebicsclient.

Plain data holders kept free of behaviour; the logic that operates on them lives in
the feature modules (e.g. ``keys.py`` for keyring generation and persistence).
"""

from dataclasses import dataclass

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
