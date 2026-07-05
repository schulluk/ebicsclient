"""ebicsclient — a pure-Python client for the EBICS 3.0 (H005) banking protocol.

The public API is curated here and stays protocol- and format-agnostic; see
docs/04-implementation-plan.md for the module layout and docs/06-engineering-conventions.md
for the conventions every addition must follow.
"""

import logging
from importlib.metadata import PackageNotFoundError, version

from ebicsclient.certificates import (
    BankCertificateVerifier,
    CertificateProvider,
    MappingCertificateProvider,
    SelfSignedCertificateProvider,
    TrustAnchorVerifier,
    load_certificate,
)
from ebicsclient.client import Client
from ebicsclient.errors import (
    BankCertificateError,
    BankKeyMismatchError,
    CertificateError,
    ClientStateError,
    CryptoError,
    EbicsError,
    KeyringDecryptionError,
    KeyringError,
    KeyringFormatError,
    MessageFormatError,
    MissingDependencyError,
    ProtocolError,
    Retryability,
    ReturnCodeError,
    TransportError,
)
from ebicsclient.keys import (
    CertificateUsage,
    bank_key_hashes,
    deserialize_keyring,
    generate_keyring,
    generate_self_signed_certificate,
    load_keyring,
    public_key_hash,
    save_keyring,
    serialize_keyring,
)
from ebicsclient.models import (
    CAMT_053,
    PAIN_001,
    PAIN_002,
    Balance,
    Bank,
    BankKeyHashes,
    BankKeys,
    BusinessTransactionFormat,
    CreditDebit,
    Entry,
    InitializationState,
    Keyring,
    Letter,
    OutputFormat,
    Statement,
    UploadPayload,
    User,
)

# A library must never configure logging — that is the application's job. Attach a
# NullHandler so importing the package never emits "No handlers could be found"
# warnings when the consuming application has not set logging up. See docs/06.
logging.getLogger(__name__).addHandler(logging.NullHandler())

try:
    __version__ = version("ebicsclient")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0"

__all__ = [
    "CAMT_053",
    "PAIN_001",
    "PAIN_002",
    "Balance",
    "Bank",
    "BankCertificateError",
    "BankCertificateVerifier",
    "BankKeyHashes",
    "BankKeyMismatchError",
    "BankKeys",
    "BusinessTransactionFormat",
    "CertificateError",
    "CertificateProvider",
    "CertificateUsage",
    "Client",
    "ClientStateError",
    "CreditDebit",
    "CryptoError",
    "EbicsError",
    "Entry",
    "InitializationState",
    "Keyring",
    "KeyringDecryptionError",
    "KeyringError",
    "KeyringFormatError",
    "Letter",
    "MappingCertificateProvider",
    "MessageFormatError",
    "MissingDependencyError",
    "OutputFormat",
    "ProtocolError",
    "Retryability",
    "ReturnCodeError",
    "SelfSignedCertificateProvider",
    "Statement",
    "TransportError",
    "TrustAnchorVerifier",
    "UploadPayload",
    "User",
    "__version__",
    "bank_key_hashes",
    "deserialize_keyring",
    "generate_keyring",
    "generate_self_signed_certificate",
    "load_certificate",
    "load_keyring",
    "public_key_hash",
    "save_keyring",
    "serialize_keyring",
]
