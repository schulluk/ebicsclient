"""ebicsclient — a pure-Python client for the EBICS 3.0 (H005) banking protocol.

The public API is curated here and stays protocol- and format-agnostic; see
docs/04-implementation-plan.md for the module layout and docs/06-engineering-conventions.md
for the conventions every addition must follow.
"""

import logging
from importlib.metadata import PackageNotFoundError, version

from ebicsclient.client import Client
from ebicsclient.errors import (
    CryptoError,
    EbicsError,
    KeyringDecryptionError,
    KeyringError,
    KeyringFormatError,
    MissingDependencyError,
    ProtocolError,
    Retryability,
    ReturnCodeError,
    TransportError,
)
from ebicsclient.keys import (
    deserialize_keyring,
    generate_keyring,
    load_keyring,
    public_key_hash,
    save_keyring,
    serialize_keyring,
)
from ebicsclient.models import (
    Bank,
    BankKeys,
    InitializationState,
    Keyring,
    Letter,
    OutputFormat,
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
    "Bank",
    "BankKeys",
    "Client",
    "CryptoError",
    "EbicsError",
    "InitializationState",
    "Keyring",
    "KeyringDecryptionError",
    "KeyringError",
    "KeyringFormatError",
    "Letter",
    "MissingDependencyError",
    "OutputFormat",
    "ProtocolError",
    "Retryability",
    "ReturnCodeError",
    "TransportError",
    "User",
    "__version__",
    "deserialize_keyring",
    "generate_keyring",
    "load_keyring",
    "public_key_hash",
    "save_keyring",
    "serialize_keyring",
]
